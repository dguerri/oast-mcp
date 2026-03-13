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

//go:build !windows

package main

import (
	"context"
	"encoding/base64"
	"io"
	"os/exec"
	"syscall"

	"github.com/creack/pty"
)

// runInteractive starts cmd under a PTY. It sends stdout via stream messages
// on the results channel and returns an io.WriteCloser for stdin.
// When the process exits, it sends a final result message with exit_code.
func runInteractive(ctx context.Context, taskID, command string, binary bool, results chan outMsg) io.WriteCloser {
	c := exec.CommandContext(ctx, "/bin/sh", "-c", command)
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	ptmx, err := pty.Start(c)
	if err != nil {
		results <- outMsg{Type: "result", TaskID: taskID, Ok: false, Error: "pty start: " + err.Error()}
		return nopWriteCloser{}
	}

	// Read PTY output and send as stream messages.
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := ptmx.Read(buf)
			if n > 0 {
				chunk := string(buf[:n])
				if binary {
					chunk = base64.StdEncoding.EncodeToString(buf[:n])
				}
				results <- outMsg{Type: "stream", TaskID: taskID, Stdout: chunk}
			}
			if err != nil {
				break
			}
		}

		// Process exited — wait for exit code.
		exitCode := 0
		if err := c.Wait(); err != nil {
			if e, ok := err.(*exec.ExitError); ok {
				exitCode = e.ExitCode()
			}
		}
		_ = ptmx.Close()
		results <- outMsg{
			Type:   "result",
			TaskID: taskID,
			Ok:     true,
			Data:   map[string]any{"exit_code": exitCode},
		}
	}()

	return ptmx // ptmx implements io.WriteCloser — writing sends to PTY stdin
}
