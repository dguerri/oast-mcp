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

//go:build windows

package main

import (
	"context"
	"encoding/base64"
	"io"
	"os/exec"
)

func runInteractive(ctx context.Context, taskID, command string, binary bool, results chan outMsg) io.WriteCloser {
	c := exec.CommandContext(ctx, "cmd.exe", "/C", command)

	stdinPipe, err := c.StdinPipe()
	if err != nil {
		results <- outMsg{Type: "result", TaskID: taskID, Ok: false, Error: "stdin pipe: " + err.Error()}
		return nopWriteCloser{}
	}
	stdoutPipe, err := c.StdoutPipe()
	if err != nil {
		results <- outMsg{Type: "result", TaskID: taskID, Ok: false, Error: "stdout pipe: " + err.Error()}
		return nopWriteCloser{}
	}
	stderrPipe, err := c.StderrPipe()
	if err != nil {
		results <- outMsg{Type: "result", TaskID: taskID, Ok: false, Error: "stderr pipe: " + err.Error()}
		return nopWriteCloser{}
	}

	if err := c.Start(); err != nil {
		results <- outMsg{Type: "result", TaskID: taskID, Ok: false, Error: "start: " + err.Error()}
		return nopWriteCloser{}
	}

	readPipe := func(r io.Reader, isStderr bool) {
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				chunk := string(buf[:n])
				if binary {
					chunk = base64.StdEncoding.EncodeToString(buf[:n])
				}
				msg := outMsg{Type: "stream", TaskID: taskID}
				if isStderr {
					msg.Stderr = chunk
				} else {
					msg.Stdout = chunk
				}
				results <- msg
			}
			if err != nil {
				break
			}
		}
	}

	go readPipe(stdoutPipe, false)
	go readPipe(stderrPipe, true)

	go func() {
		exitCode := 0
		if err := c.Wait(); err != nil {
			if e, ok := err.(*exec.ExitError); ok {
				exitCode = e.ExitCode()
			}
		}
		results <- outMsg{
			Type:   "result",
			TaskID: taskID,
			Ok:     true,
			Data:   map[string]any{"exit_code": exitCode},
		}
	}()

	return stdinPipe
}
