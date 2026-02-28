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
	"fmt"
	"os"
	"os/exec"
	"unsafe"

	"golang.org/x/sys/windows"
)

func execAgent(path, serverURL, token, agentID string) {
	// Self-delete the loader binary on Windows — os.Remove fails on a running
	// exe. markDeleteOnClose marks it for auto-deletion when we exit.
	markDeleteOnClose(os.Args[0])

	// Mark the temp agent file for auto-deletion when the agent process exits.
	markDeleteOnClose(path)

	cmd := exec.Command(path, "-url", serverURL, "-token", token, "-id", agentID)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "exec error:", err)
		os.Exit(1)
	}
}

// markDeleteOnClose opens path with DELETE access and sets FileDispositionInfo
// so Windows auto-deletes the file when all handles (including the process's
// PE mapping) are closed — i.e., when the owning process exits.
func markDeleteOnClose(path string) {
	h, err := windows.CreateFile(
		windows.StringToUTF16Ptr(path),
		windows.DELETE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		// Non-fatal: file stays on disk but agent still runs.
		fmt.Fprintf(os.Stderr, "warn: could not mark file for deletion: %v\n", err)
		return
	}
	defer windows.CloseHandle(h)

	// FILE_DISPOSITION_INFO: single BOOL field.
	info := struct{ DeleteFile uint32 }{1}
	windows.SetFileInformationByHandle(
		h,
		windows.FileDispositionInfo,
		(*byte)(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	)
}
