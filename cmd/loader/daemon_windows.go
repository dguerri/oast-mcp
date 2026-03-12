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
	"os"
	"os/exec"
	"syscall"
)

const _DETACHED_PROCESS = 0x00000008

// daemonize re-execs the current binary as a detached process with no console.
// On success the parent calls os.Exit(0) and never returns.
// On failure it returns silently so the loader continues in the foreground.
func daemonize() {
	cmd := exec.Command(os.Args[0], os.Args[1:]...)
	cmd.Env = append(os.Environ(), "_OAST_D=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | _DETACHED_PROCESS,
	}
	if err := cmd.Start(); err != nil {
		return
	}
	os.Exit(0)
}
