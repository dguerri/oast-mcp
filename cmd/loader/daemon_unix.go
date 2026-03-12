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
	"os"
	"syscall"
)

// daemonize re-execs the current binary in a new session with stdio redirected
// to /dev/null.  On success the parent calls os.Exit(0) and never returns.
// On failure it returns silently so the loader continues in the foreground.
func daemonize() {
	exe, err := os.Executable()
	if err != nil {
		return
	}

	devnull, err := os.Open(os.DevNull)
	if err != nil {
		return
	}

	env := append(os.Environ(), "_OAST_D=1")
	_, err = os.StartProcess(exe, os.Args, &os.ProcAttr{
		Env:   env,
		Files: []*os.File{devnull, devnull, devnull},
		Sys:   &syscall.SysProcAttr{Setsid: true},
	})
	_ = devnull.Close()
	if err != nil {
		return
	}
	os.Exit(0)
}
