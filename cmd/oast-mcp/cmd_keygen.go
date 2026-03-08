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

package main

import (
	"fmt"
	"os"

	"github.com/dguerri/oast-mcp/internal/agent"
)

// cmdKeygen prints a new age X25519 key pair.
// Private key → stdout (redirect to operator.key and keep offline).
// Public key  → stderr (copy into config.yml agent.operator_public_key).
func cmdKeygen(_ []string) {
	priv, pub, err := agent.GenerateKeyPair()
	if err != nil {
		fmt.Fprintf(os.Stderr, "keygen error: %v\n", err)
		os.Exit(1)
	}
	_, _ = fmt.Fprintln(os.Stdout, priv) // AGE-SECRET-KEY-...
	fmt.Fprintln(os.Stderr, pub)  // age1...
}
