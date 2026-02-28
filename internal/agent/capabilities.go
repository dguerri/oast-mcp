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

package agent

const (
	CapExec       = "exec"
	CapReadFile   = "read_file"
	CapFetchURL   = "fetch_url"
	CapSystemInfo = "system_info"
)

// AllCapabilities lists every capability string understood by the agent.
var AllCapabilities = []string{
	CapExec, CapReadFile, CapFetchURL, CapSystemInfo,
}
