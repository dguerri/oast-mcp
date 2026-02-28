# Domain setup

oast-mcp needs a domain you control so the VM can act as an authoritative nameserver for a dedicated OAST subdomain. This document explains how to choose, register, and wire a domain before running Terraform.

---

## How the DNS architecture works

It helps to understand what Terraform will build before you buy anything.

```
Registrar (your domain, e.g. example.com)
  └── NS → Cloud DNS  (ns-cloud-a1.googledomains.com …)
                │
                │  Terraform writes these records into Cloud DNS:
                │
                ├── NS   oast.example.com.  → ns1.example.com.   # NS delegation
                │                             ns2.example.com.
                ├── A    ns1.example.com.   → <VM IP>             # glue (sibling)
                ├── A    ns2.example.com.   → <VM IP>             # glue (sibling)
                ├── A    mcp.example.com.   → <VM IP>             # MCP SSE
                └── A    agent.example.com. → <VM IP>             # agent WS
```

- **Cloud DNS** is the authoritative nameserver for your root domain (`example.com`).
- The VM is the authoritative nameserver for the OAST subdomain (`oast.example.com`) — oast-mcp's native DNS responder binds port 53 directly.
- Every random callback hostname (e.g. `a1b2c3d4e5.oast.example.com`) hits the VM's native responder directly and is recorded as an interaction event.
- **All four A records are siblings of `oast.example.com`**, not children. GCP Cloud DNS (DNSSEC) rejects any record whose name falls under a delegated NS name in the same zone — that includes glue records like `ns1.oast.example.com.` as well as `mcp.oast.example.com.`. Terraform derives the parent domain automatically from `oast_domain`.

You need **one domain**. You use a subdomain of it (`oast.example.com`) for callbacks, and sibling records (`ns1`, `ns2`, `mcp`, `agent` at `example.com`) for infrastructure.

---

## Choosing a domain

### Dedicated vs. existing domain

Use a **dedicated domain** — not your company domain or personal site. OAST callback domains appear in target application logs and network captures. A purpose-built domain:

- keeps OAST traffic separate from production
- can be abandoned or replaced without affecting anything else
- avoids accidental exposure of your primary domain

### TLD and name selection

For security testing work, short generic-looking domains attract less scrutiny than obvious security-tool names. Common patterns:

| Good                 | Why                            |
| -------------------- | ------------------------------ |
| `r4ndom-short.io`    | neutral-looking, cheap         |
| `callbacks.sh`       | short, memorable               |
| `probe.dev`          | sounds legitimate              |
| `oast-<yourorg>.com` | clear ownership if you need it |

Avoid names that contain `xss`, `oast`, `hack`, `pentest`, or `burp` — these are often blocked by WAFs and corporate proxies before any callback reaches your server.

### TLD cost

`.com` domains cost ~$10–15/year and are the safest choice for bypass. `.io`, `.sh`, `.dev`, and `.app` are slightly more expensive but work equally well. Avoid free or shared subdomain services — you need the registrar NS records to be under your control.

---

## Registrar options

Any registrar that lets you set custom nameservers works. Three that are reliable and have clean UIs:

| Registrar                | Notes                                                                       |
| ------------------------ | --------------------------------------------------------------------------- |
| **Cloudflare Registrar** | At-cost pricing, clean API, no upsells. Good if you already use Cloudflare. |
| **Namecheap**            | Cheap, straightforward NS management, WHOIS privacy included.               |
| **Porkbun**              | Competitive pricing, simple interface.                                      |

The steps below use generic terms — every registrar has the same controls under a slightly different name ("nameservers", "custom DNS", "authoritative DNS").

---

## Step-by-step

### 1. Register the domain

Buy any domain from a registrar of your choice. Note the domain name — you will use it as the value for `oast_domain` in Terraform (with a subdomain prefix).

Example: you register `example.com`, and you will set `oast_domain = "oast.example.com"`.

### 2. Create a Cloud DNS managed zone for the root domain

This is step 4 of the [GCP project setup](gcp-project-setup.md). If you have not done it yet:

```bash
gcloud dns managed-zones create example-com-zone \
  --dns-name="example.com." \
  --description="Main domain" \
  --project=$PROJECT_ID
```

Retrieve the nameservers Cloud DNS assigned to this zone:

```bash
gcloud dns managed-zones describe example-com-zone \
  --format='value(nameServers)'
```

You will get four nameservers that look like:

```
ns-cloud-a1.googledomains.com.
ns-cloud-a2.googledomains.com.
ns-cloud-a3.googledomains.com.
ns-cloud-a4.googledomains.com.
```

### 3. Point the registrar at Cloud DNS

In your registrar's control panel, find **Nameservers** or **Custom DNS** and replace the default nameservers with the four from step 2.

**Cloudflare Registrar:** Domain → DNS → Nameservers → Custom nameservers
**Namecheap:** Domain List → Manage → Nameservers → Custom DNS
**Porkbun:** Domain → Edit Nameservers

Enter all four nameservers. Remove any existing ones. Save.

Propagation is usually complete within 15–30 minutes, but can take up to 48 hours. You can check progress:

```bash
# Replace with your actual domain
dig NS example.com +short
# Should return the ns-cloud-*.googledomains.com. servers when done
```

### 4. Run Terraform

Once NS propagation is complete, Terraform can write records into the Cloud DNS zone. Set the variables in `terraform.tfvars`:

```hcl
oast_domain          = "oast.example.com"      # subdomain for OAST callbacks (VM is NS)
parent_dns_zone_name = "example-com-zone"      # the managed zone name from step 2

# mcp/agent hostnames must be siblings of oast_domain, NOT children
mcp_hostname         = "mcp.example.com"
agent_hostname       = "agent.example.com"
```

Then apply:

```bash
cd deploy/terraform
terraform init -backend-config="bucket=YOUR_STATE_BUCKET"
terraform apply
```

Terraform creates all the DNS records (NS delegation, glue A records, mcp, agent) automatically. You do not need to touch Cloud DNS manually after this.

### 5. Verify the DNS chain

After `terraform apply` and a few minutes for TTLs to settle, verify the full chain:

```bash
VM_IP=$(terraform output -raw vm_public_ip)

# 1. Cloud DNS serves your root domain
dig NS example.com +short
# → ns-cloud-a1.googledomains.com. (etc.)

# 2. The NS delegation for the oast subdomain exists
dig NS oast.example.com +short
# → ns1.example.com.
# → ns2.example.com.

# 3. Glue records resolve (siblings of oast_domain, NOT children)
dig A ns1.example.com +short
# → $VM_IP

# 4. The VM answers authoritatively for oast subdomain queries
#    (oast-mcp must be running — deploy with Ansible first)
dig A anything.oast.example.com @$VM_IP +short
# → $VM_IP

# 5. mcp and agent hostnames resolve (siblings of oast_domain, served by Cloud DNS)
dig A mcp.example.com +short
dig A agent.example.com +short
# → $VM_IP both
```

---

## If you want to use a subdomain of an existing domain

If you already have a domain managed elsewhere (e.g. your company uses Cloudflare for `company.com`) and you only want to delegate a subdomain to oast-mcp:

1. **Skip** creating a Cloud DNS zone for the root domain.
2. **Skip** pointing the registrar at Cloud DNS.
3. In your existing DNS provider, manually add these records, replacing `<VM IP>` with `terraform output vm_public_ip`:

```
NS   oast.company.com.  ns1.company.com.   # nameservers are siblings, not children
NS   oast.company.com.  ns2.company.com.
A    ns1.company.com.   <VM IP>
A    ns2.company.com.   <VM IP>
A    mcp.company.com.   <VM IP>
A    agent.company.com. <VM IP>
```

Do **not** use `ns1.oast.company.com.` as the nameserver hostname — most DNS providers enforce the same constraint GCP does: records under a delegated NS name conflict with the delegation itself. Do **not** add a wildcard `*.oast.company.com` A record for the same reason; the native responder handles those queries on port 53.

4. Set `parent_dns_zone_name` in `terraform.tfvars` to an **empty string** and comment out the `module "dns"` block in `deploy/terraform/main.tf` — Terraform doesn't need to manage records you've added manually.

---

## Cost summary

| Item                         | Typical cost                                    |
| ---------------------------- | ----------------------------------------------- |
| Domain registration (`.com`) | ~$10–15/year                                    |
| Cloud DNS managed zone       | $0.20/month per zone                            |
| Cloud DNS queries            | $0.40/million queries (first million free)      |
| GCP VM (`e2-small`)          | ~$13/month                                      |
| Static IP                    | ~$3/month (when attached to a running instance) |

Total: roughly **$20–25/month** plus domain registration.
