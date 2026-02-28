# GCP project setup

Complete walkthrough for preparing a GCP project before running `terraform apply`.

---

## 1. Create the project and link billing

```bash
PROJECT_ID="oast-mcp-prod"   # must be globally unique

gcloud projects create $PROJECT_ID --name="oast-mcp"
gcloud billing projects link $PROJECT_ID \
  --billing-account=$(gcloud billing accounts list --format='value(name)' --limit=1)

gcloud config set project $PROJECT_ID
```

---

## 2. Enable required APIs

```bash
gcloud services enable \
  compute.googleapis.com \
  dns.googleapis.com \
  iam.googleapis.com \
  iamcredentials.googleapis.com
```

| API | Used for |
|-----|----------|
| `compute` | VM instance, static IP, firewall rules |
| `dns` | Cloud DNS records (NS delegation, A records, wildcard) |
| `iam` | Service accounts for the VM and Caddy |
| `iamcredentials` | Generating the Caddy SA JSON key |

---

## 3. Create a GCS bucket for Terraform state

The `backend.tf` uses a GCS backend. Create the bucket before running `terraform init` — Terraform cannot bootstrap its own state bucket.

```bash
STATE_BUCKET="$PROJECT_ID-tf-state"

gcloud storage buckets create gs://$STATE_BUCKET \
  --project=$PROJECT_ID \
  --location=US \
  --uniform-bucket-level-access

gcloud storage buckets update gs://$STATE_BUCKET --versioning
```

---

## 4. Create a Cloud DNS managed zone for your parent domain

The `parent_dns_zone_name` variable must point to an **existing** managed zone. Terraform writes DNS records into it (NS delegation + glue records for `oast.example.com`) but does not create the zone itself.

```bash
gcloud dns managed-zones create example-com-zone \
  --dns-name="example.com." \
  --description="Main domain" \
  --project=$PROJECT_ID
```

Then point your domain registrar's nameservers at the Cloud DNS nameservers for this zone:

```bash
gcloud dns managed-zones describe example-com-zone \
  --format='value(nameServers)'
# → ns-cloud-a1.googledomains.com. (and three others)
```

Update those four NS records at your registrar. DNS propagation can take up to 48 hours, but is usually minutes.

---

## 5. Authenticate Terraform

### Option A — Application Default Credentials (single operator)

```bash
gcloud auth application-default login
```

### Option B — Dedicated service account (CI/CD)

```bash
TF_SA="terraform-runner"

gcloud iam service-accounts create $TF_SA \
  --project=$PROJECT_ID \
  --display-name="Terraform runner"

for ROLE in \
  roles/compute.admin \
  roles/dns.admin \
  roles/iam.serviceAccountAdmin \
  roles/iam.serviceAccountKeyAdmin \
  roles/resourcemanager.projectIamAdmin; do
  gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$TF_SA@$PROJECT_ID.iam.gserviceaccount.com" \
    --role="$ROLE"
done

gcloud iam service-accounts keys create tf-sa-key.json \
  --iam-account="$TF_SA@$PROJECT_ID.iam.gserviceaccount.com"

export GOOGLE_APPLICATION_CREDENTIALS=$PWD/tf-sa-key.json
```

---

## 6. Deploy

GCP is ready. Continue with the [README quickstart](../README.md#quickstart) — configure `deploy/.env`, run `make secrets`, `make tf-init`, `make deploy`.

---

## What Terraform creates

| Resource | Name | Purpose |
|----------|------|---------|
| Static IP | `oast-mcp-ip` | Stable address for DNS |
| Compute instance | `oast-mcp` | Debian 12, Shielded VM, `e2-small` |
| Firewall rule | `oast-mcp-public` | TCP/UDP 53, 80, 443 open to world |
| Firewall rule | `oast-mcp-ssh` | TCP 22 restricted to `admin_ssh_cidr` |
| DNS records | in `parent_dns_zone_name` | NS delegation, glue A records at parent level, `mcp_hostname`, `agent_hostname` |
| Service account | `oast-mcp-vm@…` | VM identity, no extra IAM roles |
| Service account | `caddy-dns01@…` | `roles/dns.admin` for Caddy DNS-01 ACME |
| SA JSON key | for `caddy-dns01` | Written to `/etc/caddy/gcp-sa.json` by Ansible |

---

## Teardown

```bash
make teardown   # terraform destroy (interactive) + removes generated files
```

The following are **not** touched by teardown — they were created manually and are outside Terraform's scope:

- GCS state bucket
- Enabled APIs
- IAM bindings
- Cloud DNS managed zone

`deploy/.env` and `deploy/operator.key` are also preserved. After teardown you can immediately `make tf-init && make deploy` to redeploy without repeating any of the steps above.

Delete `deploy/.env` and `deploy/operator.key` manually if retiring the deployment entirely.

---

See the [README](../README.md) for the full deployment sequence and post-deploy validation.
