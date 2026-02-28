BINARY  := oast-mcp
LDFLAGS := -trimpath -ldflags="-s -w"

DEPLOY_DIR := deploy
TF_DIR     := $(DEPLOY_DIR)/terraform
ANS_DIR    := $(DEPLOY_DIR)/ansible

# Load deploy/.env if it exists. Variables already in the environment take precedence.
-include $(DEPLOY_DIR)/.env
export

# Defaults for optional variables (can be overridden in deploy/.env)
GCP_REGION      ?= us-central1
GCP_ZONE        ?= us-central1-a
VM_MACHINE_TYPE ?= e2-micro
VM_DISK_SIZE_GB ?= 20
VM_IMAGE        ?= debian-cloud/debian-12

.PHONY: build test lint cover cross clean build-loader-c build-loaders build-agents build-all
.PHONY: secrets tf-generate tf-init tf-apply inventory ansible deploy teardown

COVER_THRESHOLD ?= 60

# ── Go ────────────────────────────────────────────────────────────────────────

build:
	go build $(LDFLAGS) -o bin/$(BINARY) ./cmd/oast-mcp

cross:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY)-linux-amd64 ./cmd/oast-mcp

AGENT_TARGETS  := linux-amd64 linux-arm64 windows-amd64

# Build Linux loader binaries in C via Docker + Alpine + musl + mbedTLS (from source).
# Uses `docker build --output` — no volume mounts required; build context is sent to daemon.
# Docker layer caching means mbedTLS is only rebuilt when the Dockerfile changes.
# Produces bin/loader-linux-amd64 and bin/loader-linux-arm64.
build-loader-c:
	@command -v docker >/dev/null 2>&1 || { echo "error: docker required to build C loaders"; exit 1; }
	@mkdir -p bin
	@echo "Building C loader linux/amd64..."
	@tmpdir=$$(mktemp -d) && \
	 docker build --platform linux/amd64 --output type=local,dest=$$tmpdir cmd/loader-c && \
	 cp $$tmpdir/loader bin/loader-linux-amd64 && rm -rf $$tmpdir
	@chmod +x bin/loader-linux-amd64
	@printf "  linux/amd64: %d bytes\n" $$(wc -c < bin/loader-linux-amd64)
	@echo "Building C loader linux/arm64 (cross-compiled on amd64 via musl.cc toolchain)..."
	@tmpdir=$$(mktemp -d) && \
	 docker build --platform linux/amd64 -f cmd/loader-c/Dockerfile.arm64 \
	     --output type=local,dest=$$tmpdir cmd/loader-c && \
	 cp $$tmpdir/loader bin/loader-linux-arm64 && rm -rf $$tmpdir
	@chmod +x bin/loader-linux-arm64
	@printf "  linux/arm64: %d bytes\n" $$(wc -c < bin/loader-linux-arm64)

# Build all loaders: C for Linux, Go for Windows.
build-loaders: build-loader-c
	@mkdir -p bin
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o bin/loader-windows-amd64.exe ./cmd/loader
	@if command -v upx >/dev/null 2>&1; then \
	  upx --best --lzma bin/loader-windows-amd64.exe 2>/dev/null || true; fi
	@echo "All loaders built"

build-agents:
	@mkdir -p bin
	$(foreach t,$(AGENT_TARGETS), \
	  GOOS=$(word 1,$(subst -, ,$(t))) GOARCH=$(word 2,$(subst -, ,$(t))) \
	  go build $(LDFLAGS) -o bin/agent-$(t)$(if $(filter windows-%,$(t)),.exe,) \
	  ./cmd/agent;)
	@if command -v upx >/dev/null 2>&1; then \
	  upx --best --lzma bin/agent-* 2>/dev/null || true; \
	  echo "UPX compressed agents"; \
	else echo "upx not found — skipping compression"; fi

build-all: build build-loaders build-agents

test:
	go test ./... -race -count=1 -timeout=60s

cover:
	go test ./internal/... -race -count=1 -timeout=60s -coverprofile=coverage.out -covermode=atomic -coverpkg=./internal/...
	go tool cover -func=coverage.out | tee /dev/stderr | \
	  awk '/^total:/{pct=$$3+0; if(pct<$(COVER_THRESHOLD)){printf "FAIL: coverage %.1f%% below threshold %d%%\n",pct,$(COVER_THRESHOLD); exit 1} else {printf "OK: coverage %.1f%%\n",pct}}'

lint:
	golangci-lint run ./...

clean:
	rm -rf bin/

# ── First-time setup ──────────────────────────────────────────────────────────

## Generate JWT key + age operator keypair and write to deploy/.env.
## Run once. Refuses to overwrite an existing deploy/.env.
secrets: build
	@[ ! -f $(DEPLOY_DIR)/.env ] || { \
	  echo "deploy/.env already exists. Delete it first to regenerate."; exit 1; }
	@mkdir -p $(DEPLOY_DIR)
	@echo "Generating secrets..."
	@JWT=$$(openssl rand -hex 32); \
	 TSIG=$$(openssl rand -hex 32); \
	 ./bin/$(BINARY) keygen > $(DEPLOY_DIR)/operator.key 2>/tmp/_oast_pub; \
	 PUB=$$(cat /tmp/_oast_pub); rm -f /tmp/_oast_pub; \
	 cp $(DEPLOY_DIR)/.env.example $(DEPLOY_DIR)/.env; \
	 sed -i.bak "s|^JWT_KEY=.*|JWT_KEY=$$JWT|" $(DEPLOY_DIR)/.env; \
	 sed -i.bak "s|^OPERATOR_PUB=.*|OPERATOR_PUB=$$PUB|" $(DEPLOY_DIR)/.env; \
	 sed -i.bak "s|^TSIG_KEY_HEX=.*|TSIG_KEY_HEX=$$TSIG|" $(DEPLOY_DIR)/.env; \
	 rm -f $(DEPLOY_DIR)/.env.bak
	@echo "  deploy/.env        — created (JWT_KEY + OPERATOR_PUB + TSIG_KEY_HEX filled in)"
	@echo "  deploy/operator.key — age private key (keep safe, not in git)"
	@echo ""
	@echo "Next: fill in the remaining values in deploy/.env, then:"
	@echo "  make tf-init"

# ── Terraform ─────────────────────────────────────────────────────────────────

## Generate deploy/terraform/terraform.tfvars from deploy/.env.
## Called automatically by tf-apply.
tf-generate:
	@[ -n "$(GCP_PROJECT_ID)" ]       || { echo "Error: GCP_PROJECT_ID not set in deploy/.env";       exit 1; }
	@[ -n "$(TF_BACKEND_BUCKET)" ]    || { echo "Error: TF_BACKEND_BUCKET not set in deploy/.env";    exit 1; }
	@[ -n "$(SSH_KEY)" ]              || { echo "Error: SSH_KEY not set in deploy/.env";                exit 1; }
	@[ -n "$(ADMIN_SSH_CIDR)" ]       || { echo "Error: ADMIN_SSH_CIDR not set in deploy/.env";       exit 1; }
	@[ -n "$(OAST_DOMAIN)" ]          || { echo "Error: OAST_DOMAIN not set in deploy/.env";          exit 1; }
	@[ -n "$(PARENT_DNS_ZONE_NAME)" ] || { echo "Error: PARENT_DNS_ZONE_NAME not set in deploy/.env"; exit 1; }
	@[ -n "$(MCP_HOSTNAME)" ]         || { echo "Error: MCP_HOSTNAME not set in deploy/.env";         exit 1; }
	@[ -n "$(AGENT_HOSTNAME)" ]       || { echo "Error: AGENT_HOSTNAME not set in deploy/.env";       exit 1; }
	@{ \
	  printf 'gcp_project_id       = "%s"\n' "$(strip $(GCP_PROJECT_ID))";      \
	  printf 'gcp_region           = "%s"\n' "$(strip $(GCP_REGION))";          \
	  printf 'gcp_zone             = "%s"\n' "$(strip $(GCP_ZONE))";            \
	  printf 'vm_machine_type      = "%s"\n' "$(strip $(VM_MACHINE_TYPE))";     \
	  printf 'vm_disk_size_gb      = %s\n'   "$(strip $(VM_DISK_SIZE_GB))";     \
	  printf 'vm_image             = "%s"\n' "$(strip $(VM_IMAGE))";            \
	  printf 'ssh_public_key_path  = "%s"\n' "$(strip $(SSH_KEY)).pub";         \
	  printf 'admin_ssh_cidr       = "%s"\n' "$(strip $(ADMIN_SSH_CIDR))";      \
	  printf 'oast_domain          = "%s"\n' "$(strip $(OAST_DOMAIN))";         \
	  printf 'parent_dns_zone_name = "%s"\n' "$(strip $(PARENT_DNS_ZONE_NAME))";\
	  printf 'mcp_hostname         = "%s"\n' "$(strip $(MCP_HOSTNAME))";        \
	  printf 'agent_hostname       = "%s"\n' "$(strip $(AGENT_HOSTNAME))";      \
	} > $(TF_DIR)/terraform.tfvars
	@echo "Generated $(TF_DIR)/terraform.tfvars"

## Initialise Terraform backend. Run once per machine or after backend changes.
tf-init: tf-generate
	cd $(TF_DIR) && terraform init -backend-config="bucket=$(strip $(TF_BACKEND_BUCKET))"

## Generate terraform.tfvars then run terraform apply (interactive confirmation).
tf-apply: tf-generate
	cd $(TF_DIR) && terraform apply

# ── Ansible ───────────────────────────────────────────────────────────────────

## Generate deploy/ansible/inventory/hosts.yml from terraform output + SSH_KEY.
## Called automatically by `make ansible`.
inventory:
	@[ -n "$(SSH_KEY)" ]     || { echo "Error: SSH_KEY not set in deploy/.env";     exit 1; }
	@[ -n "$(OAST_DOMAIN)" ] || { echo "Error: OAST_DOMAIN not set in deploy/.env"; exit 1; }
	@VM_IP=$$(cd $(TF_DIR) && terraform output -raw vm_public_ip 2>/dev/null); \
	 [ -n "$$VM_IP" ] || { \
	   echo "Error: terraform output vm_public_ip is empty. Run 'make tf-apply' first."; exit 1; }; \
	 mkdir -p $(ANS_DIR)/inventory; \
	 printf 'all:\n  children:\n    oast:\n      hosts:\n        oast-mcp-01:\n          ansible_host: "%s"\n          ansible_user: debian\n          ansible_ssh_private_key_file: "%s"\n' \
	   "$$VM_IP" "$(strip $(SSH_KEY))" > $(ANS_DIR)/inventory/hosts.yml; \
	 echo "Generated $(ANS_DIR)/inventory/hosts.yml (ansible_host=$$VM_IP)"

## Run the Ansible playbook. Generates inventory first, pulls all vars from deploy/.env.
ansible: inventory
	@[ -n "$(JWT_KEY)" ]          || { echo "Error: JWT_KEY not set. Run 'make secrets'.";         exit 1; }
	@[ -n "$(OPERATOR_PUB)" ]     || { echo "Error: OPERATOR_PUB not set. Run 'make secrets'.";   exit 1; }
	@[ -n "$(TSIG_KEY_HEX)" ]     || { echo "Error: TSIG_KEY_HEX not set. Run 'make secrets'.";   exit 1; }
	@[ -n "$(OAST_DOMAIN)" ]      || { echo "Error: OAST_DOMAIN not set in deploy/.env";           exit 1; }
	@[ -n "$(MCP_HOSTNAME)" ]     || { echo "Error: MCP_HOSTNAME not set in deploy/.env";          exit 1; }
	@[ -n "$(AGENT_HOSTNAME)" ]   || { echo "Error: AGENT_HOSTNAME not set in deploy/.env";        exit 1; }
	@[ -n "$(GCP_PROJECT_ID)" ]   || { echo "Error: GCP_PROJECT_ID not set in deploy/.env";        exit 1; }
	@[ -n "$(ACME_EMAIL)" ]       || { echo "Error: ACME_EMAIL not set in deploy/.env";            exit 1; }
	@CADDY_SA=$$(cd $(TF_DIR) && terraform output -raw caddy_gcp_sa_key_b64 2>/dev/null); \
	 VM_IP=$$(cd $(TF_DIR) && terraform output -raw vm_public_ip 2>/dev/null); \
	 [ -n "$$CADDY_SA" ] || { \
	   echo "Error: caddy_gcp_sa_key_b64 is empty. Run 'make tf-apply' first."; exit 1; }; \
	 [ -n "$$VM_IP" ] || { \
	   echo "Error: vm_public_ip is empty. Run 'make tf-apply' first."; exit 1; }; \
	 TSIG_KEY_B64=$$(printf '%s' "$(strip $(TSIG_KEY_HEX))" | xxd -r -p | base64); \
	 cd $(ANS_DIR) && ansible-playbook \
	   -i inventory/hosts.yml \
	   -e "oast_domain=$(strip $(OAST_DOMAIN))" \
	   -e "mcp_hostname=$(strip $(MCP_HOSTNAME))" \
	   -e "agent_hostname=$(strip $(AGENT_HOSTNAME))" \
	   -e "gcp_project_id=$(strip $(GCP_PROJECT_ID))" \
	   -e "acme_email=$(strip $(ACME_EMAIL))" \
	   -e "jwt_signing_key_hex=$(strip $(JWT_KEY))" \
	   -e "operator_public_key=$(strip $(OPERATOR_PUB))" \
	   -e "caddy_gcp_sa_key=$$CADDY_SA" \
	   -e "public_ip=$$VM_IP" \
	   -e "tsig_key_name=caddy." \
	   -e "tsig_key_hex=$(strip $(TSIG_KEY_HEX))" \
	   -e "tsig_key_b64=$$TSIG_KEY_B64" \
	   playbook.yml

# ── Full pipeline ─────────────────────────────────────────────────────────────

## Build binary, apply Terraform, then run Ansible. Full deploy from scratch.
deploy: cross build-loaders build-agents tf-apply ansible

# ── Teardown ──────────────────────────────────────────────────────────────────

## Destroy Terraform-managed GCP resources and remove generated files.
## The following are NOT touched (created manually, outside Terraform):
##   GCS state bucket, enabled APIs, IAM bindings, Cloud DNS zone.
## deploy/.env and deploy/operator.key are also preserved.
teardown:
	cd $(TF_DIR) && terraform destroy
	@rm -f $(ANS_DIR)/inventory/hosts.yml
	@rm -f $(TF_DIR)/terraform.tfvars
	@echo ""
	@echo "Infrastructure destroyed."
	@echo "Preserved: GCS state bucket, APIs, IAM bindings, DNS zone, deploy/.env, deploy/operator.key"
	@echo "Run 'make tf-init && make deploy' to redeploy without any GCP setup steps."
	@echo "Delete deploy/.env and deploy/operator.key manually if retiring this deployment."
