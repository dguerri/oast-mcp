variable "gcp_project_id" {
  description = "GCP project ID"
}

variable "gcp_region" {
  description = "GCP region"
  default     = "us-central1"
}

variable "gcp_zone" {
  description = "GCP zone"
  default     = "us-central1-a"
}

variable "vm_machine_type" {
  description = "Compute instance machine type"
  default     = "e2-small"
}

variable "vm_disk_size_gb" {
  description = "Boot disk size in GB"
  type        = number
  default     = 20
}

variable "vm_image" {
  description = "Boot disk image"
  default     = "debian-cloud/debian-12"
}

variable "ssh_public_key_path" {
  description = "Path to SSH public key for VM access"
}

variable "admin_ssh_cidr" {
  description = "CIDR allowed for SSH access, e.g. 203.0.113.1/32"
}

variable "oast_domain" {
  description = "OAST callback subdomain, e.g. oast.example.com. The VM acts as authoritative NS for this zone."
}

variable "parent_dns_zone_name" {
  description = "Cloud DNS managed zone name for the parent domain"
}

variable "mcp_hostname" {
  description = "FQDN for the MCP SSE endpoint. Must NOT be a child of oast_domain. E.g. mcp.example.com when oast_domain is oast.example.com."
}

variable "agent_hostname" {
  description = "FQDN for the Agent WebSocket endpoint. Must NOT be a child of oast_domain. E.g. agent.example.com when oast_domain is oast.example.com."
}

variable "caddy_dns_sa_name" {
  description = "Name of the Caddy DNS-01 service account"
  default     = "caddy-dns01"
}
