variable "project_id" {
  description = "GCP project ID"
}

variable "parent_dns_zone_name" {
  description = "Cloud DNS managed zone name for parent domain"
}

variable "oast_domain" {
  description = "OAST callback subdomain, e.g. oast.example.com. The VM (interactsh) is authoritative NS for this zone."
}

variable "vm_public_ip" {
  description = "Static public IP of the VM"
}

variable "mcp_hostname" {
  description = "FQDN for the MCP SSE endpoint. Must be a sibling of oast_domain (same parent), NOT a child. E.g. mcp.example.com when oast_domain is oast.example.com."
}

variable "agent_hostname" {
  description = "FQDN for the Agent WebSocket endpoint. Must be a sibling of oast_domain (same parent), NOT a child. E.g. agent.example.com when oast_domain is oast.example.com."
}
