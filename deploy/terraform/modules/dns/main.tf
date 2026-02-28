locals {
  # e.g. "test1.oast.info" → "test1.oast.info."
  fqdn = "${var.oast_domain}."

  # Strip the first label to get the parent domain.
  # "test1.oast.info" → "oast.info"  |  "oast.example.com" → "example.com"
  # Nameservers live here so they are siblings of oast_domain, not children.
  # GCP Cloud DNS (DNSSEC) rejects NS delegations when the glue records are
  # children of the delegated zone (dnssecNsChangeDisallowedConflictingSubdomain).
  parent_domain = regex("^[^.]+\\.(.+)$", var.oast_domain)[0]
  parent_fqdn   = "${local.parent_domain}."
}

# NS record in the parent zone to delegate the oast subdomain to the VM.
# The nameserver hostnames (ns1/ns2.<parent_domain>) are siblings of oast_domain,
# so they do not fall under the delegated zone — GCP accepts them.
resource "google_dns_record_set" "oast_ns" {
  project      = var.project_id
  managed_zone = var.parent_dns_zone_name
  name         = local.fqdn
  type         = "NS"
  ttl          = 300
  rrdatas = [
    "ns1.${local.parent_fqdn}",
    "ns2.${local.parent_fqdn}",
  ]
}

# Glue A records for the nameservers — siblings of oast_domain in Cloud DNS
resource "google_dns_record_set" "ns1" {
  project      = var.project_id
  managed_zone = var.parent_dns_zone_name
  name         = "ns1.${local.parent_fqdn}"
  type         = "A"
  ttl          = 300
  rrdatas      = [var.vm_public_ip]
}

resource "google_dns_record_set" "ns2" {
  project      = var.project_id
  managed_zone = var.parent_dns_zone_name
  name         = "ns2.${local.parent_fqdn}"
  type         = "A"
  ttl          = 300
  rrdatas      = [var.vm_public_ip]
}

# NOTE: No wildcard A record for *.oast_domain — children of the delegated zone
# are rejected by Cloud DNS for the same DNSSEC reason. interactsh on the VM
# handles all *.oast_domain queries directly on port 53.

# MCP SSE endpoint — must be a sibling of oast_domain, NOT a child.
# Must live in Cloud DNS so Caddy's DNS-01 ACME challenge can write TXT records.
resource "google_dns_record_set" "mcp" {
  project      = var.project_id
  managed_zone = var.parent_dns_zone_name
  name         = "${var.mcp_hostname}."
  type         = "A"
  ttl          = 300
  rrdatas      = [var.vm_public_ip]
}

# Agent WebSocket endpoint — same constraint as MCP
resource "google_dns_record_set" "agent" {
  project      = var.project_id
  managed_zone = var.parent_dns_zone_name
  name         = "${var.agent_hostname}."
  type         = "A"
  ttl          = 300
  rrdatas      = [var.vm_public_ip]
}
