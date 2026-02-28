# VM service account (minimal permissions — DNS admin granted only to Caddy SA)
resource "google_service_account" "oast_vm" {
  project      = var.gcp_project_id
  account_id   = "oast-mcp-vm"
  display_name = "oast-mcp VM service account"
}

module "compute" {
  source                = "./modules/compute"
  project_id            = var.gcp_project_id
  zone                  = var.gcp_zone
  machine_type          = var.vm_machine_type
  disk_size_gb          = var.vm_disk_size_gb
  image                 = var.vm_image
  ssh_public_key_path   = var.ssh_public_key_path
  service_account_email = google_service_account.oast_vm.email
}

module "firewall" {
  source         = "./modules/firewall"
  project_id     = var.gcp_project_id
  admin_ssh_cidr = var.admin_ssh_cidr
}

module "dns" {
  source               = "./modules/dns"
  project_id           = var.gcp_project_id
  parent_dns_zone_name = var.parent_dns_zone_name
  oast_domain          = var.oast_domain
  vm_public_ip         = module.compute.public_ip
  mcp_hostname         = var.mcp_hostname
  agent_hostname       = var.agent_hostname
}

# Caddy DNS-01 service account + DNS admin role + key
resource "google_service_account" "caddy_dns" {
  project      = var.gcp_project_id
  account_id   = var.caddy_dns_sa_name
  display_name = "Caddy DNS-01 ACME challenge"
}

resource "google_project_iam_member" "caddy_dns_admin" {
  project = var.gcp_project_id
  role    = "roles/dns.admin"
  member  = "serviceAccount:${google_service_account.caddy_dns.email}"
}

resource "google_service_account_key" "caddy_dns" {
  service_account_id = google_service_account.caddy_dns.name
}

output "vm_public_ip" {
  description = "Static public IP of the oast-mcp VM"
  value       = module.compute.public_ip
}

output "vm_ssh_target" {
  description = "SSH target string"
  value       = "debian@${module.compute.public_ip}"
}

output "oast_dns_ns1" {
  description = "NS1 glue record FQDN"
  value       = module.dns.ns1_fqdn
}

output "caddy_gcp_sa_key_b64" {
  description = "Base64-encoded GCP service account JSON key for Caddy DNS-01"
  value       = google_service_account_key.caddy_dns.private_key
  sensitive   = true
}
