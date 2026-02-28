# Remove the four default GCP firewall rules that open the project to the world.
# Runs once per project; idempotent (|| true handles already-deleted rules).
resource "null_resource" "delete_default_firewall_rules" {
  triggers = {
    project_id = var.project_id
  }

  provisioner "local-exec" {
    command = <<-EOT
      for rule in default-allow-icmp default-allow-internal default-allow-rdp default-allow-ssh; do
        gcloud compute firewall-rules delete "$rule" \
          --project=${var.project_id} --quiet 2>/dev/null || true
      done
    EOT
  }
}

resource "google_compute_firewall" "oast_public" {
  name    = "oast-mcp-public"
  project = var.project_id
  network = "default"

  description = "Allow DNS, HTTP, HTTPS to oast-mcp instances"

  allow {
    protocol = "tcp"
    ports    = ["80", "443"]
  }

  allow {
    protocol = "udp"
    ports    = ["53"]
  }

  allow {
    protocol = "tcp"
    ports    = ["53"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["oast-mcp"]
}

resource "google_compute_firewall" "oast_ssh" {
  name    = "oast-mcp-ssh"
  project = var.project_id
  network = "default"

  description = "Allow SSH only from admin CIDR"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = [var.admin_ssh_cidr]
  target_tags   = ["oast-mcp"]
}
