resource "google_compute_address" "oast" {
  name    = "oast-mcp-ip"
  project = var.project_id
  region  = regex("^([a-z]+-[a-z]+[0-9]+)", var.zone)[0]
}

resource "google_compute_instance" "oast" {
  name         = "oast-mcp"
  project      = var.project_id
  zone         = var.zone
  machine_type = var.machine_type

  tags = ["oast-mcp"]

  boot_disk {
    initialize_params {
      image = var.image
      size  = var.disk_size_gb
    }
  }

  network_interface {
    network = "default"
    access_config {
      nat_ip = google_compute_address.oast.address
    }
  }

  metadata = {
    ssh-keys = "debian:${file(var.ssh_public_key_path)}"
  }

  service_account {
    email  = var.service_account_email
    scopes = ["cloud-platform"]
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }
}
