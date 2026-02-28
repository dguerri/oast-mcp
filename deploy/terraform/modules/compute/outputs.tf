output "public_ip" {
  description = "Static public IP of the oast-mcp VM"
  value       = google_compute_address.oast.address
}

output "instance_name" {
  description = "Compute instance name"
  value       = google_compute_instance.oast.name
}
