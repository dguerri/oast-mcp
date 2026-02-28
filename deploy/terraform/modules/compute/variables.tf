variable "project_id"    { description = "GCP project ID" }
variable "zone"          { description = "GCP zone" }
variable "machine_type"  { default = "e2-small" }
variable "disk_size_gb" {
  type    = number
  default = 20
}
variable "image"         { default = "debian-cloud/debian-12" }
variable "ssh_public_key_path" { description = "Path to SSH public key" }
variable "service_account_email" { description = "VM service account email" }
