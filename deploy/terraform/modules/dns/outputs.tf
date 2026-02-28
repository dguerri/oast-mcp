output "ns1_fqdn" {
  description = "NS1 glue record FQDN (sibling of oast_domain, at parent domain level)"
  value       = "ns1.${local.parent_domain}."
}

output "ns2_fqdn" {
  description = "NS2 glue record FQDN (sibling of oast_domain, at parent domain level)"
  value       = "ns2.${local.parent_domain}."
}
