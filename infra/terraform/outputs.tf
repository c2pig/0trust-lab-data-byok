output "pages_project_name" {
  description = "Cloudflare Pages project name for wrangler-action deployment."
  value       = module.cloudflare_pages_lab.pages_project_name
}

output "pages_subdomain" {
  description = "Default Cloudflare Pages subdomain."
  value       = module.cloudflare_pages_lab.pages_subdomain
}

output "lab_url" {
  description = "Production Model 1 custom domain URL."
  value       = module.cloudflare_pages_lab.lab_url
}
