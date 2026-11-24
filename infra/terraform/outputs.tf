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

output "cloud_run_service_name" {
  description = "GCP Cloud Run service name powering /api/data-byok/*."
  value       = module.cloud_run_lab.service_name
}

output "cloud_run_service_uri" {
  description = "GCP Cloud Run service origin URI (configured in 0trust-lab-router)."
  value       = module.cloud_run_lab.service_uri
}

output "cloud_run_service_account_email" {
  description = "Least-privilege GCP runtime service account email for Lab 7."
  value       = module.cloud_run_lab.service_account_email
}
