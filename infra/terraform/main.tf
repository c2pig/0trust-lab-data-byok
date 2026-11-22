provider "cloudflare" {}

module "cloudflare_pages_lab" {
  source = "git::https://github.com/c2pig/managed-infrastructure.git//modules/cloudflare-pages-lab?ref=main"

  cloudflare_account_id = var.cloudflare_account_id
  cloudflare_zone_id    = var.cloudflare_zone_id
  state_kv_namespace_id = var.state_kv_namespace_id
  pages_project_name    = var.pages_project_name
  subdomain_prefix      = var.subdomain_prefix
  domain_name           = var.domain_name
}
