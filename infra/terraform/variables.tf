variable "cloudflare_account_id" {
  type        = string
  description = "Cloudflare Account ID."
}

variable "cloudflare_zone_id" {
  type        = string
  description = "Cloudflare Zone ID for 0trust.dev."
}

variable "state_kv_namespace_id" {
  type        = string
  description = "Shared STATE_KV namespace ID."
}

variable "pages_project_name" {
  type        = string
  default     = "0trust-lab-data-byok"
  description = "Cloudflare Pages project name."
}

variable "subdomain_prefix" {
  type        = string
  default     = "lab-data-byok"
  description = "Subdomain prefix under domain_name."
}

variable "domain_name" {
  type        = string
  default     = "0trust.dev"
  description = "Base zone apex domain."
}
