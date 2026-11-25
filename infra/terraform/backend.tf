terraform {
  backend "gcs" {
    bucket = "0trust-dev-tfstate"
    prefix = "labs/data-byok"
  }
}
