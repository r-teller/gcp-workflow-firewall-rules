terraform {
  backend "gcs" {
    bucket = "gcp-workflow-firewall-rules"
    prefix = "tfstate/"
  }
}