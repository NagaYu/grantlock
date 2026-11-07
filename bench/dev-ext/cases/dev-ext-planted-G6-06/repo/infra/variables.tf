# triage-agent: IAM for the agent runtime and CI deploys.

variable "db_password" {
  type      = string
  sensitive = true
}
