provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAFAKETFPROVIDR234"
  secret_key = "FAKEtfProviderSecret0000000000000000000000"
}

variable "openai_api_key" {
  type      = string
  sensitive = true
  default   = "sk-proj-FAKEtfVarDefault00000000000000000000000000000000000T3BlbkFJ00000000000000000000000000000000000000000000000000000"
}

variable "region" {
  default = "us-east-1"
}

resource "aws_db_instance" "agent" {
  identifier = "agent-prod"
  username   = "agent"
  password   = "FAKEtfDbPassword42"
  engine     = "postgres"
}

module "network" {
  source = "./modules/network"
  cidr   = "10.0.0.0/16"
}

locals {
  name = "agent-${var.region}"
  tags = {
    Team = "agents"
  }
}
