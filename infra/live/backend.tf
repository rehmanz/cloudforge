# Generated by Terragrunt. Sig: nIlQXj57tbuaRZEa
terraform {
  backend "s3" {
    bucket         = "cloudforge-tf-state"
    dynamodb_table = "cloudforge-lock-table"
    encrypt        = true
    key            = "./terraform.tfstate"
    region         = "us-east-1"
  }
}
