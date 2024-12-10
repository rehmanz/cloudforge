#!/bin/bash

set -e  # Exit on error

TERRAFORM_VERSION="1.10.1"
TERRAGRUNT_VERSION="v0.69.2"
TERRAFORM_URL="https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_$(uname -s | tr '[:upper:]' '[:lower:]')_amd64.zip"
TERRAGRUNT_URL="https://github.com/gruntwork-io/terragrunt/releases/download/${TERRAGRUNT_VERSION}/terragrunt_$(uname -s | tr '[:upper:]' '[:lower:]')_amd64"

echo "Installing Terraform v${TERRAFORM_VERSION}..."
curl -fsSL -o terraform.zip "$TERRAFORM_URL"
unzip terraform.zip
chmod +x terraform
sudo mv terraform /usr/local/bin/
rm terraform.zip
echo "Terraform installed successfully."

echo "Installing Terragrunt v${TERRAGRUNT_VERSION}..."
curl -fsSL -o terragrunt "$TERRAGRUNT_URL"
chmod +x terragrunt
sudo mv terragrunt /usr/local/bin/
echo "Terragrunt installed successfully."

# Verify installations
echo "Verifying installations..."
terraform --version
terragrunt --version

echo "All tools installed successfully!"
