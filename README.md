# Complete Terraform Guide - From Basics to Advanced Deployment

A comprehensive, step-by-step guide to understanding and implementing Terraform for Infrastructure as Code (IaC).

---

## Table of Contents

1. [Introduction](#introduction)
2. [Prerequisites & Setup](#prerequisites--setup)
3. [Understanding Terraform Concepts](#understanding-terraform-concepts)
4. [Terraform Configuration Blocks](#terraform-configuration-blocks)
5. [Terraform Meta-Arguments](#terraform-meta-arguments)
6. [Terraform Functions](#terraform-functions)
7. [Executing Terraform - Step by Step](#executing-terraform---step-by-step)
8. [Deployment Methods](#deployment-methods)
9. [Best Practices](#best-practices)
10. [Troubleshooting](#troubleshooting)

---

## Introduction

### What is Terraform?

Terraform is an Infrastructure-as-Code (IaC) tool by HashiCorp that allows you to define, provision, and manage infrastructure across multiple cloud providers using declarative configuration files.

### Why Use Terraform?

- **Infrastructure as Code**: Version control your infrastructure
- **Multi-Cloud Support**: AWS, Azure, GCP, and more
- **Reusable Configurations**: Use modules for standardization
- **Team Collaboration**: Share infrastructure patterns
- **Automation**: Reduce manual errors and increase speed

### How Terraform Works

```
1. Write Configuration → 2. Plan Changes → 3. Apply Changes → 4. Manage State
   (HCL Files)        (terraform plan)  (terraform apply)   (.tfstate)
```

---

## Prerequisites & Setup

### Step 1: Install Terraform

#### On macOS
```bash
# Using Homebrew
brew install terraform

# Verify installation
terraform version
```

#### On Linux (Ubuntu/Debian)
```bash
# Add HashiCorp repository
wget -O- https://apt.releases.hashicorp.com/gpg | gpg --dearmor | sudo tee /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list

# Install
sudo apt-get update && sudo apt-get install terraform

# Verify
terraform version
```

#### On Windows
```bash
# Using Chocolatey
choco install terraform

# Or download from https://www.terraform.io/downloads.html
# Add to PATH environment variable

# Verify
terraform version
```

### Step 2: Configure AWS Credentials

You need AWS credentials to access AWS resources. Choose one method:

#### Method 1: AWS CLI Configuration (Recommended)
```bash
# Install AWS CLI first
aws --version

# Configure credentials
aws configure

# Follow prompts:
# AWS Access Key ID: [enter your key]
# AWS Secret Access Key: [enter your secret]
# Default region: ap-south-1
# Default output format: json
```

This creates `~/.aws/credentials` and `~/.aws/config` files.

#### Method 2: Environment Variables
```bash
# Set in terminal (temporary)
export AWS_ACCESS_KEY_ID="your-access-key-id"
export AWS_SECRET_ACCESS_KEY="your-secret-access-key"
export AWS_DEFAULT_REGION="ap-south-1"

# Or add to ~/.bashrc or ~/.zshrc (permanent)
```

#### Method 3: IAM Role (For EC2/Lambda)
```bash
# Attach IAM role to EC2 instance
# Terraform automatically uses the role credentials
# No manual configuration needed
```

#### Verify Credentials
```bash
# Test AWS access
aws sts get-caller-identity

# Output:
# {
#     "UserId": "AIDAI...",
#     "Account": "123456789012",
#     "Arn": "arn:aws:iam::123456789012:user/your-user"
# }
```

### Step 3: Create Project Structure

Create a directory structure for your Terraform project:

```
terraform-project/
├── main.tf                 # Main resource definitions
├── variables.tf            # Input variable declarations
├── outputs.tf              # Output value declarations
├── terraform.tf            # Terraform configuration (version, backend, providers)
├── providers.tf            # Provider configuration
├── locals.tf               # Local value definitions
│
├── dev.tfvars              # Development environment variables
├── staging.tfvars          # Staging environment variables
├── prod.tfvars             # Production environment variables
│
├── user_data.sh            # EC2 initialization script
├── .gitignore              # Git ignore rules
├── README.md               # Documentation
└── .terraform/             # Auto-generated (plugins, state backup)
```

### Step 4: Create .gitignore

Never commit sensitive state files to Git:

```
# Local .terraform directories
**/.terraform/*

# .tfstate files
*.tfstate
*.tfstate.*

# Crash log files
crash.log
crash.*.log

# Exclude all .tfvars files, which might contain sensitive data
*.tfvars
*.tfvars.json

# Ignore override files
override.tf
override.tf.json
*_override.tf
*_override.tf.json

# Ignore CLI configuration files
.terraformrc
terraform.rc

# Ignore plan files
*.tfplan

# IDE files
.vscode/
.idea/
*.swp
*.swo
```

---

## Understanding Terraform Concepts

### Core Concepts

#### 1. State File (terraform.tfstate)
- Stores current infrastructure state
- Tracks resource IDs, attributes, and dependencies
- **NEVER commit to Git** - contains sensitive data
- Used to detect changes between plan and apply

#### 2. Configuration Files (.tf)
- Written in HashiCorp Configuration Language (HCL)
- Define desired infrastructure state
- Declarative (WHAT, not HOW)

#### 3. Plan
- Preview of changes before applying
- Shows what will be created (+), modified (~), or destroyed (-)
- Safe to review before making changes

#### 4. Apply
- Executes the planned changes
- Creates, modifies, or deletes infrastructure
- Updates state file

#### 5. Variables
- Input parameters for configurations
- Make configurations reusable across environments
- Set via .tfvars files, CLI, or environment variables

#### 6. Outputs
- Export values from Terraform
- Display resource details after apply
- Consumed by other tools or humans

#### 7. Modules
- Reusable Terraform code
- Encapsulate infrastructure patterns
- Similar to functions in programming

---

## Terraform Configuration Blocks

### Block 1: Terraform Block

**Purpose**: Specifies Terraform version, backend, and required providers.

**Location**: At the top of `terraform.tf`

**Example**:
```hcl
terraform {
  # Enforce minimum Terraform version
  required_version = ">= 1.0"

  # Configure remote state storage
  backend "s3" {
    bucket         = "my-terraform-state"
    key            = "prod/terraform.tfstate"
    region         = "ap-south-1"
    encrypt        = true
    dynamodb_table = "terraform-locks"  # For state locking
  }

  # Specify required providers and versions
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"  # Allows 5.x but not 6.x
    }
  }
}
```

**Key Attributes**:
- `required_version`: Terraform version constraint (e.g., "~> 1.0", ">= 1.0")
- `backend`: Where state file is stored (local, s3, terraform cloud, etc.)
- `required_providers`: Provider versions and sources

**When to Use**:
- Always at the root of your Terraform configuration
- For team projects, use remote backend (not local)

---

### Block 2: Provider Block

**Purpose**: Configures the cloud provider (AWS, Azure, GCP).

**Location**: In `providers.tf`

**Example**:
```hcl
provider "aws" {
  # AWS region where resources are created
  region = var.aws_region

  # Tags applied to ALL resources
  default_tags {
    tags = {
      Environment = var.environment
      ManagedBy   = "Terraform"
      Project     = var.project_name
      CreatedDate = timestamp()
    }
  }
}
```

**Key Attributes**:
- `region`: AWS region for resources
- `default_tags`: Tags automatically applied to all resources
- `assume_role`: Cross-account access (for multi-account deployments)

**When to Use**:
- Once per cloud provider
- Multiple times for multi-region or multi-cloud deployments

---

### Block 3: Variables Block

**Purpose**: Declares input parameters for your configuration.

**Location**: In `variables.tf`

**Example**:
```hcl
# Simple string variable
variable "aws_region" {
  description = "AWS region where resources will be created"
  type        = string
  default     = "ap-south-1"
}

# Number variable with validation
variable "instance_count" {
  description = "Number of EC2 instances to create"
  type        = number
  default     = 1

  validation {
    condition     = var.instance_count >= 1 && var.instance_count <= 5
    error_message = "Instance count must be between 1 and 5"
  }
}

# List variable
variable "allowed_ssh_ports" {
  description = "Ports allowed for SSH access"
  type        = list(number)
  default     = [22]
}

# Map variable
variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default = {
    Terraform = "true"
  }
}

# Required variable (no default)
variable "owner_email" {
  description = "Email of the resource owner"
  type        = string
}

# Sensitive variable (hidden in logs)
variable "db_password" {
  description = "Database password"
  type        = string
  sensitive   = true
}
```

**Variable Types**:
| Type | Example | Use Case |
|------|---------|----------|
| `string` | `"t2.micro"` | Text values |
| `number` | `3` | Numeric values |
| `bool` | `true` | Flags/toggles |
| `list(string)` | `["a", "b"]` | Multiple items |
| `map(string)` | `{key = "val"}` | Key-value pairs |
| `object()` | Complex | Nested structures |

**Setting Variable Values**:

```bash
# 1. Via .tfvars file
terraform apply -var-file="prod.tfvars"

# 2. Via command line
terraform apply -var="instance_count=3"

# 3. Via environment variables
export TF_VAR_instance_count=3
terraform apply

# 4. Interactive prompt (if no default)
terraform apply  # Prompts for required variables
```

---

### Block 4: Locals Block

**Purpose**: Define local values computed from variables.

**Location**: In `locals.tf` or top of `main.tf`

**Example**:
```hcl
locals {
  # Computed naming pattern
  instance_name = "${var.project_name}-${var.environment}-ec2"

  # Environment-specific configuration
  environment_config = {
    dev = {
      instance_type = "t2.micro"
      volume_size   = 20
    }
    prod = {
      instance_type = "t3.large"
      volume_size   = 100
    }
  }

  # Select current environment config
  current_config = local.environment_config[var.environment]

  # Common tags (avoid repetition)
  common_tags = {
    Project     = var.project_name
    Environment = var.environment
    Owner       = var.owner_email
    ManagedBy   = "Terraform"
  }
}
```

**Usage in Resources**:
```hcl
resource "aws_instance" "web" {
  instance_type = local.current_config.instance_type

  tags = merge(
    local.common_tags,
    { Name = local.instance_name }
  )
}
```

**Benefits**:
- DRY (Don't Repeat Yourself)
- Easy to maintain
- Single source of truth for derived values

---

### Block 5: Data Block

**Purpose**: Query existing AWS resources without creating them.

**Location**: In `main.tf` or dedicated `data.tf`

**Example**:
```hcl
# Find latest Amazon Linux 2 AMI
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

# Get current AWS account information
data "aws_caller_identity" "current" {}

# Find default VPC
data "aws_vpc" "default" {
  filter {
    name   = "isDefault"
    values = ["true"]
  }
}

# Find all subnets in default VPC
data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}
```

**Common Data Sources**:
| Data Source | Purpose |
|------------|---------|
| `aws_ami` | Find AMI by filters |
| `aws_vpc` | Reference existing VPC |
| `aws_subnets` | Find subnets |
| `aws_caller_identity` | AWS account info |
| `aws_availability_zones` | Available AZs |

**Usage**:
```hcl
resource "aws_instance" "web" {
  ami           = data.aws_ami.amazon_linux.id
  instance_type = "t2.micro"
}
```

---

### Block 6: Resource Block

**Purpose**: Define infrastructure to be created and managed.

**Location**: In `main.tf`

**Example**:
```hcl
resource "aws_instance" "web" {
  # Configuration
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"

  # Root volume configuration
  root_block_device {
    volume_size = 20
    encrypted   = true
  }

  # Tags
  tags = {
    Name = "web-server"
  }
}
```

**Resource Syntax**:
```hcl
resource "<provider>_<resource_type>" "<local_name>" {
  attribute = value
}
```

**Referencing Resources**:
```hcl
# Use output of one resource as input to another
resource "aws_security_group" "web_sg" {
  vpc_id = aws_instance.web.vpc_id
}
```

---

### Block 7: Output Block

**Purpose**: Export values from your configuration.

**Location**: In `outputs.tf`

**Example**:
```hcl
output "instance_id" {
  description = "ID of the EC2 instance"
  value       = aws_instance.web.id
}

output "public_ip" {
  description = "Public IP of the instance"
  value       = aws_eip.web.public_ip
}

output "connection_string" {
  description = "SSH command to connect"
  value       = "ssh -i key.pem ec2-user@${aws_eip.web.public_ip}"
}

output "sensitive_password" {
  description = "Database password"
  value       = aws_db_instance.main.password
  sensitive   = true  # Hide from console output
}
```

**Displaying Outputs**:
```bash
# Show all outputs
terraform output

# Show specific output
terraform output public_ip

# JSON format (for scripting)
terraform output -json

# Raw value (no quotes)
terraform output -raw public_ip
```

---

## Terraform Meta-Arguments

### Meta-Argument 1: count

**Purpose**: Create multiple similar resources.

**Example**:
```hcl
# Create 3 EC2 instances
resource "aws_instance" "web" {
  count         = var.instance_count
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"

  tags = { Name = "web-${count.index + 1}" }
}

# Reference specific instance
output "first_instance_ip" {
  value = aws_instance.web[0].private_ip
}

# Reference all instances (splat syntax)
output "all_instance_ips" {
  value = aws_instance.web[*].private_ip
}

# Conditional creation
resource "aws_instance" "prod_only" {
  count = var.environment == "prod" ? 1 : 0
}
```

**When to Use**:
- Fixed number of resources
- Conditional creation
- Simple lists

---

### Meta-Argument 2: for_each

**Purpose**: Create resources from a map or set.

**Example**:
```hcl
# Create rules for multiple ports
resource "aws_security_group_rule" "allow_ports" {
  for_each = toset([22, 80, 443])

  type              = "ingress"
  from_port         = each.value
  to_port           = each.value
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.web.id
}

# Create resources from map
variable "environments" {
  default = {
    dev  = { instance_type = "t2.micro" }
    prod = { instance_type = "t3.large" }
  }
}

resource "aws_instance" "env_servers" {
  for_each      = var.environments
  instance_type = each.value.instance_type

  tags = { Name = "server-${each.key}" }
}
```

**When to Use**:
- Multiple resources from maps/sets
- Dynamic lists of resources
- When resource identity matters

**Advantage over count**:
- Map keys are stable
- More readable targeting
- Better for dynamic collections

---

### Meta-Argument 3: depends_on

**Purpose**: Explicitly specify resource dependencies.

**Example**:
```hcl
resource "aws_instance" "web" {
  # Explicit dependencies
  depends_on = [
    aws_security_group.web,
    aws_network_interface.web
  ]
}
```

**When to Use**:
- When implicit dependency doesn't exist
- To prevent parallel execution
- To document complex relationships

---

### Meta-Argument 4: provider

**Purpose**: Use specific provider for multi-region/multi-account.

**Example**:
```hcl
# Define provider aliases
provider "aws" {
  alias  = "us_east"
  region = "us-east-1"
}

provider "aws" {
  alias  = "eu_west"
  region = "eu-west-1"
}

# Use specific provider
resource "aws_instance" "us_instance" {
  provider = aws.us_east
}

resource "aws_instance" "eu_instance" {
  provider = aws.eu_west
}
```

---

### Meta-Argument 5: lifecycle

**Purpose**: Control resource creation, update, and destruction behavior.

**Example**:
```hcl
resource "aws_instance" "web" {
  # Create new before destroying old (zero-downtime)
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_db_instance" "main" {
  # Prevent accidental deletion
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket" "data" {
  # Ignore changes to these attributes
  lifecycle {
    ignore_changes = [tags["LastModified"]]
  }
}
```

---

## Terraform Functions

### String Functions

```hcl
locals {
  # Formatting
  name = format("web-%s-%s", var.environment, var.region)

  # Concatenation
  path = join("/", [var.bucket, var.prefix, var.file])

  # Case conversion
  env_upper = upper(var.environment)
  env_lower = lower(var.environment)

  # String splitting
  parts = split(",", "a,b,c")  # ["a", "b", "c"]
}
```

### Collection Functions

```hcl
locals {
  # List operations
  ports = [22, 80, 443]
  sorted_ports = sort(var.ports)
  unique_ports = distinct(var.ports)
  combined = concat([22], var.additional_ports)

  # Map operations
  tag_values = values(local.tags)
  tag_keys = keys(local.tags)
  lookup_value = lookup(local.config, "key", "default")

  # Filtering
  web_ports = [for p in var.ports : p if p > 1024]
  port_map = { for p in var.ports : p => "port-${p}" }
}
```

### Type Conversion Functions

```hcl
locals {
  # String conversion
  port_string = tostring(80)

  # Type conversion
  port_number = tonumber("80")
  bool_value = tobool("true")

  # List/Map conversion
  list_from_string = split(",", "a,b,c")
  map_from_list = { for item in var.items : item => item }
}
```

### Conditional Functions

```hcl
locals {
  # Ternary operator
  instance_type = var.environment == "prod" ? "t3.large" : "t2.micro"

  # Try function (returns value or default)
  value = try(var.optional_value, "default")
}
```

---

## Executing Terraform - Step by Step

### Complete Terraform Workflow

This is the standard workflow for every Terraform deployment.

#### Step 1: Initialize Terraform

```bash
terraform init
```

**What it does**:
- Downloads provider plugins
- Initializes backend
- Creates `.terraform/` directory
- Generates `.terraform.lock.hcl` file

**Output**:
```
Initializing the backend...
Initializing provider plugins...
Terraform has been successfully configured!
```

**Options**:
```bash
# Initialize without backend (for testing)
terraform init -backend=false

# Reconfigure backend
terraform init -reconfigure

# Migrate backend
terraform init -migrate-state
```

---

#### Step 2: Format and Validate

```bash
# Format code
terraform fmt -recursive

# Validate syntax
terraform validate
```

**Output**:
```
Success! The configuration is valid.
```

---

#### Step 3: Create a Plan

```bash
# Generate plan
terraform plan

# Save plan to file
terraform plan -out=tfplan

# Plan with specific variables
terraform plan -var-file="prod.tfvars"

# Plan specific resource
terraform plan -target="aws_instance.web"

# Plan to destroy
terraform plan -destroy
```

**Output shows**:
- `+` Resources to create
- `~` Resources to modify
- `-` Resources to destroy
- `<=` Computed/read-only values

**Example Output**:
```
Terraform will perform the following actions:

  # aws_instance.web will be created
  + resource "aws_instance" "web" {
      + ami           = "ami-0c55b159cbfafe1f0"
      + instance_type = "t2.micro"
      + tags = {
          + "Name" = "web-server"
        }
    }

Plan: 1 to add, 0 to change, 0 to destroy.
```

---

#### Step 4: Apply Configuration

```bash
# Apply with approval prompt
terraform apply

# Apply without approval
terraform apply -auto-approve

# Apply saved plan
terraform apply tfplan

# Apply specific resource
terraform apply -target="aws_instance.web"
```

**During Apply**:
- Terraform creates/updates/deletes resources
- Updates `terraform.tfstate` file
- Displays outputs

**Output**:
```
Apply complete! Resources: 1 added, 0 changed, 0 destroyed.

Outputs:

instance_id = "i-1234567890abcdef0"
public_ip = "54.123.45.67"
```

---

#### Step 5: View Infrastructure State

```bash
# Show all resources
terraform show

# List all resources
terraform state list

# Show specific resource
terraform state show aws_instance.web
```

---

#### Step 6: View Outputs

```bash
# Display all outputs
terraform output

# Display specific output
terraform output instance_id

# JSON format
terraform output -json

# Raw value
terraform output -raw public_ip
```

---

#### Step 7: Destroy Infrastructure

```bash
# Destroy with confirmation
terraform destroy

# Destroy without confirmation
terraform destroy -auto-approve

# Destroy specific resource
terraform destroy -target="aws_instance.web"

# Destroy and check first
terraform plan -destroy
terraform destroy
```

---

### Complete Workflow Script

```bash
#!/bin/bash
set -e

ENVIRONMENT="prod"
TFVARS_FILE="${ENVIRONMENT}.tfvars"

echo "=== Terraform Deployment Script ==="
echo "Environment: $ENVIRONMENT"
echo ""

# Step 1: Initialize
echo "[1/6] Initializing Terraform..."
terraform init
echo "✓ Initialized"
echo ""

# Step 2: Format and validate
echo "[2/6] Formatting and validating..."
terraform fmt -recursive
terraform validate
echo "✓ Valid"
echo ""

# Step 3: Create plan
echo "[3/6] Creating plan..."
terraform plan -var-file="$TFVARS_FILE" -out=tfplan
echo "✓ Plan created"
echo ""

# Step 4: Manual approval
echo "[4/6] Review the plan above."
read -p "Continue with apply? (yes/no): " response
if [[ "$response" != "yes" ]]; then
  echo "Deployment cancelled"
  exit 1
fi
echo ""

# Step 5: Apply
echo "[5/6] Applying configuration..."
terraform apply tfplan
echo "✓ Applied"
echo ""

# Step 6: Display outputs
echo "[6/6] Deployment complete!"
echo ""
echo "Outputs:"
terraform output
echo ""

# Backup state
echo "Backing up state file..."
cp terraform.tfstate "terraform.tfstate.backup.$(date +%s)"
echo "✓ Complete"
```

**Run the script**:
```bash
chmod +x deploy.sh
./deploy.sh
```

---

## Deployment Methods

### Method 1: Single Environment Deployment

Deploy to one environment (dev, staging, or prod).

**Step 1: Create tfvars file**

```hcl
# prod.tfvars
aws_region     = "ap-south-1"
environment    = "prod"
project_name   = "myapp"
instance_count = 3
instance_type  = "t3.large"
enable_monitoring = true
owner_email    = "ops@example.com"
cost_center    = "engineering"
```

**Step 2: Deploy**

```bash
# Plan
terraform plan -var-file="prod.tfvars" -out=prod.tfplan

# Review the plan

# Apply
terraform apply prod.tfplan

# Show outputs
terraform output
```

---

### Method 2: Multi-Environment Deployment

Deploy same configuration to dev, staging, and prod.

**Step 1: Create environment-specific tfvars files**

```hcl
# dev.tfvars
aws_region     = "ap-south-1"
environment    = "dev"
project_name   = "myapp"
instance_count = 1
instance_type  = "t2.micro"
enable_monitoring = false
owner_email    = "dev@example.com"
```

```hcl
# staging.tfvars
aws_region     = "ap-south-1"
environment    = "staging"
project_name   = "myapp"
instance_count = 2
instance_type  = "t3.small"
enable_monitoring = true
owner_email    = "staging@example.com"
```

```hcl
# prod.tfvars
aws_region     = "ap-south-1"
environment    = "prod"
project_name   = "myapp"
instance_count = 3
instance_type  = "t3.large"
enable_monitoring = true
owner_email    = "prod@example.com"
```

**Step 2: Deploy to each environment**

```bash
# Deploy to DEV
echo "=== Deploying to DEV ==="
terraform init
terraform plan -var-file="dev.tfvars" -out=dev.tfplan
terraform apply dev.tfplan

# Deploy to STAGING
echo "=== Deploying to STAGING ==="
terraform plan -var-file="staging.tfvars" -out=staging.tfplan
terraform apply staging.tfplan

# Deploy to PROD
echo "=== Deploying to PROD ==="
terraform plan -var-file="prod.tfvars" -out=prod.tfplan
terraform apply prod.tfplan
```

---

### Method 3: Using Terraform Workspaces

Manage multiple environments with separate state files.

**Step 1: Create workspaces**

```bash
# List current workspaces
terraform workspace list

# Create new workspaces
terraform workspace new dev
terraform workspace new staging
terraform workspace new prod
```

**Step 2: Deploy to each workspace**

```bash
# Switch to dev workspace
terraform workspace select dev
terraform apply -var-file="dev.tfvars" -auto-approve

# Switch to staging workspace
terraform workspace select staging
terraform apply -var-file="staging.tfvars" -auto-approve

# Switch to prod workspace
terraform workspace select prod
terraform apply -var-file="prod.tfvars" -auto-approve

# Back to default
terraform workspace select default
```

**Benefits**:
- Separate state files per environment
- Easy environment switching
- Isolated deployments

---

### Method 4: Terraform Cloud (Remote Backend)

Use Terraform Cloud for team collaboration.

**Step 1: Sign up for Terraform Cloud**

```bash
# Go to https://app.terraform.io
# Create account and organization
```

**Step 2: Authenticate**

```bash
# Generate API token at https://app.terraform.io/app/settings/tokens
terraform login

# Follow prompts to enter token
```

**Step 3: Configure backend**

```hcl
# terraform.tf
terraform {
  cloud {
    organization = "my-organization"
    
    workspaces {
      name = "production"
    }
  }
}
```

**Step 4: Deploy**

```bash
terraform init
terraform plan
terraform apply
```

**Benefits**:
- Team collaboration
- Run history
- VCS integration
- Remote state management
- Cost estimation

---

### Method 5: GitHub Actions CI/CD

Automate Terraform execution with GitHub Actions.

**Step 1: Create workflow file**

```yaml
# .github/workflows/terraform.yml
name: Terraform CI/CD

on:
  push:
    branches: [main]
    paths:
      - 'terraform/**'
  pull_request:
    paths:
      - 'terraform/**'

env:
  TF_VERSION: 1.0

jobs:
  terraform:
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v3
      
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v2
        with:
          terraform_version: ${{ env.TF_VERSION }}
      
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v2
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: ap-south-1
      
      - name: Terraform Init
        run: terraform -chdir=terraform init
      
      - name: Terraform Format
        run: terraform -chdir=terraform fmt -check
      
      - name: Terraform Validate
        run: terraform -chdir=terraform validate
      
      - name: Terraform Plan
        run: terraform -chdir=terraform plan -var-file="prod.tfvars" -out=tfplan
      
      - name: Terraform Apply
        if: github.ref == 'refs/heads/main' && github.event_name == 'push'
        run: terraform -chdir=terraform apply -auto-approve tfplan
      
      - name: Terraform Plan (PR)
        if: github.event_name == 'pull_request'
        run: terraform -chdir=terraform plan -var-file="prod.tfvars"
```

**Step 2: Add GitHub Secrets**

```bash
# Go to GitHub repo → Settings → Secrets → New repository secret
# Add:
# - AWS_ACCESS_KEY_ID
# - AWS_SECRET_ACCESS_KEY
```

**Step 3: Deploy**

```bash
# Create pull request
git checkout -b feature/new-infrastructure
git add terraform/
git commit -m "Add new EC2 instance"
git push origin feature/new-infrastructure

# GitHub Actions automatically runs:
# 1. Terraform format check
# 2. Terraform validation
# 3. Terraform plan

# After review and merge to main:
# 4. Terraform apply executes automatically
```

---

### Method 6: Targeted/Partial Deployment

Deploy or modify specific resources.

```bash
# Plan only specific resource
terraform plan -target="aws_instance.web"

# Apply only specific resource
terraform apply -target="aws_instance.web" -auto-approve

# Useful for fixing specific resources without full deployment
```

---

### Method 7: Import Existing Resources

Bring existing AWS resources into Terraform management.

**Step 1: Define resource block (empty)**

```hcl
# main.tf
resource "aws_instance" "imported" {
  # Leave empty - will be populated by import
}
```

**Step 2: Import resource**

```bash
# Get instance ID from AWS console
# Format: terraform import <resource_type>.<name> <resource_id>

terraform import aws_instance.imported i-1234567890abcdef0
```

**Output**:
```
aws_instance.imported: Importing from ID "i-1234567890abcdef0"...
aws_instance.imported: Import complete!
```

**Step 3: Update configuration to match**

```bash
# Check what was imported
terraform state show aws_instance.imported

# Update main.tf to match imported resource's attributes
# Then run plan to ensure no changes
terraform plan  # Should show no changes
```

**Benefits**:
- Manage existing infrastructure
- Gradually migrate to Terraform
- No re-provisioning needed

---

## Best Practices

### 1. Project Organization

**Good Structure**:
```
project/
├── main.tf              # Resource definitions
├── variables.tf         # Input variables
├── outputs.tf           # Output values
├── locals.tf            # Local values
├── terraform.tf         # Terraform config
├── providers.tf         # Provider setup
├── dev.tfvars
├── staging.tfvars
├── prod.tfvars
├── user_data.sh
├── .gitignore
└── README.md
```

---

### 2. Naming Conventions

```hcl
# Good: Descriptive names
resource "aws_instance" "web_server_prod" {
  tags = { Name = "web-server-prod" }
}

# Bad: Vague names
resource "aws_instance" "test" {
  tags = { Name = "t1" }
}

# Good: Clear variable names
variable "database_instance_size" { type = string }
variable "enable_monitoring" { type = bool }

# Bad: Unclear names
variable "db_size" { type = string }
variable "mon" { type = bool }
```

---

### 3. State Management

```bash
# NEVER commit state files to Git
# Add to .gitignore:
*.tfstate
*.tfstate.*
.terraform/

# Always use remote backend for teams
terraform {
  backend "s3" {
    bucket         = "terraform-state"
    key            = "prod/terraform.tfstate"
    encrypt        = true
    dynamodb_table = "terraform-locks"
  }
}

# Backup state regularly
cp terraform.tfstate terraform.tfstate.backup.$(date +%s)
```

---

### 4. Security Best Practices

```hcl
# Mark sensitive variables
variable "db_password" {
  type      = string
  sensitive = true
}

# Encrypt data at rest
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Use IAM roles, not access keys
# For EC2: Attach IAM role
# For Lambda: Use execution role
# For CI/CD: Use OIDC provider

# Enable logging and monitoring
resource "aws_instance" "web" {
  monitoring = true
  
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"  # IMDSv2
    http_put_response_hop_limit = 1
  }
}
```

---

### 5. Documentation

```hcl
# Document variables clearly
variable "instance_type" {
  description = <<-EOT
    EC2 instance type. 
    Recommended: t2.micro for dev, t3.small for staging, t3.large for prod
  EOT
  type        = string
  default     = "t2.micro"
}

# Document outputs
output "database_endpoint" {
  description = "RDS endpoint for application configuration. Use port 5432."
  value       = aws_db_instance.main.endpoint
}

# Document resources
resource "aws_instance" "web" {
  # Production web server with monitoring enabled
  # Update AMI quarterly for security patches
  monitoring = true
}
```

---

### 6. Version Control

```bash
# Commit to Git
git add main.tf variables.tf outputs.tf terraform.tf

# DO NOT commit
# - terraform.tfstate (state file)
# - .terraform/ (plugins)
# - *.tfvars (may contain secrets)
# - .terraform.lock.hcl (team may use different providers)

# For team: Commit lock file
git add .terraform.lock.hcl

# Good commit message
git commit -m "Add EC2 instance and security group for web servers"

# Bad commit message
git commit -m "update"
```

---

### 7. Testing

```bash
# Validate syntax
terraform validate

# Format check
terraform fmt -check -recursive

# Lint code
tflint

# Security scan
checkov -d .

# Plan before apply
terraform plan -out=tfplan

# Dry run in non-prod first
terraform plan -var-file="staging.tfvars"
```

---

### 8. Code Review Checklist

Before merging/applying:

```bash
# ✓ Security
- No hardcoded secrets
- Encryption enabled
- IAM least privilege
- IMDSv2 enabled

# ✓ Functionality
- Syntax valid (terraform validate)
- Plan reviewed (terraform plan)
- Outputs defined
- Dependencies correct

# ✓ Best Practices
- Descriptive names
- Tags present
- Documentation complete
- Variables validated

# ✓ State Management
- Remote backend configured
- State file not committed
- Lock file present (if team)

# ✓ Deployment
- Tested in dev first
- Staging approval received
- Rollback plan exists
```

---

## Troubleshooting

### Common Issues and Solutions

#### Issue 1: "Error acquiring the state lock"

**Problem**: Another user/process has the state file locked.

**Solution**:
```bash
# Wait for other process to complete, then:
terraform plan

# If stuck, force unlock (DANGEROUS - only if sure):
terraform force-unlock LOCK_ID
```

---

#### Issue 2: "Error: resource already exists in AWS"

**Problem**: Resource exists in AWS but not in Terraform state.

**Solution**:
```bash
# Option 1: Import resource
terraform import aws_instance.web i-1234567890abcdef0

# Option 2: Delete from AWS and re-create
# (If you don't need the existing resource)
```

---

#### Issue 3: "Provider version mismatch"

**Problem**: Provider version is different from .terraform.lock.hcl

**Solution**:
```bash
# Update providers
terraform init -upgrade

# Or specify exact version in terraform.tf:
required_providers {
  aws = {
    version = "= 5.0.0"
  }
}

# Then:
terraform init -upgrade
```

---

#### Issue 4: "Backend initialization failed"

**Problem**: Can't connect to remote backend (S3, TFC, etc.)

**Solution**:
```bash
# Check credentials
aws sts get-caller-identity

# Reconfigure backend
terraform init -reconfigure

# Use local backend temporarily for testing
terraform init -backend=false

# Then migrate back:
terraform init -migrate-state
```

---

#### Issue 5: "Invalid or unknown key"

**Problem**: Syntax error in Terraform configuration.

**Solution**:
```bash
# Validate syntax
terraform validate

# Format code
terraform fmt -recursive

# Check for typos in attribute names
# Compare with AWS provider documentation
```

---

#### Issue 6: "Insufficient IAM permissions"

**Problem**: AWS credentials don't have required permissions.

**Solution**:
```bash
# Check current user
aws sts get-caller-identity

# View permissions
aws iam list-attached-user-policies --user-name YOUR_USER

# Add required permissions
# Go to AWS IAM console and attach policies

# Or create custom policy:
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:*",
        "elasticip:*"
      ],
      "Resource": "*"
    }
  ]
}
```

---

#### Issue 7: "Resource destroyed outside Terraform"

**Problem**: Infrastructure manually deleted in AWS console.

**Solution**:
```bash
# Refresh state
terraform refresh

# Or run plan to see what changed
terraform plan

# Update state manually if needed
terraform state rm aws_instance.web  # Remove from state
terraform import aws_instance.web <id>  # Re-import
```

---

## Quick Reference

### Essential Commands

```bash
# Core workflow
terraform init          # Initialize
terraform plan          # Preview changes
terraform apply         # Deploy
terraform destroy       # Cleanup

# State management
terraform state list    # List resources
terraform state show    # Show resource details
terraform state rm      # Remove from state
terraform state pull    # Download state

# Formatting and validation
terraform fmt           # Format code
terraform validate      # Check syntax
terraform fmt -check    # Check if formatted

# Inspection
terraform output        # Show outputs
terraform show          # Show state
terraform console       # Interactive REPL

# Workspaces
terraform workspace new   # Create workspace
terraform workspace list  # List workspaces
terraform workspace select # Switch workspace

# Advanced
terraform import        # Import resource
terraform taint         # Mark for replacement
terraform untaint       # Unmark resource
terraform graph         # Show dependency graph
```

---

### Common Options

```bash
# Variables
-var="key=value"              # Set variable
-var-file="prod.tfvars"       # Use tfvars file
-var-file="prod.tfvars"       # Multiple files
-var-file="common.tfvars" -var-file="prod.tfvars"

# Output
-out=tfplan                   # Save plan
-no-color                     # No colored output
-json                         # JSON output

# Targeting
-target="aws_instance.web"    # Specific resource
-target="module.vpc"          # Specific module

# Other
-auto-approve                 # Skip approval
-compact-warnings             # Compact warnings
-lock-timeout=5m              # Lock timeout
```

---

## Summary

### Terraform Execution Flow

```
1. Write Configuration (HCL files)
         ↓
2. terraform init (Setup)
         ↓
3. terraform plan (Preview)
         ↓
4. Review Plan
         ↓
5. terraform apply (Deploy)
         ↓
6. Verify Infrastructure
         ↓
7. terraform destroy (Cleanup when needed)
```

### When to Use Each Method

| Method | Use Case | Complexity |
|--------|----------|-----------|
| Single Environment | Small projects, testing | Low |
| Multi-Environment | Multiple environments (dev/staging/prod) | Medium |
| Workspaces | Multiple similar deployments | Medium |
| Terraform Cloud | Team collaboration, VCS integration | High |
| CI/CD Pipeline | Automated deployments on push | High |
| Targeted Deployment | Fix specific resources | Low-Medium |
| Import | Migrate existing infrastructure | Medium |

---

## Further Resources

- **Official Terraform Docs**: https://www.terraform.io/docs
- **AWS Provider Documentation**: https://registry.terraform.io/providers/hashicorp/aws/latest/docs
- **Terraform Registry**: https://registry.terraform.io
- **HashiCorp Learn**: https://learn.hashicorp.com/terraform

---

## Document Version

- **Version**: 1.0
- **Last Updated**: 2025
- **Terraform Version**: 1.0+
- **AWS Provider Version**: 5.0+

This comprehensive guide covers all aspects of Terraform from basics to advanced deployment strategies. Use it as a reference while implementing Infrastructure as Code projects.