# ============================================================================
# TERRAFORM CONFIGURATION BLOCK
# ============================================================================
# This block specifies the required Terraform version and providers.
# It ensures that anyone running this configuration uses compatible versions.
#
# required_version: Minimum Terraform version required (1.0 or higher)
#   Terraform 1.0+ provides stable APIs and better error handling
#
# required_providers: Specifies which providers are needed and their versions
#   - aws: The AWS provider for managing AWS resources
#   - source: "hashicorp/aws" - Official AWS provider from HashiCorp
#   - version: "~> 5.0" - Allows any version 5.x but not 6.0+
#     The ~> operator allows patch and minor version updates but not major
# ============================================================================
terraform {
  required_version = ">= 1.0"
  
  backend "s3" {
    bucket         = "git-hpha-terraform-state"
    key            = "terraformv2/environments/prod/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    use_lockfile = true
    # S3 native locking explanation:
    # Terraform will attempt to create a temporary lock object alongside
    # the state file (for example: terraform.tfstate.tflock) using S3's
    # conditional-write capability (If-None-Match). The PUT will succeed
    # only if the lock object doesn't already exist. If another process
    # has already created the lock object, the conditional write will
    # fail and Terraform will not proceed with state-changing operations.
    # When the operation finishes, Terraform deletes the lock object.
    # This prevents concurrent modifications of the same remote state
    # and avoids corruption or lost updates.
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# ============================================================================
# AWS PROVIDER CONFIGURATION
# ============================================================================
# The provider block configures how Terraform interacts with AWS.
# This tells Terraform which AWS region to use for all resource creation.
#
# region: The AWS region where resources will be created
#   This comes from the variable var.aws_region (set in terraform.tfvars)
#   Examples: "us-east-1", "us-west-2", "eu-west-1"
#
# Note: All resources created by this configuration will be in this region.
# If you need resources in multiple regions, you would define multiple provider
# blocks with aliases.
# ============================================================================
provider "aws" {
  region = var.aws_region
}

# ============================================================================
# MODULE: Network Infrastructure
# ============================================================================
# This module creates the foundational networking components:
#   - VPC (Virtual Private Cloud)
#   - Internet Gateway
#   - Two public subnets in different availability zones
#   - Route tables and associations
#   - Discovers the latest Amazon Linux 2 AMI
#
# Module Source: "../../modules/network" - Relative path to the network module
#
# Input Variables:
#   - aws_region: Region where resources will be created
#   - vpc_cidr: IP address range for the VPC (e.g., "10.2.0.0/16" for prod)
#   - vpc_name: Name tag for the VPC (e.g., "prod-vpc")
#   - public_subnet_1_cidr: IP range for first public subnet (e.g., "10.2.1.0/24")
#   - public_subnet_2_cidr: IP range for second public subnet (e.g., "10.2.2.0/24")
#
# Outputs Used Later:
#   - module.network.vpc_id: Used by security and ALB modules
#   - module.network.public_subnet_1_id: Used by instances and ALB modules
#   - module.network.public_subnet_2_id: Used by instances and ALB modules
#   - module.network.amazon_linux_2_ami_id: Used by instances module
#
# Dependency Order: This module has no dependencies, so it's created first.
# ============================================================================
module "network" {
  source = "../../modules/network"

  aws_region          = var.aws_region
  vpc_cidr            = var.vpc_cidr
  vpc_name            = "${var.environment}-vpc"
  public_subnet_1_cidr = var.public_subnet_1_cidr
  public_subnet_2_cidr = var.public_subnet_2_cidr
}

# ============================================================================
# MODULE: Security Groups
# ============================================================================
# This module creates security groups (virtual firewalls) that control
# network traffic to and from AWS resources.
#
# Resources Created:
#   - Security group for Application Load Balancer (allows HTTP from internet)
#   - Security group for EC2 instances (allows HTTP only from ALB)
#
# Module Source: "../../modules/security" - Relative path to the security module
#
# Input Variables:
#   - vpc_id: The VPC where security groups will be created
#     This comes from the network module output
#   - environment: Environment name for naming and tagging
#
# Outputs Used Later:
#   - module.security.ec2_security_group_id: Attached to EC2 instances
#   - module.security.alb_security_group_id: Attached to Application Load Balancer
#
# Dependency: Requires network module to be created first (needs VPC ID)
# ============================================================================
module "security" {
  source = "../../modules/security"

  vpc_id      = module.network.vpc_id
  environment = var.environment
}

# ============================================================================
# MODULE: EC2 Instances (Web Servers)
# ============================================================================
# This module creates two EC2 instances that will serve as web servers.
# The instances are deployed in different availability zones for high availability.
#
# Resources Created:
#   - EC2 Instance 1: In public subnet 1 (first availability zone)
#   - EC2 Instance 2: In public subnet 2 (second availability zone)
#
# Module Source: "../../modules/instances" - Relative path to the instances module
#
# Input Variables:
#   - ami_id: Amazon Machine Image ID (from network module)
#   - instance_type: EC2 instance size (e.g., "t2.medium" for prod)
#   - public_subnet_1_id: Subnet for first instance (from network module)
#   - public_subnet_2_id: Subnet for second instance (from network module)
#   - ec2_security_group_id: Security group for instances (from security module)
#   - environment: Environment name for naming and user data customization
#
# User Data Script: Automatically installs and configures Apache web server
#   on each instance when it first starts.
#
# Outputs Used Later:
#   - module.instances.web_1_instance_id: Attached to ALB target group
#   - module.instances.web_2_instance_id: Attached to ALB target group
#
# Dependencies:
#   - Requires network module (for subnets and AMI)
#   - Requires security module (for security group)
# ============================================================================
module "instances" {
  source = "../../modules/instances"

  ami_id                = module.network.amazon_linux_2_ami_id
  instance_type         = var.instance_type
  public_subnet_1_id    = module.network.public_subnet_1_id
  public_subnet_2_id    = module.network.public_subnet_2_id
  ec2_security_group_id = module.security.ec2_security_group_id
  environment           = var.environment
}

# ============================================================================
# MODULE: Application Load Balancer (ALB)
# ============================================================================
# This module creates an Application Load Balancer that distributes incoming
# web traffic across the two EC2 instances.
#
# Resources Created:
#   - Application Load Balancer (internet-facing)
#   - Target Group (defines which instances receive traffic)
#   - Target Group Attachments (connects instances to target group)
#   - Listener (accepts HTTP traffic on port 80)
#
# Module Source: "../../modules/alb" - Relative path to the ALB module
#
# Input Variables:
#   - vpc_id: VPC where ALB will be created (from network module)
#   - public_subnet_1_id: First subnet for ALB (from network module)
#   - public_subnet_2_id: Second subnet for ALB (from network module)
#   - alb_security_group_id: Security group for ALB (from security module)
#   - web_1_instance_id: First EC2 instance to attach (from instances module)
#   - web_2_instance_id: Second EC2 instance to attach (from instances module)
#   - environment: Environment name for naming
#
# How It Works:
#   1. Internet traffic arrives at ALB's public DNS name
#   2. ALB performs health checks on both instances
#   3. ALB distributes traffic to healthy instances
#   4. If one instance fails, traffic automatically goes to the other
#
# Outputs:
#   - module.alb.alb_dns_name: Public URL to access the application
#     This is displayed after terraform apply completes
#
# Dependencies:
#   - Requires network module (for VPC and subnets)
#   - Requires security module (for ALB security group)
#   - Requires instances module (for EC2 instance IDs)
# ============================================================================
module "alb" {
  source = "../../modules/alb"

  vpc_id                = module.network.vpc_id
  public_subnet_1_id    = module.network.public_subnet_1_id
  public_subnet_2_id    = module.network.public_subnet_2_id
  alb_security_group_id = module.security.alb_security_group_id
  web_1_instance_id     = module.instances.web_1_instance_id
  web_2_instance_id     = module.instances.web_2_instance_id
  environment           = var.environment
}

