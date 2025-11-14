# ============================================================================
# TERRAFORM CONFIGURATION - Comprehensive EC2 Instance Deployment
# ============================================================================
# This file demonstrates all major Terraform constructs and components
# for creating and managing an AWS EC2 instance with best practices.
# ============================================================================

# ============================================================================
# 1. TERRAFORM BLOCK
# ============================================================================
# Purpose: Specifies Terraform version constraints, required providers, and backend config
# Why use: Ensures consistent Terraform versions across team and lockstep provider updates
# When to use: At the root of every Terraform module configuration
# How to use: Define before other blocks; Terraform reads this first
terraform {
  # Required Terraform version constraint
  # Type: String constraint (e.g., "~> 1.0", ">= 1.0", "= 1.5.0")
  # Why: Prevents incompatibilities from outdated or newer versions
  required_version = ">= 1.0"

  # Backend configuration - stores and manages state file
  # Type: Backend type (s3, azurerm, gcs, consul, etc.)
  # Why: Enables team collaboration by storing state in centralized location
  # When: Always use remote backend for team projects (local default unsafe for teams)
  backend "s3" {
    bucket         = "my-terraform-state"
    key            = "prod/terraform.tfstate"
    region         = "ap-south-1"
    encrypt        = true
    dynamodb_table = "terraform-locks"
  }

  # Required providers - specifies dependencies
  # Type: Provider name with source and version constraints
  # Why: Ensures specific provider versions are used; prevents breaking changes
  # How: Each provider gets a source and version constraint
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0" # Allows 5.x but not 6.x
    }
  }
}

# ============================================================================
# 2. PROVIDER BLOCK
# ============================================================================
# Purpose: Configures the AWS provider with authentication and region settings
# Type: Provider configuration block
# Why use: Tells Terraform which cloud/service to connect to and how
# When to use: Required for every provider you use
# How to use: Use variables for dynamic configuration across environments
provider "aws" {
  # The region where resources will be created
  # Type: String
  # Why: AWS requires explicit region; allows multi-region deployments with multiple providers
  # When: Specify for each provider; can be overridden per resource
  region = var.aws_region

  # Default tags applied to all resources created by this provider
  # Type: Map of strings
  # Why: Ensures consistent tagging across all resources for cost tracking and compliance
  # How: AWS automatically applies these tags to every resource
  default_tags {
    tags = {
      Environment = var.environment
      ManagedBy   = "Terraform"
      CreatedAt   = timestamp()
    }
  }
}

# ============================================================================
# 3. LOCALS BLOCK
# ============================================================================
# Purpose: Defines local values/expressions for reuse within this module
# Type: Local variable declarations
# Why use: Reduces repetition, improves maintainability, keeps logic in one place
# When to use: For derived values, computed strings, or values used multiple times
# How to use: Reference with local.<name>; can reference variables and other locals
locals {
  # Derived value combining multiple variables
  # Type: String (computed)
  # Why: Reusable naming convention applied consistently
  instance_name = "${var.project_name}-${var.environment}-ec2"

  # Environment-specific settings as a map
  # Type: Map of strings
  # Why: Different configurations for dev/staging/prod without conditional logic
  environment_config = {
    dev = {
      instance_type = "t2.micro"
      volume_size   = 20
      monitoring    = false
    }
    prod = {
      instance_type = "t3.small"
      volume_size   = 50
      monitoring    = true
    }
  }

  # Current environment settings (dynamic lookup)
  # Type: Map of strings (from environment_config)
  # Why: Safely get environment-specific values; prevents key errors with merge
  current_env_config = merge(
    local.environment_config[var.environment],
    var.environment_overrides
  )

  # Common tags to apply to all resources
  # Type: Map of strings
  # Why: Reduces repetition; ensures consistency; single source of truth for tags
  common_tags = {
    Project     = var.project_name
    Environment = var.environment
    Owner       = var.owner_email
    CostCenter  = var.cost_center
  }
}

# ============================================================================
# 4. VARIABLES BLOCK
# ============================================================================
# Purpose: Declares input variables - the interface to your module
# Type: Input variable declarations
# Why use: Makes configurations reusable, testable, and environment-agnostic
# When to use: For every value that might change between environments/deployments
# How to use: Set via .tfvars files, CLI flags, or environment variables

variable "aws_region" {
  # Description appears in terraform plan and helps documentation
  # Type: String
  # Why: Required for users to understand what the variable does
  description = "AWS region where resources will be created"

  # Data type of the variable
  # Type: type (string, number, bool, list, map, object, tuple)
  # Why: Validates input and enables IDE autocompletion
  # When: Always specify for production code
  type = string

  # Default value used if not provided
  # Type: Matches the type constraint
  # Why: Makes variables optional; useful for common values
  # When: Use for non-critical configs; omit for required values
  default = "ap-south-1"

  # Input validation to ensure only valid values accepted
  # Type: List of condition blocks
  # Why: Prevents invalid configurations early; improves error messages
  # When: For critical values with limited valid options
  validation {
    condition     = contains(["ap-south-1", "us-east-1", "eu-west-1"], var.aws_region)
    error_message = "AWS region must be one of: ap-south-1, us-east-1, eu-west-1"
  }

  # Marks this as a sensitive variable
  # Type: Boolean
  # Why: Prevents value from showing in logs or console output (for secrets)
  sensitive = false
}

variable "environment" {
  description = "Deployment environment (dev, staging, prod)"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod"
  }
}

variable "project_name" {
  description = "Project name used for resource naming and tagging"
  type        = string
  # No default = required variable; must be provided
}

variable "instance_count" {
  description = "Number of EC2 instances to create"
  type        = number
  default     = 1

  # Validate that count is between 1 and 5
  validation {
    condition     = var.instance_count >= 1 && var.instance_count <= 5
    error_message = "Instance count must be between 1 and 5"
  }
}

variable "enable_monitoring" {
  description = "Enable detailed monitoring for EC2 instances"
  type        = bool
  default     = false
}

variable "allowed_ssh_ports" {
  description = "List of ports allowed for SSH inbound traffic"
  type        = list(number)
  default     = [22]
}

variable "tags" {
  description = "Additional tags to apply to resources"
  type        = map(string)
  default = {
    Terraform = "true"
  }
}

variable "ami_id" {
  description = "AMI ID for the EC2 instance (optional - uses data source if not provided)"
  type        = string
  default     = ""
}

variable "owner_email" {
  description = "Email of the resource owner"
  type        = string
}

variable "cost_center" {
  description = "Cost center for billing allocation"
  type        = string
}

variable "environment_overrides" {
  description = "Environment-specific configuration overrides"
  type        = map(any)
  default     = {}
}

# ============================================================================
# 5. DATA BLOCK
# ============================================================================
# Purpose: Queries existing AWS resources (AMI, VPC, subnets, etc.)
# Type: Data source block
# Why use: Fetch dynamic information without hardcoding; single source of truth
# When to use: For values that change or are managed outside Terraform
# How to use: Reference with data.<type>.<name>.<attribute>

# Data source: Find the most recent Amazon Linux 2 AMI
# Type: aws_ami data source
# Why: Instead of hardcoding AMI ID, dynamically find latest; auto-updates with patches
# When: Use for base AMIs that receive updates; not for custom AMIs
data "aws_ami" "amazon_linux" {
  # Condition: Use data source only if ami_id variable is empty
  # Type: Conditional expression
  # Why: Allow override via variable, but default to data source lookup
  count = var.ami_id == "" ? 1 : 0

  # Find the most recent AMI matching filters
  # Type: Boolean
  # Why: Gets latest security patches and updates
  most_recent = true

  # Filter by AMI owners
  # Type: List of strings (AWS account IDs or aliases)
  # Why: Ensures we get official AWS AMIs, not community/malicious ones
  owners = ["amazon"]

  # Filters to narrow down AMI results
  # Type: Filter blocks with name and values
  # Why: Specify OS, architecture, and other characteristics
  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }

  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Data source: Get the current AWS account ID
# Type: aws_caller_identity data source
# Why: Reference account ID without hardcoding; useful for ARNs and policies
# When: Building ARNs, policies, or cross-account references
data "aws_caller_identity" "current" {
  # No arguments needed - returns current account info
}

# Data source: Get VPC and subnet information
# Type: aws_vpc data source
# Why: Dynamically find the default VPC instead of hardcoding
# When: Deploying to default VPC or querying existing VPCs
data "aws_vpc" "default" {
  # Filter for the default VPC
  filter {
    name   = "isDefault"
    values = ["true"]
  }
}

# Data source: Get available subnets in the default VPC
# Type: aws_subnets data source
# Why: Dynamically find subnets instead of hardcoding subnet IDs
# When: Need to place resources in available subnets
data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

# ============================================================================
# 6. RESOURCE BLOCKS
# ============================================================================
# Purpose: Defines AWS infrastructure resources to create, update, or delete
# Type: Resource declaration
# Why use: Central mechanism for declaring desired infrastructure state
# When to use: For every resource you want Terraform to manage
# How to use: Reference with resource.<type>.<name>.<attribute>

# ============================================================================
# 6.1 Security Group Resource
# ============================================================================
# Purpose: Define firewall rules for the EC2 instance
# Type: aws_security_group resource
# Why: Controls ingress/egress traffic for security
# When: Always create for ec2 instances; use least privilege rules
resource "aws_security_group" "web" {
  # Resource name in Terraform (not AWS name)
  # Type: String identifier
  # Why: Used to reference this resource in other blocks
  # Convention: descriptive names reflecting purpose

  # Description of the security group
  # Type: String
  # Why: Appears in AWS console; helps operators understand purpose
  description = "Security group for web server EC2 instance"

  # VPC where this security group is created
  # Type: String (VPC ID)
  # Why: Explicitly specify VPC; prevents accidental creation in wrong VPC
  vpc_id = data.aws_vpc.default.id

  # Tags for identification and cost tracking
  # Type: Map of strings
  # Why: AWS best practice; enables filtering, cost allocation, automation
  tags = merge(
    local.common_tags,
    {
      Name = "${local.instance_name}-sg"
    }
  )

  # Lifecycle meta-argument
  # Type: Lifecycle block
  # Why: Recreate security group before destroying (prevents downtime)
  # When: For resources that other resources depend on
  lifecycle {
    create_before_destroy = true
  }
}

# ============================================================================
# 6.2 Security Group Rules - Dynamic Generation
# ============================================================================
# Purpose: Allow inbound traffic on specified ports
# Type: aws_security_group_rule resource with for_each
# Why use for_each: Dynamically create multiple rules from a list
# When to use: For variable lists of ports/IPs; reduces repetition
# How: for_each iterates over each port in the allowed_ssh_ports variable

# Dynamic ingress rules for SSH access
# Type: Resource with for_each meta-argument
# Why: Create one rule per port without repetition
# How: for_each creates instance for each item in list
resource "aws_security_group_rule" "allow_ssh" {
  # Convert list to set for for_each (for_each requires unique values)
  # Type: Map (from toset conversion)
  # Why: for_each requires set or map; toset converts list to set
  for_each = toset(var.allowed_ssh_ports)

  # Type of rule: ingress (inbound) or egress (outbound)
  type              = "ingress"
  from_port         = tonumber(each.value) # Convert string port to number
  to_port           = tonumber(each.value)
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"] # WARNING: Open to world; use restrictive CIDR in production
  security_group_id = aws_security_group.web.id
}

# Dynamic egress rule for HTTP outbound traffic
# Type: Resource with for_each meta-argument
# Why: Allow multiple protocols for outbound traffic
resource "aws_security_group_rule" "allow_outbound_http" {
  for_each = toset([80, 443])

  type              = "egress"
  from_port         = each.value
  to_port           = each.value
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.web.id
}

# ============================================================================
# 6.3 Network Interface for EC2
# ============================================================================
# Purpose: Explicitly define network interface for the EC2 instance
# Type: aws_network_interface resource
# Why: Provides control over IP assignments and subnet placement
# When: When you need precise network configuration
resource "aws_network_interface" "web" {
  # Subnet where the network interface is created
  # Type: String (Subnet ID)
  # Why: Determines which AZ and VPC the instance launches in
  subnet_id = data.aws_subnets.default.ids[0] # Use first available subnet

  # Security groups for this network interface
  # Type: List of security group IDs
  security_groups = [aws_security_group.web.id]

  tags = merge(
    local.common_tags,
    {
      Name = "${local.instance_name}-eni"
    }
  )
}

# ============================================================================
# 6.4 Elastic IP - Static Public IP Address
# ============================================================================
# Purpose: Allocate a static public IP for the EC2 instance
# Type: aws_eip resource
# Why: Ensures consistent IP for DNS records and allowlisting
# When: For production servers needing stable external IPs
resource "aws_eip" "web" {
  # Domain for EIP: vpc (recommended) or standard (legacy)
  # Type: String
  # Why: VPC is the modern standard; standard is for EC2-Classic
  domain = "vpc"

  # Associate with network interface
  # Type: String (ENI ID)
  # Why: Direct association; alternative to auto-assign via instance
  network_interface = aws_network_interface.web.id

  # Dependency meta-argument
  # Type: List of resource references
  # Why: Explicit dependency; ensures EIP created after VPC Internet Gateway
  depends_on = [data.aws_vpc.default]

  # Lifecycle: prevent accidental deletion
  # Type: Lifecycle block
  # Why: Prevents destruction of static IP (prevent_destroy = true)
  lifecycle {
    prevent_destroy = true
  }

  tags = merge(
    local.common_tags,
    {
      Name = "${local.instance_name}-eip"
    }
  )
}

# ============================================================================
# 6.5 EC2 Instance Resource - Main Compute
# ============================================================================
# Purpose: Create the actual EC2 instance
# Type: aws_instance resource
# Why: Core component for running compute workloads
# When: Whenever you need virtual compute in AWS
# How: Configure with AMI, instance type, networking, and optional provisioners

# Create EC2 instance(s) using count meta-argument
# Type: Resource with count meta-argument
# Why use count: Create multiple identical instances; index with count.index
# When: For fixed number of resources OR variable quantity based on environment
# How: count.index provides 0-based index; reference with count.each_value
resource "aws_instance" "web" {
  # Count meta-argument: create N instances
  # Type: Number or expression evaluating to number
  # Why: Dynamically create multiple instances from single configuration
  # When: Use count for fixed sets; use for_each for maps
  # Note: Prefer for_each when possible for easier targeting
  count = var.instance_count

  # AMI ID - determines OS and base software
  # Type: String (AMI ID)
  # Why: Specifies base image; critical choice for OS, security baseline
  # When: Use data source to find latest; or provide specific ID for reproducibility
  ami = var.ami_id != "" ? var.ami_id : data.aws_ami.amazon_linux[0].id

  # Instance type - determines CPU, memory, storage capacity
  # Type: String (instance type)
  # Why: Affects performance and cost; choose appropriate for workload
  # When: dev=smaller, prod=larger; consider burstable vs guaranteed
  instance_type = local.current_env_config.instance_type

  # Enable/disable monitoring
  # Type: Boolean
  # Why: Detailed monitoring provides more frequent metrics (extra cost)
  # When: Enable for prod; disable for dev to save cost
  monitoring = var.enable_monitoring

  # Disable public IP auto-assignment (we use Elastic IP instead)
  # Type: Boolean
  # Why: Avoid multiple IPs; use static Elastic IP for consistency
  associate_public_ip_address = false

  # Primary network interface configuration
  # Type: Network interface specification
  # Why: Explicitly specify ENI for precise control
  network_interface {
    network_interface_id = aws_network_interface.web.id
    device_index         = 0 # Primary interface
  }

  # Root volume configuration
  # Type: EBS volume configuration
  # Why: Configure storage size, type, encryption for infrastructure needs
  root_block_device {
    volume_type           = "gp3"
    volume_size           = local.current_env_config.volume_size
    encrypted             = true # Always encrypt volumes
    delete_on_termination = true # Delete volume when instance terminates
  }

  # User data script executed on first boot
  # Type: String (shell script)
  # Why: Automate instance initialization (install packages, configure services)
  # When: For initial setup; prefer configuration management tools (Ansible, Chef) for complex setups
  # Note: Use provisioners as last resort
  user_data = base64encode(templatefile("${path.module}/user_data.sh", {
    environment = var.environment
    project     = var.project_name
  }))

  # Metadata options (IMDSv2 for security)
  # Type: Metadata options block
  # Why: IMDSv2 prevents SSRF attacks; requires explicit token for metadata access
  # When: Always use IMDSv2 for security
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2 only
    http_put_response_hop_limit = 1
  }

  # Provisioner for remote command execution (NOT RECOMMENDED)
  # Type: Provisioner block (remote-exec)
  # Why: AVOID - Use user_data or configuration management instead
  # This is an example only; should be avoided in production
  # provisioner "remote-exec" {
  #   inline = ["echo 'Instance provisioned'"]
  # }

  # Lifecycle meta-argument
  # Type: Lifecycle block with multiple attributes
  # Why: Control behavior during create, update, destroy
  # When: Prevent accidental destruction; ignore certain changes
  lifecycle {
    # Ignore changes to these attributes to prevent unnecessary updates
    # Type: List of attribute names
    # Why: Some attributes change outside Terraform (e.g., tags modified in console)
    ignore_changes = [tags["ManagedBy"]] # Ignore this specific tag change

    # Prevent instance from being destroyed
    # Type: Boolean
    # Why: Safety mechanism for production instances
    # When: Use for critical persistent resources
    # prevent_destroy = true # Uncomment for production

    # Create new instance before destroying old one
    # Type: Boolean
    # Why: Avoid downtime during updates; ensures continuity
    create_before_destroy = false
  }

  # Explicit dependency
  # Type: List of resource references
  # Why: Terraform usually infers dependencies; explicit improves clarity and debugging
  # When: Use when implicit dependency isn't obvious
  depends_on = [
    aws_security_group.web,
    aws_network_interface.web
  ]

  # Tags for identification, cost tracking, automation
  # Type: Map of strings
  # Why: AWS best practice; enables filtering and cost allocation
  tags = merge(
    local.common_tags,
    {
      Name = "${local.instance_name}-${count.index + 1}"
    }
  )
}

# ============================================================================
# 6.6 CloudWatch Alarm - Monitoring
# ============================================================================
# Purpose: Monitor EC2 instance and alert on issues
# Type: aws_cloudwatch_metric_alarm resource
# Why: Enables proactive monitoring and alerting
# When: For production workloads requiring uptime
resource "aws_cloudwatch_metric_alarm" "cpu_utilization" {
  # Condition: Only create alarm if we have EC2 instances
  # Type: Conditional expression
  # Why: Alarm not needed if no instances
  count = var.instance_count > 0 ? 1 : 0

  alarm_name          = "${local.instance_name}-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 300 # 5 minutes
  statistic           = "Average"
  threshold           = 80.0

  dimensions = {
    InstanceId = aws_instance.web[0].id
  }

  alarm_description = "Alert when CPU utilization exceeds 80% for 10 minutes"
}

# ============================================================================
# 7. OUTPUT BLOCKS
# ============================================================================
# Purpose: Export values from Terraform for external consumption
# Type: Output declaration
# Why use: Provide key information to operators, other modules, or systems
# When to use: For every value others might need (IPs, IDs, endpoints)
# How to use: Reference with output.<name>; displayed after terraform apply

# Output: EC2 Instance IDs
# Type: Output block with count
# Why: IDs needed to reference instances in other tools/systems
# When: Always export resource IDs for troubleshooting and automation
output "instance_ids" {
  description = "IDs of created EC2 instances"
  value       = aws_instance.web[*].id # [*] splat syntax gets all instances

  # Sensitive marking
  # Type: Boolean
  # Why: Prevents value from showing in logs (doesn't hide from state file)
  sensitive = false
}

# Output: Private IP addresses
# Type: Output block
# Why: Needed for internal communication and documentation
output "private_ips" {
  description = "Private IP addresses of the EC2 instances"
  value       = aws_instance.web[*].private_ip
}

# Output: Elastic IP addresses
# Type: Output block
# Why: Needed for external access and DNS records
output "elastic_ips" {
  description = "Elastic IP addresses assigned to instances"
  value       = aws_eip.web.public_ip
}

# Output: Security group ID
# Type: Output block
# Why: Needed to reference in other configurations (e.g., RDS security groups)
output "security_group_id" {
  description = "Security group ID for the EC2 instances"
  value       = aws_security_group.web.id
}

# Output: AWS Account ID
# Type: Output block (from data source)
# Why: Useful for ARN construction and documentation
output "aws_account_id" {
  description = "AWS account ID"
  value       = data.aws_caller_identity.current.account_id
}

# Output: Connection information for troubleshooting
# Type: Output block with computed value
# Why: Provides SSH command for operators; reduces manual work
# When: Always provide connection strings for compute resources
output "ssh_command" {
  description = "SSH command to connect to the instance"
  value = var.instance_count > 0 ? format(
    "ssh -i <path-to-key> ec2-user@%s",
    aws_eip.web.public_ip
  ) : "No instances created"

  depends_on = [aws_eip.web]
}