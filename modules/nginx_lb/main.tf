# ============================================================================
# NGINX LOAD BALANCER MODULE
# ============================================================================
# This module creates an EC2 instance with Nginx configured as a reverse
# proxy/load balancer. It distributes traffic between two backend web servers.
# 
# This is an alternative to AWS ALB for environments with ALB restrictions.
# ============================================================================

resource "aws_instance" "nginx_lb" {
  ami           = var.ami_id
  instance_type = var.instance_type
  subnet_id     = var.public_subnet_id
  key_name      = var.key_name

  vpc_security_group_ids = [var.nginx_security_group_id]

  # Assign public IP to the Nginx LB
  associate_public_ip_address = true

  # User data script to install and configure Nginx
  # IMPORTANT: templatefile() MUST come before base64encode() so variables are substituted first
  user_data = base64encode(
    templatefile("${path.module}/nginx_config.sh", {
      web_1_ip = var.web_1_private_ip
      web_2_ip = var.web_2_private_ip
    })
  )

  tags = {
    Name        = "${var.environment}-nginx-lb"
    Environment = var.environment
    Role        = "LoadBalancer"
  }

  lifecycle {
    create_before_destroy = true
    prevent_destroy = true 
  }
}

# Data source to wait for instance to be running
resource "aws_ec2_instance_state" "nginx_lb" {
  instance_id = aws_instance.nginx_lb.id
  state       = "running"

  depends_on = [aws_instance.nginx_lb]
}
