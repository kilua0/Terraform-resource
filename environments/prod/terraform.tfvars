// NOTE: Values for the `prod` environment were consolidated into `variables.tf` as defaults.
// Keeping this file as documentation. To use custom values, either edit `variables.tf`
// or create a separate -var-file and pass it with `-var-file=...` when running Terraform.

// Load Balancer Configuration
// Options: "nginx" (currently active) or "alb" (for future use)
load_balancer_type = "nginx"

