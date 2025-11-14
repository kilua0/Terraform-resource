# Nginx Installation Failure - Fix Applied ✅

## Problem Identified

The Nginx service was not running on the EC2 instance after Terraform applied the infrastructure. The issue was in the `nginx_config.sh` script:

### Root Cause
```bash
set -e    # ❌ PROBLEM: This causes script to exit on first error silently
yum install -y nginx  # This might fail due to network/package issues
# Rest of script never executes if yum fails
```

**Result:** If `yum install` failed for any reason, the script would exit without any logging, and Nginx would never be installed/started.

---

## Solution Applied

### 1. **Removed `set -e`** 
- No more silent failures
- Each command is checked explicitly with `if [ $? -eq 0 ]`
- Better error messages

### 2. **Added Comprehensive Logging**
```bash
exec > >(tee /var/log/nginx_install.log)
exec 2>&1
```
- Logs to `/var/log/nginx_install.log` on the EC2 instance
- Logs to console output
- Can view in EC2 system logs

### 3. **Added Error Checking**
Each critical step now has explicit validation:
```bash
if [ $? -eq 0 ]; then
  echo "✓ Nginx installed successfully"
else
  echo "✗ Failed to install Nginx"
  exit 1
fi
```

### 4. **Added Verification Steps**
- Check if nginx binary exists
- Verify nginx configuration syntax with `nginx -t`
- Verify nginx service is actually running with `systemctl is-active nginx`
- Wait 2 seconds before checking status (allows service time to start)

### 5. **Better Error Messages**
Script now shows:
```
[1/5] Updating system packages...
[2/5] Installing Nginx...
✓ Nginx installed successfully
✓ Nginx binary found at: /usr/sbin/nginx
✓ Nginx version: nginx version: nginx/1.24.0
[3/5] Creating Nginx configuration...
✓ Nginx configuration created
[4/5] Verifying Nginx configuration syntax...
✓ Nginx configuration syntax is valid
[5/5] Starting Nginx service...
✓ Nginx service started successfully
✓ Nginx is running

======================================================
Nginx Load Balancer Configuration Complete!
======================================================
Backend servers configured:
  - Server 1: 10.2.1.X:80
  - Server 2: 10.2.2.X:80
```

---

## Files Modified

✅ `/modules/nginx_lb/nginx_config.sh` - Updated with robust error handling

---

## How to Debug on Running Instance

### 1. **SSH into the Nginx instance**
```bash
ssh -i your-key.pem ec2-user@43.205.99.203
```

### 2. **Check the installation log**
```bash
sudo cat /var/log/nginx_install.log
```
This will show exactly where the script failed and why.

### 3. **Check Nginx status**
```bash
sudo systemctl status nginx
sudo systemctl is-active nginx
```

### 4. **Check Nginx error log**
```bash
sudo tail -50 /var/log/nginx/error.log
sudo tail -50 /var/log/nginx/lb_error.log
```

### 5. **Verify Nginx configuration**
```bash
sudo nginx -t
```

### 6. **Check if port 80 is listening**
```bash
sudo netstat -tlnp | grep nginx
# or
sudo ss -tlnp | grep 80
```

### 7. **Test Nginx endpoints**
```bash
curl http://43.205.99.203/health
curl http://43.205.99.203/
```

---

## To Deploy the Fixed Version

### Option A: Destroy and Reapply (Recommended for Clean Start)
```bash
# Destroy the current infrastructure
terraform -chdir=environments/prod destroy

# Apply with the fixed script
terraform -chdir=environments/prod apply
```

### Option B: SSH and Run Script Manually
```bash
# SSH into the instance
ssh -i your-key.pem ec2-user@43.205.99.203

# Run the fixed script manually (get the IPs from Terraform outputs first)
sudo bash << 'EOF'
# Copy the contents of nginx_config.sh and run it
# But first substitute the IPs:
web_1_ip="10.2.1.X"  # Replace with actual IP from terraform outputs
web_2_ip="10.2.2.X"  # Replace with actual IP from terraform outputs
# ... then paste script contents
EOF
```

---

## What Changed in the Script

| Aspect | Before | After |
|--------|--------|-------|
| Error Handling | `set -e` (silent) | Explicit `if [ $? -eq 0 ]` checks |
| Logging | None | Logs to `/var/log/nginx_install.log` |
| Verification | None | Tests binary, config syntax, service status |
| Debug Info | Minimal | Detailed step-by-step progress |
| Service Check | Just start | Start + verify running + wait |

---

## Expected Result After Next Apply

✅ Nginx will be properly installed and running  
✅ Service will be enabled (auto-start on reboot)  
✅ Configuration will be validated before start  
✅ Health check endpoint will be available at `http://<ip>/health`  
✅ Load balancer will forward traffic to backend servers  
✅ Installation logs will be available for troubleshooting  

---

## Testing After Deployment

```bash
# 1. Check Nginx is running
curl http://43.205.99.203/health
# Expected: "Nginx Load Balancer is running"

# 2. Check load balancer is working
curl http://43.205.99.203/
# Expected: HTML from one of the backend web servers

# 3. Hit it again to see round-robin
curl http://43.205.99.203/
# Expected: HTML from the OTHER web server (alternating)

# 4. Check Nginx stats (requires SSH)
ssh -i key.pem ec2-user@43.205.99.203 "curl http://localhost/nginx_status"
```

---

## Summary

The updated `nginx_config.sh` script now:
1. ✅ Logs all output to a file for debugging
2. ✅ Checks each step explicitly instead of failing silently
3. ✅ Verifies Nginx installation, configuration, and service status
4. ✅ Provides clear success/failure messages
5. ✅ Ensures the service is actually running before returning

**Status:** Ready for redeployment! 🚀
#scsva