# Ops Defender - Production Deployment Guide

> **🤖 EXPERIMENTAL PROJECT - READ BEFORE DEPLOYING:**
> 
> This project was created as an **experiment with GitHub Copilot** as the primary development tool. While it demonstrates promising capabilities, **deploying AI-generated code to production without verification carries significant risks**.
> 
> **CRITICAL PRE-DEPLOYMENT REQUIREMENTS:**
> - ✅ **Security audit by qualified professionals required**
> - ✅ **Extensive testing in staging environments mandatory**
> - ✅ **Code review by experienced developers necessary**
> - ✅ **Incident response and rollback plans must be prepared**
> - ✅ **Compliance and legal review recommended**
> 
> **This is experimental software.** Use for learning and testing, not as a production-ready security solution without proper verification.

> **⚠️ SECURITY DISCLAIMER:**
> 
> This document contains production deployment examples and configuration details. Before using in production:
> - **DO NOT** commit this file with real credentials, IP addresses, or infrastructure details
> - Replace all example values (domains, IPs, passwords) with your actual values
> - Keep this documentation private and secure
> - Review and update configurations regularly as your infrastructure evolves
> 
> **VERSION & PLATFORM NOTICE:**
> 
> This guide references specific versions and cloud providers (Ubuntu 18, Azure) as examples only. The deployment approach applies to any Linux distribution and cloud provider. Adjust commands and paths according to your specific:
> - Operating system version (Ubuntu 20/22, Debian, RHEL, etc.)
> - Cloud provider (AWS, GCP, DigitalOcean, on-premises, etc.)
> - Nginx version and configuration layout
> - Redis instance configuration
> 
> Always test in a staging environment before deploying to production.

## Overview

This guide covers deploying Ops Defender on a Linux VM (example: Azure Ubuntu 18).

**Architecture:**
- Linux VM (Azure/AWS/GCP/on-premises)
- **HTTP-based integration** - works with any reverse proxy
- Ops Defender protecting all applications
- Shared blocked IP list across all domains

**Proxy Compatibility:**
Ops Defender's HTTP-based `/check` endpoint integrates with any reverse proxy or API gateway:
- **Nginx** (using `auth_request` directive)
- **Caddy** (using `forward_auth` handler)
- **Traefik** (using `forwardAuth` middleware)
- **HAProxy** (using Lua or external check)
- **Apache** (using `mod_proxy` + `mod_rewrite`)
- **Cloud API Gateways** (AWS API Gateway, Azure Application Gateway, etc.)

This guide focuses on Nginx examples, but the HTTP-based approach works with any proxy. See README.md for integration examples with other proxies.

## Deployment Options

### Recommended: Binary + Systemd (No Docker)

**Advantages:**
- ✓ No Docker overhead
- ✓ Native systemd integration
- ✓ Better resource control
- ✓ Simpler for VM deployments
- ✓ Easier updates and monitoring

**When to use:** Production VMs, traditional server setups

### Alternative: Docker

**Advantages:**
- ✓ Isolated environment
- ✓ Includes Redis automatically
- ✓ Easier local development

**When to use:** Containerized infrastructure, development/testing

---

## Method 1: Binary + Systemd Deployment (Recommended)

### Step 1: Build the Binary

On your development machine or directly on the VM:

```bash
# Navigate to project
cd /path/to/ops-defender

# Build for Linux (cross-compile if building on Mac/Windows)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o ops-defender

# Verify binary
file ops-defender
# Should show: ops-defender: ELF 64-bit LSB executable, x86-64
```

### Step 2: Deploy to Azure VM

```bash
# Copy binary to VM
scp ops-defender azureuser@YOUR-VM-IP:/tmp/

# SSH into VM
ssh azureuser@YOUR-VM-IP

# Move to system location
sudo mv /tmp/ops-defender /usr/local/bin/
sudo chmod +x /usr/local/bin/ops-defender

# Test binary
/usr/local/bin/ops-defender --help
```

### Step 3: Connect to Existing Redis Instance

**If you already have a Redis instance** (e.g., Azure Redis Cache, AWS ElastiCache, managed Redis):

```bash
# Test connection to your existing Redis instance
# Replace with your actual Redis connection details
redis-cli -h your-redis-instance.redis.cache.windows.net \
          -p 6380 \
          -a "YOUR_ACCESS_KEY" \
          --tls \
          ping
# Should return: PONG

# Note your connection string format for later:
# Azure Redis: rediss://:<access-key>@<instance-name>.redis.cache.windows.net:6380/0
# AWS ElastiCache: redis://<endpoint>:6379/0
# Standard Redis: redis://localhost:6379/0
```

**Connection string examples:**

```bash
# Azure Redis Cache (SSL enabled)
REDIS_URL="rediss://:YOUR_ACCESS_KEY@your-instance.redis.cache.windows.net:6380/0"

# AWS ElastiCache
REDIS_URL="redis://your-cluster.cache.amazonaws.com:6379/0"

# Self-hosted with authentication
REDIS_URL="redis://:password@redis-server.internal:6379/0"

# Local development (no auth)
REDIS_URL="redis://localhost:6379/0"
```

**If you need to install Redis locally** (development/testing only):

```bash
# Update package list
sudo apt update

# Install Redis
sudo apt install redis-server -y

# Configure Redis to start on boot
sudo systemctl enable redis-server
sudo systemctl start redis-server

# Verify Redis is running
redis-cli ping
# Should return: PONG
```

**Security Note:** Never include real access keys in configuration files. Use environment variables or secrets management.

### Step 4: Create Working Directory

```bash
# Create directory for reports and data
sudo mkdir -p /var/lib/ops-defender/reports

# Set ownership to www-data (Nginx user)
sudo chown -R www-data:www-data /var/lib/ops-defender

# Verify permissions
ls -la /var/lib/ | grep ops-defender
```

### Step 5: Create Systemd Service

```bash
# Create service file
sudo nano /etc/systemd/system/ops-defender.service
```

**Paste this configuration:**

```ini
[Unit]
Description=Ops Defender HTTP Request Monitor
Documentation=https://github.com/luisgizirian/ops-defender
After=network.target redis.service
Requires=network.target

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=/var/lib/ops-defender

# Environment configuration
Environment="PORT=8080"
Environment="ANALYSIS_THRESHOLD=5"
Environment="BLOCK_DURATION=1440"
Environment="MAX_TRACKED_IPS=10000"

# Redis connection - REPLACE WITH YOUR ACTUAL REDIS URL
# Examples:
#   Azure Redis: rediss://:ACCESS_KEY@instance.redis.cache.windows.net:6380/0
#   AWS ElastiCache: redis://endpoint.cache.amazonaws.com:6379/0
#   Local: redis://localhost:6379/0
Environment="REDIS_URL=rediss://:YOUR_ACCESS_KEY@your-redis.redis.cache.windows.net:6380/0"

# Optional: Email reporting
# Environment="EMAIL_ENABLED=false"
# Environment="EMAIL_TO=ops@example.com"
# Environment="EMAIL_FROM=defender@example.com"
# Environment="SMTP_HOST=smtp.gmail.com"
# Environment="SMTP_PORT=587"
# Environment="SMTP_USER=your-email@gmail.com"
# Environment="SMTP_PASSWORD=your-app-password"

ExecStart=/usr/local/bin/ops-defender
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/ops-defender

# Resource limits
LimitNOFILE=65536
LimitNPROC=512

[Install]
WantedBy=multi-user.target
```

**Configuration Options Explained:**

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | Service port (ensure firewall allows localhost access) |
| `ANALYSIS_THRESHOLD` | `5` | Requests before analysis (lower = faster blocking) |
| `BLOCK_DURATION` | `1440` | Block duration in minutes (1440 = 24 hours) |
| `MAX_TRACKED_IPS` | `10000` | Memory limit protection (~5MB at 10k IPs) |
| `REDIS_URL` | - | Redis connection string |

### Step 6: Start and Enable Service

```bash
# Reload systemd to recognize new service
sudo systemctl daemon-reload

# Enable service to start on boot
sudo systemctl enable ops-defender

# Start service
sudo systemctl start ops-defender

# Check status
sudo systemctl status ops-defender

# Should show: Active: active (running)
```

### Step 7: Verify Service is Running

```bash
# Check logs
sudo journalctl -u ops-defender -f

# Test health endpoint
curl http://localhost:8080/health
# Should return: OK

# Check stats
curl http://localhost:8080/stats
# Should return JSON with stats

# Test check endpoint
curl -H "X-Real-IP: 192.168.1.100" \
     -H "X-Original-URI: /test" \
     http://localhost:8080/check
# Should return: 200 OK
```

---

## Proxy Integration

### HTTP-Based Integration Approach

Ops Defender uses a simple HTTP API pattern that works with any reverse proxy:

1. **Proxy forwards request** to Ops Defender `/check` endpoint
2. **Required headers:** `X-Real-IP` (client IP), `X-Original-URI` (requested path)
3. **Response codes:**
   - `200 OK` = Allow request (proxy continues to backend)
   - `404 Not Found` = Block request (proxy returns 404 to client)

This section focuses on **Nginx integration examples**. For other proxies (Caddy, Traefik, HAProxy, Apache), see the **Proxy Integration** section in [README.md](README.md) for configuration examples.

## Nginx Integration for Multi-Tenant Setup

### Option A: Shared Snippet (Recommended for Multiple Tenants)

**1. Create shared configuration snippet:**

```bash
sudo nano /etc/nginx/snippets/ops-defender.conf
```

**Paste this content:**

```nginx
# Ops Defender Integration
# Include this in each server block to enable protection

auth_request /ops-auth;
auth_request_set $auth_status $upstream_status;

location = /ops-auth {
    internal;
    proxy_pass http://127.0.0.1:8080/check;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Original-URI $request_uri;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header Host $host;
}
```

**2. Include snippet in each tenant's server block:**

```bash
# Edit tenant configuration
sudo nano /etc/nginx/sites-available/tenant1.example.com
```

**Modify to include snippet:**

```nginx
server {
    listen 80;
    server_name tenant1.example.com;

    # Enable Ops Defender protection
    include snippets/ops-defender.conf;

    # Your existing location blocks
    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # Additional locations...
}
```

**Repeat for all tenant server blocks:**

```bash
# tenant2.example.com
sudo nano /etc/nginx/sites-available/tenant2.example.com
# Add: include snippets/ops-defender.conf;

# tenant3.example.com
sudo nano /etc/nginx/sites-available/tenant3.example.com
# Add: include snippets/ops-defender.conf;
```

### Option B: Inline Configuration (Single Tenant)

If you only have one or two tenants, you can configure directly:

```nginx
server {
    listen 80;
    server_name example.com www.example.com;

    # Ops Defender auth check
    auth_request /ops-auth;
    auth_request_set $auth_status $upstream_status;
    
    location = /ops-auth {
        internal;
        proxy_pass http://127.0.0.1:8080/check;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Host $host;
    }

    # Your application
    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### Step 8: Test and Reload Nginx

```bash
# Test configuration syntax
sudo nginx -t
# Should show: syntax is ok

# Reload Nginx (zero-downtime)
sudo systemctl reload nginx

# Check Nginx status
sudo systemctl status nginx

# Monitor Nginx error logs
sudo tail -f /var/log/nginx/error.log
```

---

## Testing the Deployment

### 1. Test Legitimate Traffic

```bash
# From another machine or using curl
curl -v http://tenant1.example.com/

# Should work normally (200 OK from your app)
```

### 2. Test Attack Detection

```bash
# Send suspicious requests (from external machine)
# Path traversal
curl http://tenant1.example.com/../../../etc/passwd

# SQL injection  
curl "http://tenant1.example.com/api/users?id=1' OR '1'='1"

# WordPress exploit
curl http://tenant1.example.com/wp-admin/

# Repeat 5+ times to trigger analysis threshold
for i in {1..6}; do
  curl http://tenant1.example.com/../../../etc/passwd
  sleep 0.5
done

# After threshold, should return 404
```

### 3. Monitor Ops Defender

```bash
# Watch live logs
sudo journalctl -u ops-defender -f

# Check which IPs are blocked
curl http://localhost:8080/stats | jq '.top_ips[] | select(.blocked == true)'

# Generate report
curl http://localhost:8080/report?period=24 | jq
```

### 4. Check Nginx Access Logs

```bash
# Should see 404 responses for blocked IPs
sudo tail -f /var/log/nginx/access.log | grep 404
```

---

## Method 2: Docker Deployment

### Step 1: Install Docker

```bash
# Update packages
sudo apt update

# Install Docker
sudo apt install docker.io docker-compose -y

# Start and enable Docker
sudo systemctl enable docker
sudo systemctl start docker

# Add your user to docker group (optional)
sudo usermod -aG docker $USER
# Log out and back in for group changes to take effect
```

### Step 2: Deploy with Docker Compose

```bash
# Clone repository or copy files
cd /home/azureuser
git clone https://github.com/luisgizirian/ops-defender.git
cd ops-defender

# Start services (includes Redis automatically)
sudo docker-compose up -d

# Check logs
sudo docker-compose logs -f ops-defender

# Check status
sudo docker-compose ps
```

### Step 3: Configure Nginx

Use the same Nginx configuration as Method 1 (snippets approach).

**Note:** Ops Defender will be running on `localhost:8080` regardless of deployment method.

---

## Multi-Tenant Considerations

### Shared Protection

- **All tenants protected:** Single Ops Defender instance protects all domains
- **Shared block list:** Attack on `tenant1.com` blocks IP across all tenants
- **Centralized monitoring:** One stats/report endpoint for all traffic

### Benefits

1. **Resource efficient:** One service protects unlimited tenants
2. **Consistent security:** Same rules applied across all domains
3. **Simplified management:** Single point of configuration

### Scaling Across Multiple VMs

If you have multiple Azure VMs:

**All VMs point to shared Redis instance:**

```bash
# All instances use the same managed Redis (e.g., Azure Redis Cache)
# This ensures shared state across all VMs
REDIS_URL=rediss://:ACCESS_KEY@your-redis.redis.cache.windows.net:6380/0

# Benefits of managed Redis:
# - High availability and automatic failover
# - No need to manage Redis infrastructure
# - Built-in security (SSL/TLS, firewall rules)
# - Automatic backups
# - Low latency when in same datacenter/region
```

**Network Security:**

```bash
# Ensure your Redis instance firewall allows connections from your VMs
# Azure Redis: Add VM subnet/IPs to firewall rules in Azure Portal
# AWS ElastiCache: Configure security groups
# Self-hosted: Configure firewall rules for private network only
```

**Shared state ensures:**
- IP blocked on VM 1 is blocked on VM 2
- Reports show combined data from all VMs

---

## Monitoring & Maintenance

### View Logs

```bash
# Systemd deployment
sudo journalctl -u ops-defender -f
sudo journalctl -u ops-defender --since "1 hour ago"
sudo journalctl -u ops-defender -n 100

# Docker deployment
sudo docker-compose logs -f ops-defender
sudo docker-compose logs --tail=100 ops-defender
```

### Check Statistics

```bash
# Current stats
curl http://localhost:8080/stats | jq

# Specific fields
curl http://localhost:8080/stats | jq '.memory_usage'
curl http://localhost:8080/stats | jq '.blocked_ips'
```

### Generate Reports

```bash
# Daily report (last 24 hours)
curl http://localhost:8080/report | jq

# Weekly report (last 7 days)
curl http://localhost:8080/report?period=168 | jq

# Custom period (last 48 hours)
curl http://localhost:8080/report?period=48 | jq

# Save report to file
curl http://localhost:8080/report > /tmp/defender-report-$(date +%Y%m%d).json
```

### Service Management

```bash
# Systemd
sudo systemctl status ops-defender
sudo systemctl restart ops-defender
sudo systemctl stop ops-defender
sudo systemctl start ops-defender

# Docker
sudo docker-compose ps
sudo docker-compose restart ops-defender
sudo docker-compose stop
sudo docker-compose up -d
```

### Update Ops Defender

> **⚠️ IMPORTANT:** Before updating in production:
> 1. Test the new version in staging
> 2. Create a backup of the current binary/image
> 3. Review [ROLLBACK.md](ROLLBACK.md) for fast rollback procedures if needed
> 4. Have rollback plan ready before deployment

**Systemd deployment:**

```bash
# On development machine: build new binary
./build.sh

# Copy to VM
scp ops-defender azureuser@YOUR-VM-IP:/tmp/

# On VM: backup current version and deploy
ssh azureuser@YOUR-VM-IP

# IMPORTANT: Backup current binary before updating
sudo cp /usr/local/bin/ops-defender /var/backups/ops-defender/ops-defender-$(date +%Y%m%d_%H%M%S)

# Replace binary
sudo systemctl stop ops-defender
sudo mv /tmp/ops-defender /usr/local/bin/
sudo chmod +x /usr/local/bin/ops-defender
sudo systemctl start ops-defender

# Verify deployment
sudo systemctl status ops-defender
curl http://localhost:8080/health

# If deployment fails, see ROLLBACK.md for fast rollback procedures
```

**Docker deployment:**

```bash
# On VM
cd /home/azureuser/ops-defender

# IMPORTANT: Tag current image as backup before updating
docker tag ops-defender:latest ops-defender:backup-$(date +%Y%m%d)

# Update
git pull origin main
sudo docker-compose down
sudo docker-compose build
sudo docker-compose up -d

# Verify deployment
docker-compose ps
curl http://localhost:8080/health

# If deployment fails, see ROLLBACK.md for fast rollback procedures
```

### Backup and Restore

> **Critical for Fast Rollback:** Maintain regular backups to enable fast rollback procedures.
> See [ROLLBACK.md](ROLLBACK.md) for complete rollback procedures.

**Ops Defender Binary Backups (Systemd deployment):**

```bash
# Create backup directory
sudo mkdir -p /var/backups/ops-defender

# Manual backup before deployment
sudo cp /usr/local/bin/ops-defender /var/backups/ops-defender/ops-defender-$(date +%Y%m%d_%H%M%S)

# Automated daily backup (add to crontab)
0 1 * * * [ -f /usr/local/bin/ops-defender ] && cp /usr/local/bin/ops-defender /var/backups/ops-defender/ops-defender-$(date +\%Y\%m\%d)

# Keep only last 7 backups (cleanup old ones)
find /var/backups/ops-defender/ -name "ops-defender-*" -mtime +7 -delete
```

**Docker Image Backups:**

```bash
# Before updating, always tag current working version
docker tag ops-defender:latest ops-defender:stable
docker tag ops-defender:latest ops-defender:backup-$(date +%Y%m%d)

# List available images for rollback
docker images ops-defender

# Save image to tar for external backup (optional)
docker save ops-defender:stable | gzip > /backup/ops-defender-$(date +%Y%m%d).tar.gz
```

**Redis data backup:**

```bash
# Manual backup
redis-cli save
sudo cp /var/lib/redis/dump.rdb /backup/redis-$(date +%Y%m%d).rdb

# Automated daily backup (add to crontab)
0 2 * * * redis-cli save && cp /var/lib/redis/dump.rdb /backup/redis-$(date +\%Y\%m\%d).rdb

# Keep only last 30 days of Redis backups
find /backup/ -name "redis-*.rdb" -mtime +30 -delete
```

**Report backups:**

```bash
# Reports are in /var/lib/ops-defender/reports/
sudo tar -czf /backup/ops-reports-$(date +%Y%m%d).tar.gz \
  /var/lib/ops-defender/reports/
```

**Restore from Backup (for rollback):**

See [ROLLBACK.md](ROLLBACK.md) for detailed rollback procedures including:
- Fast binary rollback (< 90 seconds)
- Fast Docker rollback (< 60 seconds)
- Emergency rollback procedures
- Redis state preservation
- Rollback verification steps

---

## Troubleshooting

### Ops Defender Not Starting

**Check logs:**
```bash
sudo journalctl -u ops-defender -n 50
```

**Common issues:**

1. **Port already in use:**
   ```bash
   # Check what's using port 8080
   sudo netstat -tlnp | grep 8080
   
   # Change port in systemd service file
   sudo nano /etc/systemd/system/ops-defender.service
   # Change Environment="PORT=8080" to PORT=8081
   sudo systemctl daemon-reload
   sudo systemctl restart ops-defender
   ```

2. **Redis connection failed:**
   ```bash
   # Check Redis is running
   sudo systemctl status redis-server
   redis-cli ping
   
   # Check Redis URL in service file
   sudo nano /etc/systemd/system/ops-defender.service
   ```

3. **Permission denied on /var/lib/ops-defender:**
   ```bash
   sudo chown -R www-data:www-data /var/lib/ops-defender
   sudo chmod 755 /var/lib/ops-defender
   ```

### Nginx Returns 500 Error

**Check Nginx error log:**
```bash
sudo tail -f /var/log/nginx/error.log
```

**Common issues:**

1. **Ops Defender not running:**
   ```bash
   sudo systemctl status ops-defender
   curl http://localhost:8080/health
   ```

2. **auth_request syntax error:**
   ```bash
   sudo nginx -t
   # Fix any syntax errors shown
   ```

3. **Proxy timeout:**
   ```nginx
   # Add to Nginx config
   location = /ops-auth {
       # ... existing config
       proxy_connect_timeout 1s;
       proxy_send_timeout 1s;
       proxy_read_timeout 1s;
   }
   ```

### Legitimate Traffic Being Blocked

**Check what triggered the block:**
```bash
curl http://localhost:8080/report | jq '.block_events[] | select(.ip == "x.x.x.x")'
```

**Options:**

1. **Unblock specific IP temporarily:**
   ```bash
   # Connect to Redis
   redis-cli
   > DEL blocked:x.x.x.x
   > exit
   ```

2. **Adjust detection threshold:**
   ```bash
   # Edit systemd service
   sudo nano /etc/systemd/system/ops-defender.service
   # Change ANALYSIS_THRESHOLD from 5 to 10
   sudo systemctl daemon-reload
   sudo systemctl restart ops-defender
   ```

3. **Modify patterns:**
   - Edit `defender.go` to remove overly aggressive patterns
   - Rebuild and redeploy

### High Memory Usage

**Check memory stats:**
```bash
curl http://localhost:8080/stats | jq '.memory_usage'
```

**If usage is high:**

1. **Increase MAX_TRACKED_IPS limit:**
   ```bash
   sudo nano /etc/systemd/system/ops-defender.service
   # Change MAX_TRACKED_IPS to 20000
   sudo systemctl daemon-reload
   sudo systemctl restart ops-defender
   ```

2. **Check dropped IPs:**
   ```bash
   curl http://localhost:8080/stats | jq '.memory_usage.dropped_ips'
   # If high, you're under memory pressure
   ```

---

## Performance Tuning

### For High-Traffic Sites (10k+ req/sec)

**Increase system limits:**

```bash
# Edit systemd service
sudo nano /etc/systemd/system/ops-defender.service
```

```ini
[Service]
# ... existing config
LimitNOFILE=1048576
LimitNPROC=4096
Environment="MAX_TRACKED_IPS=50000"
```

**Configure Redis for high throughput:**

```bash
sudo nano /etc/redis/redis.conf
```

```
maxmemory 1gb
maxmemory-policy allkeys-lru
tcp-backlog 511
timeout 0
tcp-keepalive 300
```

### For Low-Memory VMs (<2GB RAM)

```ini
[Service]
# ... existing config
Environment="MAX_TRACKED_IPS=5000"
Environment="ANALYSIS_THRESHOLD=3"  # Faster analysis
```

---

## Security Hardening

### Restrict Stats/Report Endpoints

Add authentication to stats and reporting endpoints:

```nginx
# In Nginx config
location /stats {
    proxy_pass http://127.0.0.1:8080/stats;
    allow 10.0.0.0/8;  # Only allow from private network
    deny all;
    auth_basic "Ops Defender Stats";
    auth_basic_user_file /etc/nginx/.htpasswd;
}

location /report {
    proxy_pass http://127.0.0.1:8080/report;
    allow 10.0.0.0/8;
    deny all;
    auth_basic "Ops Defender Reports";
    auth_basic_user_file /etc/nginx/.htpasswd;
}
```

### Firewall Configuration

```bash
# Ensure port 8080 is only accessible from localhost
sudo ufw status
sudo ufw deny 8080  # Block external access
# Nginx will still access it via 127.0.0.1
```

---

## Automated Email Reports

Enable email notifications for daily/weekly reports:

```bash
sudo nano /etc/systemd/system/ops-defender.service
```

Add email configuration:

```ini
Environment="EMAIL_ENABLED=true"
Environment="EMAIL_TO=security@example.com,ops@example.com"
Environment="EMAIL_FROM=ops-defender@example.com"
Environment="SMTP_HOST=smtp.gmail.com"
Environment="SMTP_PORT=587"
Environment="SMTP_USER=your-email@gmail.com"
Environment="SMTP_PASSWORD=your-app-password"
```

**For Gmail:**
1. Enable 2FA on your Google account
2. Generate App Password: https://myaccount.google.com/apppasswords
3. Use app password in SMTP_PASSWORD

**Restart service:**
```bash
sudo systemctl daemon-reload
sudo systemctl restart ops-defender
```

---

## Production Checklist

Before going live:

- [ ] Redis installed and running
- [ ] Ops Defender systemd service enabled and started
- [ ] Nginx snippet created and included in all server blocks
- [ ] Nginx configuration tested (`nginx -t`)
- [ ] Test legitimate traffic works normally
- [ ] Test attack detection with malicious patterns
- [ ] Verify blocked IPs return 404
- [ ] Check `/stats` endpoint shows data
- [ ] Review logs for errors
- [ ] Set up monitoring/alerting
- [ ] Configure automated backups (binary + Redis)
- [ ] **Review rollback procedures ([ROLLBACK.md](ROLLBACK.md))**
- [ ] **Test rollback in staging environment**
- [ ] Document any custom configurations
- [ ] Test service survives reboot (`sudo reboot`)

---

## Additional Resources

- [README.md](README.md) - Complete feature documentation
- [ROLLBACK.md](ROLLBACK.md) - **Fast rollback procedures for production**
- [DDOS-DEFENSE.md](DDOS-DEFENSE.md) - DDoS protection analysis
- [nginx.conf.example](nginx.conf.example) - Full Nginx example
- [test-attacks.sh](test-attacks.sh) - Attack detection test suite
- [load-test.sh](load-test.sh) - Performance testing

---

## Support

For deployment issues, questions, or feedback:
- **GitHub Issues**: https://github.com/luisgizirian/ops-defender/issues
- **Repository**: https://github.com/luisgizirian/ops-defender
- Search existing issues first - your question may already be answered
- Tag deployment-related issues with `deployment` label
