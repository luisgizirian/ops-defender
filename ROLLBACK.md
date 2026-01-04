# Ops Defender - Rollback & Removal Procedures

> **⚠️ CRITICAL OPERATIONS GUIDE:**
> 
> This document contains procedures for:
> - **Rolling back** to a previous version after a failed upgrade
> - **Completely removing** Ops Defender from your system
> 
> These procedures are designed to minimize downtime and service disruption.
> 
> **Test all procedures in staging before attempting in production.**

## Overview

This guide provides fast rollback procedures for Ops Defender when a deployment causes issues in production. It covers two scenarios:

1. **Version Rollback**: Rolling back to a previous working version after an upgrade
2. **Complete Removal**: Uninstalling Ops Defender entirely from your system

Rollback procedures are designed to be:

- **Fast**: Complete in under 2 minutes
- **Safe**: Preserve blocked IP data and request history (when desired)
- **Reliable**: Return to known-good state or clean removal
- **Minimal downtime**: Zero-downtime for most scenarios

## Complete Removal (First-Time Installation Gone Wrong)

If you've installed Ops Defender for the first time and want to completely remove it from your system (e.g., you're disappointed with the results or it doesn't meet your needs), follow these procedures.

### Scenario: Removing Ops Defender Completely

**When to use this:**
- First-time installation didn't meet expectations
- Switching to a different security solution
- Simplifying your infrastructure
- Ops Defender is causing more problems than it solves

**Total time: ~2-3 minutes**

---

### Complete Removal: Systemd Binary Deployment

**Step 1: Disable Nginx Integration**

```bash
# Remove Ops Defender from Nginx configuration
# Option A: If using snippet (recommended during installation)
sudo rm /etc/nginx/snippets/ops-defender.conf

# Option B: If configured inline, edit each server block
sudo nano /etc/nginx/sites-available/your-site.conf
# Remove or comment out these lines:
#   auth_request /ops-auth;
#   auth_request_set $auth_status $upstream_status;
#   location = /ops-auth { ... }

# Test Nginx configuration
sudo nginx -t

# Reload Nginx (zero-downtime)
sudo systemctl reload nginx

# Verify your site works without Ops Defender
curl http://your-domain.com/
```

**Step 2: Stop and Disable Service**

```bash
# Stop the service
sudo systemctl stop ops-defender

# Disable from starting on boot
sudo systemctl disable ops-defender

# Verify stopped
sudo systemctl status ops-defender
# Should show: inactive (dead)
```

**Step 3: Remove Service Files**

```bash
# Remove systemd service file
sudo rm /etc/systemd/system/ops-defender.service

# Reload systemd
sudo systemctl daemon-reload

# Verify service is gone
sudo systemctl status ops-defender
# Should show: Unit ops-defender.service could not be found
```

**Step 4: Remove Binary and Data**

```bash
# Remove the binary
sudo rm /usr/local/bin/ops-defender

# Remove working directory (includes reports)
sudo rm -rf /var/lib/ops-defender

# Remove backup directory (if you created it)
sudo rm -rf /var/backups/ops-defender
```

**Step 5: Clean Up Redis Data (Optional)**

```bash
# If you want to remove blocked IP data from Redis
redis-cli KEYS "blocked:*" | xargs redis-cli DEL
redis-cli KEYS "block_events" | xargs redis-cli DEL

# Or if Redis was only used for Ops Defender, you can flush the database
# WARNING: This removes ALL data in the Redis database
redis-cli FLUSHDB

# If Redis was installed only for Ops Defender and not needed
# sudo systemctl stop redis-server
# sudo systemctl disable redis-server
# sudo apt remove redis-server  # Ubuntu/Debian
```

**Step 6: Verify Complete Removal**

```bash
# Check service is gone
sudo systemctl status ops-defender
# Expected: Unit could not be found

# Check binary is removed
which ops-defender
# Expected: no output

# Check Nginx works
sudo nginx -t
curl http://your-domain.com/
# Expected: Site works normally

# Check no Ops Defender processes
ps aux | grep ops-defender
# Expected: Only grep itself
```

---

### Complete Removal: Docker Deployment

**Step 1: Disable Nginx Integration**

```bash
# Remove Ops Defender from Nginx configuration
sudo rm /etc/nginx/snippets/ops-defender.conf

# Or edit inline configurations
# Remove auth_request directives from server blocks

# Test and reload Nginx
sudo nginx -t
sudo systemctl reload nginx

# Verify site works
curl http://your-domain.com/
```

**Step 2: Stop and Remove Containers**

```bash
# Navigate to Ops Defender directory
cd /path/to/ops-defender

# Stop all services
docker-compose down

# Remove containers, networks, and volumes
docker-compose down -v

# Verify containers are gone
docker ps -a | grep ops
# Expected: no output
```

**Step 3: Remove Images (Optional)**

```bash
# List Ops Defender images
docker images | grep ops-defender

# Remove specific images
docker rmi ops-defender:latest
docker rmi ops-defender:v1.0.0  # any tagged versions

# Or remove all Ops Defender images
docker images | grep ops-defender | awk '{print $3}' | xargs docker rmi

# If you want to remove Redis image too (only if not used elsewhere)
# docker rmi redis:7-alpine
```

**Step 4: Remove Project Files**

```bash
# Remove the project directory
cd ~
rm -rf /path/to/ops-defender

# Or if you want to keep the code but remove data
cd /path/to/ops-defender
rm -rf reports/
docker-compose down -v
```

**Step 5: Clean Up Redis Data (Optional)**

If Redis was running in Docker for Ops Defender only:

```bash
# Redis data is already removed with `docker-compose down -v`
# Verify volumes are gone
docker volume ls | grep ops

# Remove any remaining volumes
docker volume prune
```

**Step 6: Verify Complete Removal**

```bash
# Check no containers
docker ps -a | grep ops
# Expected: no output

# Check no images (if you removed them)
docker images | grep ops-defender
# Expected: no output

# Check Nginx works
sudo nginx -t
curl http://your-domain.com/
# Expected: Site works normally

# Check no volumes
docker volume ls | grep ops
# Expected: no output
```

---

### After Complete Removal

**What happens to your traffic:**
- All requests now go directly to your application
- **No protection against malicious patterns** - your application is fully exposed
- Nginx serves all requests without any auth_request checks
- All previously blocked IPs can now access your application

**Important considerations:**

1. **Security Gap**: You're removing a security layer. Ensure you have alternative protection:
   - WAF (Web Application Firewall)
   - Application-level security
   - Rate limiting
   - Other security tools

2. **Data Cleanup**: Decide if you want to:
   - Keep Redis blocked IP data (for reference)
   - Remove all Ops Defender data
   - Export reports before removal

3. **Monitoring**: Watch your application logs after removal:
   ```bash
   # Monitor application logs
   sudo tail -f /var/log/your-app/app.log
   
   # Monitor Nginx access logs
   sudo tail -f /var/log/nginx/access.log
   
   # Watch for unusual patterns
   sudo tail -f /var/log/nginx/access.log | grep -E '(\.\.\/|union|select|script)'
   ```

4. **Documentation**: Document why you removed Ops Defender:
   - What didn't work
   - What you're using instead
   - Lessons learned

---

## When to Rollback (Version Rollback)

Consider a rollback when:

- ✗ Service fails to start after deployment
- ✗ Health check fails (`/health` endpoint returns errors)
- ✗ Increased error rates in logs
- ✗ Legitimate traffic being blocked unexpectedly
- ✗ Memory or CPU usage spikes abnormally
- ✗ Integration with Nginx breaks
- ✗ Redis connection issues after update

**IMPORTANT:** Always investigate the root cause after rollback to prevent recurring issues.

## Pre-Rollback Validation

Before rolling back, quickly check:

```bash
# 1. Verify the issue (current version)
curl http://localhost:8080/health
sudo systemctl status ops-defender  # or: docker-compose ps

# 2. Check logs for errors
sudo journalctl -u ops-defender -n 50  # or: docker-compose logs --tail=50 ops-defender

# 3. Verify Nginx is still functioning
sudo nginx -t
curl http://your-domain.com/

# 4. Check Redis connectivity (if using Redis)
redis-cli ping
```

## Rollback Procedures by Deployment Method

### Method 1: Binary + Systemd Rollback (Recommended)

**Total time: ~90 seconds**

#### Step 1: Identify Previous Version

```bash
# List recent binaries (if you maintain backups)
ls -lth /var/backups/ops-defender/ | head -5

# Or check systemd journal for last successful start
sudo journalctl -u ops-defender | grep "Starting Ops Defender" | tail -5
```

#### Step 2: Stop Current Service

```bash
# Stop the service (won't affect Redis data)
sudo systemctl stop ops-defender

# Verify stopped
sudo systemctl status ops-defender
```

#### Step 3: Restore Previous Binary

**Option A: From Backup Directory**

```bash
# Identify backup (example: timestamped backups)
ls -lth /var/backups/ops-defender/

# Restore previous version
sudo cp /var/backups/ops-defender/ops-defender-2025-01-15 /usr/local/bin/ops-defender
sudo chmod +x /usr/local/bin/ops-defender
```

**Option B: Rebuild Previous Git Tag**

```bash
# On your build machine
cd /path/to/ops-defender
git checkout v1.2.0  # or specific commit hash

# Build
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o ops-defender

# Copy to server
scp ops-defender azureuser@YOUR-VM-IP:/tmp/

# On server
ssh azureuser@YOUR-VM-IP
sudo mv /tmp/ops-defender /usr/local/bin/
sudo chmod +x /usr/local/bin/ops-defender
```

**Option C: Download Pre-built Release** (if available)

```bash
# Download specific version
wget https://github.com/luisgizirian/ops-defender/releases/download/v1.2.0/ops-defender-linux-amd64

# Install
sudo mv ops-defender-linux-amd64 /usr/local/bin/ops-defender
sudo chmod +x /usr/local/bin/ops-defender
```

#### Step 4: Start Service

```bash
# Start with previous version
sudo systemctl start ops-defender

# Check status immediately
sudo systemctl status ops-defender
```

#### Step 5: Verify Rollback

```bash
# Health check
curl http://localhost:8080/health
# Expected: OK

# Stats check
curl http://localhost:8080/stats | jq '.blocked_ips'
# Should show preserved blocked IPs from Redis

# Test with Nginx
curl -v http://your-domain.com/
# Should work normally

# Monitor logs
sudo journalctl -u ops-defender -f
# Watch for any errors
```

---

### Method 2: Docker Rollback

**Total time: ~60 seconds**

#### Step 1: Identify Previous Image

```bash
# List available images
docker images ops-defender --format "table {{.Repository}}\t{{.Tag}}\t{{.CreatedAt}}"

# Or check docker-compose history
docker-compose ps -a
```

#### Step 2: Stop Current Container

```bash
# Stop and remove current container
docker-compose down ops-defender
# OR
docker stop ops-defender && docker rm ops-defender
```

#### Step 3: Rollback to Previous Image

**Option A: Using Tagged Image**

```bash
# If you tagged the previous working version
docker tag ops-defender:latest ops-defender:backup-$(date +%Y%m%d)  # For current (before rollback)
docker tag ops-defender:v1.2.0 ops-defender:latest

# Restart with previous version
docker-compose up -d ops-defender
```

**Option B: Rebuild from Git Tag**

```bash
cd /path/to/ops-defender
git checkout v1.2.0

# Rebuild
docker-compose build ops-defender

# Start
docker-compose up -d ops-defender
```

**Option C: Pull Pre-built Image** (if using registry)

```bash
# Pull specific version from registry
docker pull your-registry/ops-defender:v1.2.0
docker tag your-registry/ops-defender:v1.2.0 ops-defender:latest

# Restart
docker-compose up -d ops-defender
```

#### Step 4: Verify Rollback

```bash
# Check container status
docker-compose ps ops-defender
# Should show: Up

# Health check
curl http://localhost:8080/health
# Expected: OK

# View logs
docker-compose logs --tail=50 -f ops-defender

# Verify Redis connection
docker-compose exec ops-defender sh -c 'wget -qO- http://localhost:8080/stats' | grep blocked_ips
```

---

### Method 3: Emergency Rollback (Any Method)

**When standard procedures fail - Total time: ~30 seconds**

This is a minimal rollback when you need to restore service ASAP:

```bash
# 1. Stop the broken service immediately
sudo systemctl stop ops-defender
# OR
docker-compose stop ops-defender

# 2. Temporarily disable Ops Defender in Nginx
sudo nano /etc/nginx/snippets/ops-defender.conf

# Comment out auth_request:
# auth_request /ops-auth;
# auth_request_set $auth_status $upstream_status;

# 3. Reload Nginx (zero downtime)
sudo nginx -t && sudo systemctl reload nginx

# 4. Your application is now unprotected but functional
# Use this time to fix Ops Defender or rollback properly
```

**CRITICAL:** This removes protection! Only use as last resort. Restore Ops Defender ASAP.

---

## Redis State Preservation

### Why Redis Data is Safe During Rollback

Ops Defender stores critical data in Redis:
- Blocked IPs with TTL (auto-expire after block duration)
- Block events history (kept for 7 days)
- Request metadata

**Rollback does NOT affect Redis data:**

```
Before rollback: IP blocked → stored in Redis with TTL
Rollback occurs: Binary/container replaced
After rollback:  Previous version reads same Redis data → IP still blocked
```

### Verifying Redis State After Rollback

```bash
# Check blocked IPs in Redis
redis-cli KEYS "blocked:*" | wc -l

# Check specific blocked IP
redis-cli GET "blocked:192.168.1.100"

# Check block events
redis-cli ZRANGE block_events 0 -1

# Verify TTL is still set
redis-cli TTL "blocked:192.168.1.100"
# Should show remaining seconds until expiry
```

### If Redis Data is Corrupted

```bash
# Backup current Redis data
redis-cli SAVE
sudo cp /var/lib/redis/dump.rdb /var/backups/redis-before-rollback-$(date +%Y%m%d_%H%M%S).rdb

# If you have a backup from before deployment:
sudo systemctl stop redis-server
sudo cp /var/backups/redis-YYYYMMDD.rdb /var/lib/redis/dump.rdb
sudo chown redis:redis /var/lib/redis/dump.rdb
sudo systemctl start redis-server
```

---

## Rollback Verification Checklist

After rollback, verify all functionality:

### 1. Service Health

```bash
# Health endpoint
curl http://localhost:8080/health
# Expected: OK

# Stats endpoint
curl http://localhost:8080/stats | jq
# Should return valid JSON

# Report endpoint
curl http://localhost:8080/report | jq
# Should return valid JSON
```

### 2. Nginx Integration

```bash
# Test auth_request endpoint
curl -H "X-Real-IP: 192.168.1.100" \
     -H "X-Original-URI: /test" \
     http://localhost:8080/check
# Expected: 200 OK

# Test blocked IP (if you know one)
curl -H "X-Real-IP: 10.0.0.99" \
     -H "X-Original-URI: /test" \
     http://localhost:8080/check
# Expected: 404 (if IP is blocked)

# Test through Nginx
curl -v http://your-domain.com/
# Expected: Normal response from your app
```

### 3. Functionality Validation

```bash
# Test attack detection (send suspicious requests)
for i in {1..6}; do
  curl -H "X-Real-IP: 192.168.99.99" \
       -H "X-Original-URI: /../../../etc/passwd" \
       http://localhost:8080/check
  sleep 0.2
done

# Should block after threshold
curl -H "X-Real-IP: 192.168.99.99" \
     -H "X-Original-URI: /any" \
     http://localhost:8080/check
# Expected: 404
```

### 4. Performance Check

```bash
# Check memory usage
curl http://localhost:8080/stats | jq '.memory_usage'

# Check response time (should be < 5ms for most requests)
time curl http://localhost:8080/check \
  -H "X-Real-IP: 192.168.1.101" \
  -H "X-Original-URI: /test"
```

### 5. Logs Review

```bash
# Systemd
sudo journalctl -u ops-defender -n 100 | grep -i error

# Docker
docker-compose logs --tail=100 ops-defender | grep -i error

# Should see minimal/no errors
```

---

## Post-Rollback Actions

### 1. Document the Issue

```bash
# Create incident report
cat > /tmp/rollback-incident-$(date +%Y%m%d).txt << EOF
Date: $(date)
Rolled back from: [new version/commit]
Rolled back to: [previous version/commit]
Reason: [brief description]
Impact: [user impact, downtime]
Root cause: [if known]
Prevention: [steps to prevent recurrence]
EOF
```

### 2. Notify Team

If using email notifications:

```bash
# Generate incident report
curl "http://localhost:8080/report?period=1" > /tmp/rollback-report.json

# Email to team with details
# (Use your organization's notification system)
```

### 3. Investigate Root Cause

```bash
# Save logs from failed deployment
sudo journalctl -u ops-defender --since "1 hour ago" > /tmp/failed-deployment-logs.txt

# Or for Docker
docker-compose logs --since 1h ops-defender > /tmp/failed-deployment-logs.txt

# Review changes that caused the issue
git diff v1.2.0 v1.3.0
```

### 4. Plan Re-deployment

Before attempting deployment again:

- [ ] Fix the root cause in code
- [ ] Test thoroughly in staging
- [ ] Run `./test-attacks.sh` to validate
- [ ] Run `./load-test.sh` for performance
- [ ] Document changes in changelog
- [ ] Plan deployment window
- [ ] Ensure rollback procedure is tested

---

## Rollback Testing Procedures

### Test Rollback in Staging

**Before production deployment, test your rollback procedure:**

```bash
# 1. Deploy to staging
# ... deployment steps ...

# 2. Verify working
curl http://staging.example.com/health

# 3. Intentionally rollback to previous version
# ... follow rollback procedures ...

# 4. Verify rollback successful
curl http://staging.example.com/health

# 5. Time the rollback process
# Should complete in < 2 minutes
```

### Rollback Drill

Periodically practice rollback:

```bash
# Schedule quarterly rollback drill
# 1. Deploy current version with a tag
# 2. Deploy a "new" version (can be same, just re-tag)
# 3. Practice rollback procedure
# 4. Measure time and document issues
# 5. Update rollback procedures if needed
```

---

## Best Practices for Preventing Rollback

### 1. Version Tagging Strategy

```bash
# Always tag releases before deployment
git tag -a v1.3.0 -m "Release 1.3.0 - Feature XYZ"
git push origin v1.3.0

# Build from tagged version
git checkout v1.3.0
./build.sh
```

### 2. Binary Backups

**Automate backup of working binaries:**

```bash
# Before deploying new version
sudo cp /usr/local/bin/ops-defender /var/backups/ops-defender/ops-defender-$(date +%Y%m%d_%H%M%S)

# Keep last 5 backups
cd /var/backups/ops-defender/
ls -t | tail -n +6 | xargs rm -f
```

**Add to deployment script:**

```bash
#!/bin/bash
# deploy.sh

# Backup current version
sudo cp /usr/local/bin/ops-defender /var/backups/ops-defender/ops-defender-backup-$(date +%Y%m%d_%H%M%S)

# Deploy new version
sudo systemctl stop ops-defender
sudo cp ops-defender /usr/local/bin/
sudo chmod +x /usr/local/bin/ops-defender
sudo systemctl start ops-defender

# Verify
sleep 2
curl http://localhost:8080/health || {
  echo "Deployment failed! Rolling back..."
  sudo systemctl stop ops-defender
  sudo cp /var/backups/ops-defender/ops-defender-backup-* /usr/local/bin/ops-defender
  sudo systemctl start ops-defender
  exit 1
}
```

### 3. Docker Image Tagging

```bash
# Always tag images before pushing to production
docker build -t ops-defender:v1.3.0 .
docker tag ops-defender:v1.3.0 ops-defender:latest
docker tag ops-defender:v1.3.0 ops-defender:stable  # Keep stable as last known good

# In docker-compose.yml, use specific versions:
services:
  ops-defender:
    image: ops-defender:v1.3.0  # Not :latest
```

### 4. Staging Environment Testing

**Always test in staging before production:**

```bash
# Staging checklist
- [ ] Deploy to staging
- [ ] Run ./test-attacks.sh
- [ ] Run ./load-test.sh
- [ ] Monitor for 24 hours
- [ ] Check memory usage
- [ ] Verify Redis integration
- [ ] Test Nginx integration
- [ ] Review logs for errors
```

### 5. Gradual Rollout (Blue-Green Deployment)

For high-availability setups:

```bash
# Deploy new version alongside old version
# Route 10% of traffic to new version
# Monitor for issues
# If OK, gradually increase to 100%
# If issues, route back to old version (instant rollback)
```

---

## Troubleshooting Rollback Issues

### Service Won't Start After Rollback

**Symptom:** Service fails to start with previous binary

```bash
# Check systemd status
sudo systemctl status ops-defender

# Check logs
sudo journalctl -u ops-defender -n 50

# Common issues:
# 1. Binary permissions
sudo chmod +x /usr/local/bin/ops-defender

# 2. Redis connection changed
redis-cli ping
# Update REDIS_URL in systemd service file if needed

# 3. Port in use
sudo netstat -tlnp | grep 8080
# Kill process using port if needed
```

### Nginx Still Returning Errors

**Symptom:** 502 errors after rollback

```bash
# Check Nginx error log
sudo tail -f /var/log/nginx/error.log

# Check Ops Defender is accessible
curl http://localhost:8080/health

# Test auth_request endpoint
curl -H "X-Real-IP: 192.168.1.1" \
     -H "X-Original-URI: /test" \
     http://localhost:8080/check

# If still failing, temporarily disable auth_request
sudo nano /etc/nginx/snippets/ops-defender.conf
# Comment out: # auth_request /ops-auth;
sudo systemctl reload nginx
```

### Redis Data Lost

**Symptom:** All blocked IPs gone after rollback

```bash
# Check if Redis is running
sudo systemctl status redis-server

# Check Redis data
redis-cli KEYS "blocked:*"

# If empty, restore from backup
sudo systemctl stop redis-server
sudo cp /var/backups/redis-YYYYMMDD.rdb /var/lib/redis/dump.rdb
sudo chown redis:redis /var/lib/redis/dump.rdb
sudo systemctl start redis-server

# Verify
redis-cli KEYS "blocked:*"
```

### Can't Find Previous Version

**Symptom:** No backup binary or Docker image

```bash
# Option 1: Rebuild from Git
git log --oneline | head -20  # Find last working commit
git checkout <commit-hash>
./build.sh

# Option 2: Use in-memory mode temporarily
# Edit systemd service, remove REDIS_URL
sudo systemctl daemon-reload
sudo systemctl restart ops-defender

# Option 3: Download from releases (if available)
wget https://github.com/luisgizirian/ops-defender/releases/download/v1.2.0/ops-defender
```

---

## Quick Reference: Rollback & Removal Commands

### Complete Removal (Systemd)

```bash
# 1. Remove from Nginx
sudo rm /etc/nginx/snippets/ops-defender.conf
sudo nginx -t && sudo systemctl reload nginx

# 2. Stop and remove service
sudo systemctl stop ops-defender
sudo systemctl disable ops-defender
sudo rm /etc/systemd/system/ops-defender.service
sudo systemctl daemon-reload

# 3. Remove files
sudo rm /usr/local/bin/ops-defender
sudo rm -rf /var/lib/ops-defender
sudo rm -rf /var/backups/ops-defender

# 4. Clean Redis (optional)
redis-cli KEYS "blocked:*" | xargs redis-cli DEL
redis-cli KEYS "block_events" | xargs redis-cli DEL
```

### Complete Removal (Docker)

```bash
# 1. Remove from Nginx
sudo rm /etc/nginx/snippets/ops-defender.conf
sudo nginx -t && sudo systemctl reload nginx

# 2. Remove containers and volumes
cd /path/to/ops-defender
docker-compose down -v

# 3. Remove images (optional)
docker rmi ops-defender:latest
docker volume prune

# 4. Remove project (optional)
cd ~ && rm -rf /path/to/ops-defender
```

### Systemd Binary Rollback

```bash
sudo systemctl stop ops-defender
sudo cp /var/backups/ops-defender/ops-defender-YYYYMMDD /usr/local/bin/ops-defender
sudo chmod +x /usr/local/bin/ops-defender
sudo systemctl start ops-defender
curl http://localhost:8080/health
```

### Docker Rollback

```bash
docker-compose down ops-defender
docker tag ops-defender:v1.2.0 ops-defender:latest
docker-compose up -d ops-defender
curl http://localhost:8080/health
```

### Emergency Disable

```bash
sudo nano /etc/nginx/snippets/ops-defender.conf  # Comment out auth_request
sudo systemctl reload nginx
```

---

## Additional Resources

- [DEPLOYMENT.md](DEPLOYMENT.md) - Deployment procedures
- [README.md](README.md) - Feature documentation
- [test-attacks.sh](test-attacks.sh) - Validation testing
- [load-test.sh](load-test.sh) - Performance testing

---

## Support

For rollback assistance or incident reports:
- **GitHub Issues**: https://github.com/luisgizirian/ops-defender/issues
- **Repository**: https://github.com/luisgizirian/ops-defender
- Tag urgent rollback issues with `incident` and `rollback` labels
- Include logs and error messages to help the community assist you

---

**Remember:** Always test rollback procedures in staging before needing them in production!
