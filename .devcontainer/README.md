# Development Container Guide

This directory contains the configuration for the VS Code Development Container for Ops Defender.

**Base image:** `mcr.microsoft.com/devcontainers/go:1.25-bookworm` (Go 1.25 on Debian Bookworm)

## What's Included

The devcontainer provides a complete, isolated development environment with:

### Tools & Languages
- **Go 1.25**: Full Go toolchain with modules support
- **Delve (dlv)**: Go debugger for breakpoint debugging
- **gopls v0.21.0**: Go language server for IntelliSense (requires Go 1.25; pinned per [proxy.golang.org listing](https://proxy.golang.org/golang.org/x/tools/gopls/@v/list))
- **golangci-lint**: Comprehensive Go linter

### Cloud & Infrastructure
- **Azure CLI (az)**: Pre-installed and ready for cloud operations
- **Docker-in-Docker**: Full Docker daemon inside the container
- **docker-compose v2**: For orchestrating multi-container applications

### Development Tools
- **Git**: Version control
- **jq**: JSON processor for API testing
- **redis-tools**: Redis CLI for database inspection
- **netcat-openbsd**: Network debugging
- **curl/wget**: HTTP clients

### VS Code Extensions
- **Go**: Full Go language support
- **Docker**: Container management and debugging
- **Azure CLI Tools**: Azure integration
- **YAML**: YAML syntax support
- **Remote Containers**: Container development support

## Quick Start

### 1. Prerequisites

Install on your host machine:
- [Visual Studio Code](https://code.visualstudio.com/)
- [Docker Desktop](https://www.docker.com/products/docker-desktop)
- [Remote - Containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers)

### 2. Open in Container

```bash
# Clone the repository
git clone https://github.com/luisgizirian/ops-defender.git
cd ops-defender

# Open in VS Code
code .

# Reopen in container
# Press F1 → "Dev Containers: Reopen in Container"
# Or click "Reopen in Container" when prompted
```

### 3. Wait for Setup

First time only (~2-3 minutes):
1. Docker builds the container image
2. Container starts with Redis service
3. VS Code extensions install automatically
4. Go tools download (gopls, dlv, etc.)

### 4. Start Developing

The container opens at `/workspace` with your code mounted. Everything is ready:

```bash
# Download Go dependencies
go mod download

# Build the application
./build.sh

# Run with Redis (pre-configured)
./ops-defender
# or with memory storage
unset REDIS_URL && ./ops-defender

# Run tests
go test -v ./...

# Run attack detection tests
./test-attacks.sh

# Load testing
./load-test.sh
```

## Debugging

### Go Application Debugging

#### Method 1: VS Code Debug Panel (Recommended)

1. Open the Debug panel (Ctrl+Shift+D / Cmd+Shift+D)
2. Select a debug configuration:
   - **Launch Ops Defender**: Debug with Redis
   - **Launch Ops Defender (Memory Storage)**: Debug without Redis
   - **Debug Tests**: Debug all tests
   - **Debug Current Test**: Debug specific test
3. Press F5 to start debugging
4. Set breakpoints by clicking left of line numbers

#### Method 2: Command Line Debug

```bash
# Start with debugger
dlv debug -- 

# Or debug tests
dlv test
```

### Docker Container Debugging

The devcontainer includes **Docker-in-Docker** with full debugging capabilities.

#### Inspect Running Containers

```bash
# Inside the devcontainer, you have full Docker access:

# List containers (including from docker-compose.yml)
docker ps -a

# View logs
docker logs ops-defender-ops-defender-1
docker logs ops-defender-redis-1

# Execute commands in containers
docker exec -it ops-defender-redis-1 redis-cli

# Inspect container details
docker inspect ops-defender-ops-defender-1

# View networks
docker network ls
docker network inspect ops-defender_default
```

#### Debug Production Docker Build

```bash
# Build the production Dockerfile
docker build -t ops-defender:debug .

# Run with debug port exposed
docker run -it --rm \
  -p 8080:8080 \
  -p 2345:2345 \
  -e REDIS_URL=redis://redis:6379/0 \
  --network ops-defender_default \
  ops-defender:debug

# In another terminal, attach debugger
dlv connect localhost:2345
```

#### Debug with docker-compose

```bash
# Start services defined in root docker-compose.yml
cd /workspace
docker-compose up -d

# Check service status
docker-compose ps

# View logs
docker-compose logs -f ops-defender

# Execute commands in service containers
docker-compose exec ops-defender sh

# Stop services
docker-compose down
```

#### VS Code Docker Extension

The Docker extension provides GUI debugging:

1. Click Docker icon in sidebar
2. Right-click on containers → "View Logs"
3. Right-click on containers → "Attach Shell"
4. Right-click on images → "Run Interactive"

### Remote Debugging (Attach to Container)

To debug a running container:

1. Start container with Delve:
```bash
# Build with debug symbols
go build -gcflags="all=-N -l" -o ops-defender .

# Run with Delve headless
dlv exec ./ops-defender --headless --listen=:2345 --api-version=2 --accept-multiclient
```

2. In VS Code:
   - Select "Attach to Docker Container" in debug panel
   - Press F5
   - Debugger connects to port 2345

## Environment Variables

The devcontainer pre-configures these environment variables:

```bash
REDIS_URL=redis://redis:6379/0    # Redis connection (via Docker network)
ANALYSIS_THRESHOLD=5               # Request threshold for analysis
BLOCK_DURATION=60                  # Block duration in minutes
MAX_TRACKED_IPS=10000             # Memory limit protection
```

Override in `.vscode/launch.json` or in your terminal:

```bash
BLOCK_DURATION=30 ./ops-defender
```

## Persistence

### What's Persisted
- **Go modules cache**: `/go/pkg/mod` (volume `go-modules`)
- **Bash history**: `/commandhistory/.bash_history` (volume `bash-history`)
- **Redis data**: `/data` (volume `redis-data`)
- **Source code**: `/workspace` (bind mount to host)

### What's NOT Persisted
- Compiled binaries (`ops-defender`)
- Test reports
- Temporary files

This means:
- ✅ Dependencies download once
- ✅ Command history survives container rebuilds
- ✅ Redis data persists between sessions
- ✅ Source changes are immediately reflected on host
- ✅ No pollution of your host system

## Services

### Redis (Included)

Redis runs automatically when you open the devcontainer:

```bash
# Check Redis is running
docker ps | grep redis

# Connect to Redis CLI
redis-cli -h redis

# Test connection
redis-cli -h redis ping
# Returns: PONG

# Inspect blocked IPs
redis-cli -h redis KEYS "blocked:*"

# View block events
redis-cli -h redis ZRANGE block_events 0 -1 WITHSCORES
```

### Port Forwarding

These ports are automatically forwarded to your host:

- **8080**: Ops Defender HTTP API
- **6379**: Redis (for external tools)

Access from host browser/tools:
```bash
# From your host machine (not inside container)
curl http://localhost:8080/health
curl http://localhost:8080/stats

# Redis GUI clients can connect to localhost:6379
```

## Azure CLI

Azure CLI is pre-installed for cloud deployments:

```bash
# Login to Azure
az login

# List subscriptions
az account list --output table

# Set active subscription
az account set --subscription "Your Subscription"

# Deploy to Azure Container Instances
az container create \
  --resource-group your-rg \
  --name ops-defender \
  --image your-registry/ops-defender:latest \
  --cpu 1 --memory 1 \
  --environment-variables \
    REDIS_URL=redis://your-redis:6379/0 \
    BLOCK_DURATION=1440
```

## Troubleshooting

### Container Won't Start

```bash
# Check Docker is running on host
docker ps

# Rebuild container without cache
# F1 → "Dev Containers: Rebuild Container Without Cache"
```

### Go Tools Not Working

```bash
# Reinstall Go tools
go install github.com/go-delve/delve/cmd/dlv@latest
go install golang.org/x/tools/gopls@latest
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
```

### Redis Connection Failed

```bash
# Check Redis is running
docker ps | grep redis

# Restart Redis service
docker-compose restart redis

# Test connection
redis-cli -h redis ping
```

### Port Already in Use

If ports 8080 or 6379 are already in use on your host:

1. Stop conflicting services
2. Or modify `.devcontainer/docker-compose.yml` port mappings:
```yaml
ports:
  - "8081:8080"  # Changed to 8081
```

### Docker-in-Docker Issues

```bash
# Check Docker daemon inside container
docker ps

# If Docker is not running, restart the container
# F1 → "Dev Containers: Rebuild Container"
```

## Customization

### Add More Extensions

Edit `.devcontainer/devcontainer.json`:

```json
"extensions": [
    "golang.go",
    "your-extension-id"
]
```

### Change Go Version

Edit `.devcontainer/Dockerfile` and replace the tag. The current default is `mcr.microsoft.com/devcontainers/go:1.25-bookworm`:

```dockerfile
FROM mcr.microsoft.com/devcontainers/go:1.25-bookworm
```

### Add System Packages

Edit `.devcontainer/Dockerfile`:

```dockerfile
RUN apt-get update && apt-get install -y \
    your-package \
    && rm -rf /var/lib/apt/lists/*
```

### Modify Environment Variables

Edit `.devcontainer/docker-compose.yml`:

```yaml
environment:
  - YOUR_VAR=value
```

## Best Practices

### 1. Keep Host Clean
✅ All development tools run inside the container
✅ No need to install Go, Azure CLI, or Docker tools on host
✅ Only VS Code and Docker Desktop required on host

### 2. Use Redis for Testing
✅ Redis service is always available at `redis:6379`
✅ Pre-configured in `REDIS_URL` environment variable
✅ Test real production scenarios

### 3. Leverage Debugging
✅ Use VS Code debugging instead of print statements
✅ Set breakpoints and inspect variables
✅ Step through code execution

### 4. Persist Important Data
✅ Go modules cache persists (faster rebuilds)
✅ Bash history persists (convenient command recall)
✅ Git commits happen on host (safe)

### 5. Test with Docker
✅ Use docker-compose to test full stack
✅ Debug production Dockerfile issues
✅ Validate Nginx integration locally

## Performance Tips

### Speed Up Container Startup
- Container image is cached after first build
- Go modules cache persists (no re-download)
- Only source changes trigger minimal rebuild

### Reduce Memory Usage
- Stop the devcontainer when not developing
- Prune unused Docker images: `docker system prune`

### Fast Iteration
```bash
# Run without building container
go run .

# Watch mode (install first: go install github.com/cosmtrek/air@latest)
air
```

## FAQ

**Q: Do I need Go installed on my host?**  
A: No! Everything runs inside the container.

**Q: Can I use this on Windows/Mac/Linux?**  
A: Yes! Docker and VS Code work on all platforms.

**Q: Does this work with VS Code on the web (github.dev)?**  
A: No, you need VS Code desktop with Docker.

**Q: Can I use another IDE instead of VS Code?**  
A: The devcontainer is VS Code-specific, but you can still use the Docker setup manually with any IDE.

**Q: Will my changes persist if I close VS Code?**  
A: Yes! Source code is bind-mounted to host. Container state persists until you explicitly remove it.

**Q: Can multiple people use this simultaneously?**  
A: Yes! Each developer gets their own isolated container instance.

**Q: How much disk space does this use?**  
A: ~2GB for the container image, ~100MB for Go modules cache.

## Resources

- [VS Code Dev Containers Documentation](https://code.visualstudio.com/docs/devcontainers/containers)
- [Docker-in-Docker Feature](https://github.com/devcontainers/features/tree/main/src/docker-in-docker)
- [Go Debugging in VS Code](https://github.com/golang/vscode-go/wiki/debugging)
- [Azure CLI Reference](https://docs.microsoft.com/en-us/cli/azure/)

## Support

For issues with the devcontainer setup, please check:
1. Docker Desktop is running
2. VS Code Remote - Containers extension is installed
3. No port conflicts (8080, 6379)
4. Sufficient disk space (~5GB free)

If problems persist, rebuild the container:
- F1 → "Dev Containers: Rebuild Container Without Cache"
