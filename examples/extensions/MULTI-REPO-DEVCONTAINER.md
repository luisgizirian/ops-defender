# Multi-Repository Development with Devcontainer

This guide explains how to develop private extensions alongside the Ops Defender core in a unified VS Code devcontainer environment.

## Overview

The recommended setup uses a **VS Code multi-root workspace** with both repositories (public core + private extensions) sharing a single devcontainer. This provides:

✅ **Unified development environment** - One devcontainer for both repos  
✅ **Seamless Go module integration** - Use `replace` directive for local development  
✅ **Shared tools and dependencies** - Redis, Go tools, debugging, etc.  
✅ **Simplified workflow** - Edit core and extensions simultaneously  

## Architecture

```
workspace-folder/
├── ops-defender/                    # Public core repository
│   ├── .devcontainer/              # Devcontainer config (shared)
│   ├── extension-points/           # Extension interfaces
│   ├── internal/defender/          # Core logic
│   └── go.mod                      # Core module
│
└── ops-defender-extensions/        # Private extensions repository
    ├── patterns/                   # Custom patterns
    ├── rules/                      # Custom blocking rules
    ├── handlers/                   # Pre/post request handlers
    ├── go.mod                      # Extension module (depends on core)
    └── main.go                     # Extension registration
```

## Setup Instructions

### Step 1: Clone Both Repositories

```bash
# Create workspace directory
mkdir ops-defender-workspace
cd ops-defender-workspace

# Clone public core
git clone https://github.com/luisgizirian/ops-defender.git

# Clone your private extensions (replace with your repo)
git clone https://github.com/your-org/ops-defender-extensions.git
```

### Step 2: Create Multi-Root Workspace File

Create `ops-defender.code-workspace` in the workspace root:

```json
{
  "folders": [
    {
      "path": "ops-defender",
      "name": "Ops Defender (Core)"
    },
    {
      "path": "ops-defender-extensions",
      "name": "Private Extensions"
    }
  ],
  "settings": {
    "go.toolsManagement.autoUpdate": true,
    "go.useLanguageServer": true,
    "go.lintTool": "golangci-lint",
    "go.lintOnSave": "workspace",
    "go.buildOnSave": "workspace",
    "terminal.integrated.defaultProfile.linux": "bash",
    "files.watcherExclude": {
      "**/.git/objects/**": true,
      "**/.git/subtree-cache/**": true,
      "**/node_modules/**": true,
      "**/vendor/**": true
    }
  },
  "extensions": {
    "recommendations": [
      "golang.go",
      "ms-azuretools.vscode-docker",
      "ms-vscode-remote.remote-containers"
    ]
  },
  "remoteEnv": {
    "DEVCONTAINER": "true"
  }
}
```

### Step 3: Configure Extension Module for Local Development

In your private `ops-defender-extensions/go.mod`:

```go
module your-org/ops-defender-extensions

go 1.25

require (
    github.com/luisgizirian/ops-defender v0.0.0 // Will be replaced with local path
)

// Replace directive for local development
// Points to core repository in same workspace
replace github.com/luisgizirian/ops-defender => ../ops-defender
```

**Important:** The `replace` directive tells Go to use the local core code instead of fetching from GitHub. This allows you to:
- Edit core interfaces and see changes immediately in extensions
- Test extension compatibility before core changes are merged
- Develop both repositories in parallel

### Step 4: Open Workspace in VS Code

```bash
# Open the workspace file
code ops-defender.code-workspace
```

VS Code will detect the devcontainer configuration from `ops-defender/.devcontainer/` and prompt:

> **"Folder contains a Dev Container configuration file. Reopen folder to develop in a container?"**

Click **"Reopen in Container"**.

### Step 5: Verify Setup

Once the devcontainer builds and opens:

```bash
# Terminal 1 (Core): Navigate to core
cd /workspaces/ops-defender
go mod download
go build ./...

# Terminal 2 (Extensions): Navigate to extensions
cd /workspaces/ops-defender-extensions
go mod download
go build ./...
```

If both build successfully, your multi-repo devcontainer is ready!

## Development Workflow

### Editing Extension Interfaces (Core)

When you need to add new extension points:

1. **Edit interface** in `ops-defender/extension-points/interfaces.go`
2. **Build core** to ensure no syntax errors
3. **Switch to extensions repo** - changes are immediately available via `replace` directive
4. **Implement interface** in your private extension
5. **Test locally** before committing to core

Example:

```bash
# Terminal 1: Edit core interface
cd /workspaces/ops-defender
vim extension-points/interfaces.go
go build ./...

# Terminal 2: Immediately use new interface
cd /workspaces/ops-defender-extensions
vim handlers/my_handler.go  # Implement new interface
go build ./...  # Uses local core code via replace directive
```

### Implementing Private Extensions

1. **Create extension files** in your private repo:

```go
// ops-defender-extensions/handlers/trusted_ips.go
package handlers

import (
    "net"
    "github.com/luisgizirian/ops-defender/extension-points"
)

type TrustedIPHandler struct {
    trustedCIDRs []*net.IPNet
}

func NewTrustedIPHandler(cidrs []string) *TrustedIPHandler {
    // Implementation...
}

func (t *TrustedIPHandler) Handle(ip, uri, userAgent string) extensions.RequestAction {
    // Check if IP is in trusted list
    // Return Terminate to bypass processing
    // Return Continue to proceed normally
}

func (t *TrustedIPHandler) GetName() string {
    return "Trusted IP Bypass"
}

func (t *TrustedIPHandler) GetPriority() int {
    return 100 // High priority
}
```

2. **Register extensions** in your private `main.go`:

```go
// ops-defender-extensions/main.go
package main

import (
    "github.com/luisgizirian/ops-defender/extension-points"
    "github.com/luisgizirian/ops-defender/internal/defender"
    "your-org/ops-defender-extensions/handlers"
    "your-org/ops-defender-extensions/patterns"
)

func main() {
    // Create extension registry
    registry := extensions.NewExtensionRegistry()
    
    // Register your private extensions
    trustedIPs := []string{"10.0.0.0/8", "172.16.0.0/12"}
    registry.RegisterPreRequestHandler(handlers.NewTrustedIPHandler(trustedIPs))
    registry.RegisterPatternProvider(&patterns.InternalAPIPatterns{})
    
    // Create defender with extensions
    d := defender.NewDefender(defender.DefenderOptions{
        ExtensionRegistry: registry,
        // ... other config
    })
    
    // Start server...
}
```

### Running and Testing

#### Option 1: Run Core Without Extensions

```bash
cd /workspaces/ops-defender
./scripts/build.sh
./ops-defender
```

This runs the vanilla core - useful for baseline testing.

#### Option 2: Run With Private Extensions

```bash
cd /workspaces/ops-defender-extensions
go build -o ops-defender-extended
./ops-defender-extended
```

This runs the core with your private extensions loaded.

#### Option 3: Debugging

VS Code debug configurations work across both repositories:

**Launch config for core:**
```json
{
  "name": "Debug Core",
  "type": "go",
  "request": "launch",
  "mode": "debug",
  "program": "${workspaceFolder}/ops-defender/cmd/ops-defender",
  "cwd": "${workspaceFolder}/ops-defender"
}
```

**Launch config for extensions:**
```json
{
  "name": "Debug Extensions",
  "type": "go",
  "request": "launch",
  "mode": "debug",
  "program": "${workspaceFolder}/ops-defender-extensions",
  "cwd": "${workspaceFolder}/ops-defender-extensions"
}
```

## Devcontainer Configuration

The devcontainer from `ops-defender/.devcontainer/` includes:

- **Go 1.25** with full toolchain
- **Redis** service for testing
- **Azure CLI** for cloud deployments
- **Docker-in-Docker** for container debugging
- **VS Code extensions**: Go, Docker, Azure CLI

All tools are available to both repositories automatically.

## Testing Strategy

### Unit Tests

Test extensions independently:

```bash
# Test core
cd /workspaces/ops-defender
go test ./...

# Test extensions
cd /workspaces/ops-defender-extensions
go test ./...
```

### Integration Tests

Test core + extensions together:

```bash
cd /workspaces/ops-defender-extensions

# Start defender with extensions
./ops-defender-extended &

# Run attack tests against extended version
cd /workspaces/ops-defender
./scripts/test-attacks.sh
```

### Load Tests

```bash
cd /workspaces/ops-defender
DURATION=60 RPS=50 ./scripts/load-test.sh
```

## Git Workflow

### Core Changes

When you need to change core interfaces:

```bash
cd /workspaces/ops-defender

# Create feature branch
git checkout -b feature/new-extension-point

# Make changes to extension-points/interfaces.go
vim extension-points/interfaces.go

# Test locally in extensions repo (via replace directive)
cd /workspaces/ops-defender-extensions
go build ./...  # Uses local core code

# If all works, commit core changes
cd /workspaces/ops-defender
git add extension-points/interfaces.go
git commit -m "Add new extension point for X"
git push origin feature/new-extension-point
```

### Extension Changes

Private extension changes stay in your private repo:

```bash
cd /workspaces/ops-defender-extensions

# Create feature branch
git checkout -b feature/add-trusted-ips

# Implement extension
vim handlers/trusted_ips.go

# Test
go build ./...
./ops-defender-extended

# Commit to private repo
git add handlers/trusted_ips.go
git commit -m "Add trusted IP bypass handler"
git push origin feature/add-trusted-ips
```

## Production Deployment

### Remove Replace Directive

Before deploying extensions to production:

1. **Merge core changes** to main branch
2. **Tag core release**: `git tag v1.2.0 && git push --tags`
3. **Update extension go.mod** to use tagged version:

```go
module your-org/ops-defender-extensions

go 1.25

require (
    github.com/luisgizirian/ops-defender v1.2.0  // Use tagged version
)

// Remove or comment out replace directive for production
// replace github.com/luisgizirian/ops-defender => ../ops-defender
```

4. **Build production binary**:

```bash
cd ops-defender-extensions
go build -o ops-defender-production
```

### Deployment Options

**Option 1: Docker**

```dockerfile
FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o ops-defender-extended

FROM alpine:latest
COPY --from=builder /app/ops-defender-extended /usr/local/bin/
CMD ["ops-defender-extended"]
```

**Option 2: Binary Deployment**

```bash
# Build for target platform
GOOS=linux GOARCH=amd64 go build -o ops-defender-linux-amd64

# Deploy to server
scp ops-defender-linux-amd64 user@server:/opt/ops-defender/
```

## Troubleshooting

### Issue: Extensions Not Loading

**Symptom:** Extensions registered but not being called

**Check:**
1. `extensionRegistry` passed to `NewDefender()` in main.go
2. Extensions actually registered before passing registry
3. No nil pointer errors in logs

### Issue: "Cannot Find Package"

**Symptom:** `go build` fails with import errors

**Solution:**
```bash
# Ensure replace directive is present
cat go.mod | grep replace

# Should show:
# replace github.com/luisgizirian/ops-defender => ../ops-defender

# If missing, add it:
go mod edit -replace github.com/luisgizirian/ops-defender=../ops-defender
```

### Issue: Devcontainer Won't Start

**Symptom:** VS Code fails to build container

**Check:**
1. Docker daemon is running
2. `ops-defender/.devcontainer/devcontainer.json` exists
3. Workspace file paths are correct (relative to workspace root)

### Issue: Redis Connection Errors

**Symptom:** "Failed to connect to Redis" in logs

**Solution:**
```bash
# Check if Redis is running in devcontainer
docker ps | grep redis

# If not, start it:
cd /workspaces/ops-defender
docker-compose up -d redis
```

## Best Practices

1. **Always use replace directive** in development - keeps extensions in sync with core
2. **Test without extensions first** - ensures core changes don't break vanilla behavior
3. **Use separate Git branches** - feature branches for both core and extensions
4. **Version core interfaces carefully** - breaking changes require major version bump
5. **Document private extensions** - even private repos need good docs
6. **Monitor performance** - extension handlers add latency, measure impact

## Example: Complete Setup

Here's a complete example of setting up and using the multi-repo devcontainer:

```bash
# 1. Create workspace
mkdir ~/ops-defender-workspace
cd ~/ops-defender-workspace

# 2. Clone repositories
git clone https://github.com/luisgizirian/ops-defender.git
git clone https://github.com/your-org/ops-defender-extensions.git

# 3. Create workspace file
cat > ops-defender.code-workspace <<EOF
{
  "folders": [
    {"path": "ops-defender", "name": "Core"},
    {"path": "ops-defender-extensions", "name": "Extensions"}
  ]
}
EOF

# 4. Open in VS Code
code ops-defender.code-workspace

# 5. Reopen in container when prompted

# 6. After container builds, test both repos
cd /workspaces/ops-defender
go build ./...

cd /workspaces/ops-defender-extensions
go mod edit -replace github.com/luisgizirian/ops-defender=../ops-defender
go build ./...
```

## Summary

The multi-repo devcontainer setup provides:

✅ **Unified environment** - One devcontainer for core + extensions  
✅ **Local testing** - Test interface changes before merging  
✅ **Flexible deployment** - Use replace for dev, tags for prod  
✅ **Clean separation** - Public core, private extensions  
✅ **Full tooling** - Debugging, testing, linting all work  

This approach follows the **Open Core + Private Extension** architecture while maintaining excellent developer experience.

For questions or issues, see the main [EXTENSIBILITY.md](../../EXTENSIBILITY.md) documentation.
