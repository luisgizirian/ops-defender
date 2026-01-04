# Contributing to Ops Defender

Thank you for your interest in contributing to Ops Defender! This guide will help you get started with development.

## Quick Start with Dev Container (Recommended)

The fastest way to start developing is using the VS Code Dev Container:

### Prerequisites
- [Visual Studio Code](https://code.visualstudio.com/)
- [Docker Desktop](https://www.docker.com/products/docker-desktop)
- [Remote - Containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers)

### Getting Started

```bash
# 1. Clone the repository
git clone https://github.com/luisgizirian/ops-defender.git
cd ops-defender

# 2. Open in VS Code
code .

# 3. Reopen in Container
# Press F1 → "Dev Containers: Reopen in Container"
# Or click "Reopen in Container" when prompted

# 4. Wait for setup (first time: ~2-3 minutes)
# The container will automatically:
# - Install Go 1.25 and all tools
# - Install Azure CLI
# - Set up Docker-in-Docker
# - Start Redis service
# - Install VS Code extensions

# 5. Start developing!
```

## Development Environment

### What's Included

The dev container provides:
- ✅ **Go 1.25** with gopls, delve, golangci-lint
- ✅ **Azure CLI** for cloud deployments
- ✅ **Docker-in-Docker** for container debugging
- ✅ **Redis** service pre-configured and running
- ✅ **VS Code extensions** automatically installed
- ✅ **Persistent volumes** for Go modules, bash history

### Environment Variables

Pre-configured for development:
```bash
REDIS_URL=redis://redis:6379/0
ANALYSIS_THRESHOLD=5
BLOCK_DURATION=60
MAX_TRACKED_IPS=10000
```

## Common Tasks

### Building

```bash
# Using build script
./build.sh

# Or with Go directly
go build -o ops-defender .

# Or use VS Code task: Ctrl+Shift+B → "Build Ops Defender"
```

### Running

```bash
# With Redis (recommended)
./ops-defender

# With memory storage
unset REDIS_URL && ./ops-defender

# Or use VS Code debug: F5 → "Launch Ops Defender"
```

### Testing

```bash
# Run unit tests
go test -v ./...

# Run attack detection tests
./test-attacks.sh

# Run load tests
./load-test.sh

# Or use VS Code tasks:
# - Ctrl+Shift+P → "Tasks: Run Task" → "Run Tests"
# - Ctrl+Shift+P → "Tasks: Run Task" → "Run Attack Tests"
```

### Debugging

#### Debug Go Application

1. Set breakpoints by clicking left of line numbers
2. Press F5 or use Debug panel
3. Select configuration:
   - **Launch Ops Defender**: With Redis
   - **Launch Ops Defender (Memory Storage)**: Without Redis
   - **Debug Tests**: Debug all tests
   - **Debug Current Test**: Debug specific test

#### Debug Docker Containers

```bash
# Inside devcontainer, you have full Docker access:

# View running containers
docker ps

# View logs
docker logs ops-defender-redis-1

# Execute commands in containers
docker exec -it ops-defender-redis-1 redis-cli

# Build and test production image
docker build -t ops-defender:test .
docker run -p 8080:8080 ops-defender:test
```

### Linting

```bash
# Run linter
golangci-lint run

# Auto-format code
go fmt ./...

# Or use VS Code: Save files auto-formats
```

## Project Structure

```
.
├── main.go              # HTTP server, route handlers
├── defender.go          # Core defense logic, three-tier cache
├── storage.go           # Redis + in-memory storage
├── reporter.go          # Report generation
├── defender_test.go     # Unit tests
├── test-attacks.sh      # Attack detection tests
├── load-test.sh         # Load/performance tests
├── .devcontainer/       # Dev container configuration
│   ├── devcontainer.json
│   ├── Dockerfile
│   ├── docker-compose.yml
│   ├── README.md        # Comprehensive devcontainer guide
│   └── validate-config.sh
├── .vscode/             # VS Code configuration
│   ├── launch.json      # Debug configurations
│   ├── settings.json    # Go settings
│   └── tasks.json       # Build/test tasks
└── .github/
    └── copilot-instructions.md  # AI agent instructions
```

## Development Workflow

### 1. Create a Feature Branch

```bash
git checkout -b feature/your-feature-name
```

### 2. Make Changes

- Follow existing code style
- Add/update tests for new functionality
- Update documentation if needed

### 3. Test Your Changes

```bash
# Build
./build.sh

# Run unit tests
go test -v ./...

# Run attack detection tests
./test-attacks.sh

# Test manually
./ops-defender &
curl http://localhost:8080/health
curl http://localhost:8080/stats
```

### 4. Commit and Push

```bash
git add .
git commit -m "feat: your feature description"
git push origin feature/your-feature-name
```

## Code Style Guidelines

### Go Code

- Use `gofmt` for formatting (auto-applied on save in dev container)
- Follow [Effective Go](https://golang.org/doc/effective_go.html)
- Add comments for exported functions
- Use meaningful variable names
- Keep functions small and focused

### Critical Patterns

#### Async Analysis Pattern

**Never** add blocking operations to `CheckRequest()`:

```go
// ❌ WRONG - Blocks request processing
func (d *Defender) CheckRequest(w http.ResponseWriter, r *http.Request) {
    result := d.analyzePattern(ip)  // Blocking!
    if result.suspicious { ... }
}

// ✅ CORRECT - Non-blocking
func (d *Defender) CheckRequest(w http.ResponseWriter, r *http.Request) {
    tracker.RequestLogs = append(tracker.RequestLogs, log)
    w.WriteHeader(http.StatusOK)  // Return immediately
    // Analysis happens in background worker
}
```

#### Memory Safety

Always respect `maxTrackedIPs` limit:

```go
// Check before adding new IP tracker
if currentCount >= d.evictionThreshold && !d.evictionInProgress {
    d.evictionInProgress = true
    go d.evictBulkIPsSync()  // Preemptive bulk eviction
}
```

#### Redis TTL

Always set TTL for blocked IPs:

```go
// ✅ CORRECT - TTL set
rs.client.Set(ctx, key, data, d.blockDuration)

// ❌ WRONG - No TTL, will never expire
rs.client.Set(ctx, key, data, 0)
```

## Adding New Attack Patterns

1. Add regex pattern to `defender.go`:

```go
patterns := []string{
    // ... existing patterns
    `your-new-pattern`,  // Add here with comment explaining what it detects
}
```

2. Add test case to `test-attacks.sh`:

```bash
test_request \
    "Your Attack Name" \
    "192.168.1.XXX" \
    "/your/malicious/uri" \
    "blocked"
```

3. Run tests:

```bash
./test-attacks.sh
```

## Documentation Updates

**MANDATORY:** When making changes, update relevant documentation:

- **README.md**: Feature changes, new configuration options
- **DEPLOYMENT.md**: Deployment process changes
- **DDOS-DEFENSE.md**: Security feature changes
- **.github/copilot-instructions.md**: Architecture or pattern changes
- **Code comments**: Complex logic changes

## Testing Requirements

Before submitting changes:

1. ✅ Unit tests pass: `go test -v ./...`
2. ✅ Attack detection tests pass: `./test-attacks.sh`
3. ✅ Build succeeds: `./build.sh`
4. ✅ Code is formatted: `go fmt ./...`
5. ✅ No new warnings: `golangci-lint run`
6. ✅ Documentation updated
7. ✅ Manual testing completed

## Performance Considerations

- `CheckRequest()` must respond in microseconds
- Use three-tier caching (memory → memory → Redis)
- Minimize Redis calls (cache aggressively)
- Use mutex locks sparingly (hold for minimal time)
- Profile before optimizing: `go test -bench=. -cpuprofile=cpu.prof`

## Debugging Tips

### Enable Verbose Logging

```bash
# Check logs for analysis decisions
docker-compose logs -f ops-defender | grep "suspicious"

# Monitor Redis operations
redis-cli MONITOR
```

### Check Stats

```bash
# View current statistics
curl http://localhost:8080/stats | jq

# Generate report
curl http://localhost:8080/report | jq
```

### Inspect Redis Data

```bash
# Inside devcontainer
redis-cli -h redis

# List blocked IPs
redis> KEYS blocked:*

# View block events
redis> ZRANGE block_events 0 -1 WITHSCORES
```

## Troubleshooting

### Dev Container Won't Start

```bash
# Rebuild without cache
# F1 → "Dev Containers: Rebuild Container Without Cache"

# Check Docker is running
docker ps
```

### Go Tools Not Working

```bash
# Reinstall tools
go install github.com/go-delve/delve/cmd/dlv@latest
go install golang.org/x/tools/gopls@latest
```

### Redis Connection Failed

```bash
# Check Redis is running
docker ps | grep redis

# Restart Redis
docker-compose restart redis

# Test connection
redis-cli -h redis ping
```

### Tests Failing

```bash
# Check if ops-defender is already running
lsof -i :8080
kill <PID>

# Clean and rebuild
./build.sh
go clean -testcache
go test -v ./...
```

## Resources

- **[README.md](../README.md)**: Project overview and features
- **[.devcontainer/README.md](.devcontainer/README.md)**: Dev container guide
- **[DEPLOYMENT.md](../DEPLOYMENT.md)**: Production deployment
- **[DDOS-DEFENSE.md](../DDOS-DEFENSE.md)**: DDoS protection details
- **[Go Documentation](https://golang.org/doc/)**
- **[VS Code Dev Containers](https://code.visualstudio.com/docs/devcontainers/containers)**

## Getting Help

For questions, issues, or discussions:
- **GitHub Issues**: https://github.com/luisgizirian/ops-defender/issues - Best for bug reports and feature requests
- **GitHub Discussions**: Check if available for general questions and ideas
- Review existing issues and PRs before creating new ones
- Check documentation in project files and `.devcontainer/README.md`

## Code of Conduct

- Be respectful and constructive
- Follow best practices
- Write clear commit messages
- Test thoroughly before submitting
- Document your changes

---

**Happy coding! 🚀**
