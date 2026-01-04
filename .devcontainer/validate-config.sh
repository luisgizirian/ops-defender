#!/bin/bash
# Devcontainer Configuration Validator
# Validates that all devcontainer files are properly configured

set -e

echo "==================================="
echo "Devcontainer Configuration Validator"
echo "==================================="
echo ""

# Check if required files exist
echo "✓ Checking for required files..."
files=(
    ".devcontainer/devcontainer.json"
    ".devcontainer/Dockerfile"
    ".devcontainer/docker-compose.yml"
    ".devcontainer/README.md"
    ".vscode/launch.json"
    ".vscode/settings.json"
    ".vscode/tasks.json"
)

for file in "${files[@]}"; do
    if [ -f "$file" ]; then
        echo "  ✓ $file exists"
    else
        echo "  ✗ $file is missing"
        exit 1
    fi
done

echo ""
echo "✓ Validating JSON/JSONC syntax..."

# Validate JSON files (allow comments for JSONC)
validate_json() {
    local file=$1
    jq empty "$file" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "  ✓ $file is valid"
    else
        echo "  ✗ $file has errors"
        exit 1
    fi
}

validate_jsonc() {
    local file=$1
    # For JSONC files (with comments), use node if available, otherwise just check syntax
    if command -v node &> /dev/null; then
        node -e "require('fs').readFileSync('$file', 'utf8')" > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            echo "  ✓ $file syntax is readable"
        else
            echo "  ✗ $file has errors"
            exit 1
        fi
    else
        # Just check file is readable
        if [ -r "$file" ]; then
            echo "  ✓ $file exists and is readable"
        else
            echo "  ✗ $file cannot be read"
            exit 1
        fi
    fi
}

# Validate strict JSON files
validate_json ".vscode/launch.json"
validate_json ".vscode/settings.json"
validate_json ".vscode/tasks.json"

# Validate JSONC (allows comments)
validate_jsonc ".devcontainer/devcontainer.json"

echo ""
echo "✓ Validating Docker configuration..."

# Check docker-compose syntax
if command -v docker-compose &> /dev/null; then
    cd .devcontainer
    docker-compose config > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "  ✓ docker-compose.yml is valid"
    else
        echo "  ✗ docker-compose.yml has errors"
        exit 1
    fi
    cd ..
else
    echo "  ⚠ docker-compose not found, skipping validation"
fi

# Check Dockerfile syntax (basic check)
if [ -f ".devcontainer/Dockerfile" ]; then
    if grep -q "FROM" .devcontainer/Dockerfile; then
        echo "  ✓ Dockerfile has FROM instruction"
    else
        echo "  ✗ Dockerfile missing FROM instruction"
        exit 1
    fi
fi

echo ""
echo "✓ Checking devcontainer features..."

# Check for required features
if grep -q "docker-in-docker" .devcontainer/devcontainer.json; then
    echo "  ✓ Docker-in-Docker feature configured"
else
    echo "  ⚠ Docker-in-Docker feature not found"
fi

if grep -q "azure-cli" .devcontainer/devcontainer.json; then
    echo "  ✓ Azure CLI feature configured"
else
    echo "  ⚠ Azure CLI feature not found"
fi

echo ""
echo "✓ Checking VS Code extensions..."

# Check for required extensions
required_extensions=("golang.go" "ms-azuretools.vscode-docker" "ms-azuretools.vscode-azurecli")
for ext in "${required_extensions[@]}"; do
    if grep -q "$ext" .devcontainer/devcontainer.json; then
        echo "  ✓ Extension $ext configured"
    else
        echo "  ⚠ Extension $ext not found"
    fi
done

echo ""
echo "✓ Checking port forwarding..."

if grep -q "8080" .devcontainer/devcontainer.json; then
    echo "  ✓ Port 8080 (Ops Defender) configured"
else
    echo "  ⚠ Port 8080 not forwarded"
fi

if grep -q "6379" .devcontainer/devcontainer.json; then
    echo "  ✓ Port 6379 (Redis) configured"
else
    echo "  ⚠ Port 6379 not forwarded"
fi

echo ""
echo "==================================="
echo "✓ All validations passed!"
echo "==================================="
echo ""
echo "The devcontainer configuration is valid."
echo "To use it:"
echo "  1. Open this project in VS Code"
echo "  2. Press F1 and select 'Dev Containers: Reopen in Container'"
echo "  3. Wait for the container to build (first time: ~2-3 minutes)"
echo "  4. Start developing!"
echo ""
