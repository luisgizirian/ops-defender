#!/bin/bash

# Ops Defender Build Script

set -e

# Navigate to project root
cd "$(dirname "$0")/.."

echo "Building Ops Defender..."

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "Error: Go is not installed. Please install Go 1.25 or later."
    echo "Visit: https://go.dev/doc/install"
    exit 1
fi

# Build the binary
echo "Compiling..."
go build -o ops-defender -ldflags="-s -w" ./cmd/ops-defender

echo "Build complete! Binary: ./ops-defender"
echo ""
echo "To run:"
echo "  ./ops-defender"
echo ""
echo "To configure, set environment variables:"
echo "  PORT=8080 ANALYSIS_THRESHOLD=5 BLOCK_DURATION=60 ./ops-defender"
