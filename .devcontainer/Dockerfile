# Use official Go image as base
FROM mcr.microsoft.com/devcontainers/go:1.25-bookworm

# Set the working directory
WORKDIR /workspace

# Install additional tools and dependencies
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends \
    # Common utilities
    git \
    curl \
    wget \
    ca-certificates \
    # Network tools for testing
    netcat-openbsd \
    redis-tools \
    # Build tools
    build-essential \
    # Debugging tools
    gdb \
    # JSON processor for testing
    jq \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Go tools (done in postCreateCommand but keeping here as fallback)
# These are installed per-user in postCreateCommand for better caching
# RUN go install github.com/go-delve/delve/cmd/dlv@latest \
#     && go install golang.org/x/tools/gopls@latest

# Create bash history file
RUN mkdir -p /commandhistory \
    && touch /commandhistory/.bash_history \
    && chown -R vscode:vscode /commandhistory

# Set up bash history persistence
RUN echo "export PROMPT_COMMAND='history -a' && export HISTFILE=/commandhistory/.bash_history" >> /home/vscode/.bashrc

# Create and set permissions for Go directories
RUN mkdir -p /go/pkg/mod /go/bin \
    && chown -R vscode:vscode /go

# Switch to vscode user
USER vscode

# Set Go environment variables
ENV GOPATH=/go
ENV PATH=$GOPATH/bin:$PATH

# Azure CLI and Docker-in-Docker are installed via features in devcontainer.json
