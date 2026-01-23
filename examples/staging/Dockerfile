# Build stage
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Copy go module files
COPY go.mod go.sum* ./
RUN go mod download

# Copy entire project (needed for internal package imports)
COPY . .

# Build the staging example
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o ops-defender-staging ./examples/staging

# Runtime stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy binary from builder
COPY --from=builder /app/ops-defender-staging .

# Copy allowlist configuration
COPY --from=builder /app/examples/staging/allowlist.json /etc/ops-defender/allowlist.json

# Set default config path
ENV ALLOWLIST_CONFIG=/etc/ops-defender/allowlist.json

EXPOSE 8080

CMD ["./ops-defender-staging"]
