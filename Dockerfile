# Build stage
FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY go.mod go.sum* ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o ops-defender ./cmd/ops-defender

# Runtime stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /root/

COPY --from=builder /app/ops-defender .

EXPOSE 8080

CMD ["./ops-defender"]
