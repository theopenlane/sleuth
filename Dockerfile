# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o sleuth main.go

# Final stage
FROM alpine:latest

# Install dependencies and nuclei
RUN apk --no-cache add ca-certificates curl git && \
    # Install nuclei
    curl -L "https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.tar.gz" | \
    tar -xzC /usr/local/bin/ nuclei && \
    chmod +x /usr/local/bin/nuclei

WORKDIR /root/

# Copy the binary from builder
COPY --from=builder /app/sleuth .

# Update nuclei templates
RUN nuclei -update-templates -silent || true

# Create non-root user for security
RUN adduser -D -s /bin/sh sleuth && \
    chown sleuth:sleuth ./sleuth

USER sleuth

# Expose port
EXPOSE 8080

# Run the application
CMD ["./sleuth"]