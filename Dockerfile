# Build stage
FROM golang:1.25-alpine AS builder

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
ARG TARGETARCH
RUN set -eux; \
    apk --no-cache add ca-certificates curl git unzip; \
    arch="${TARGETARCH:-$(uname -m)}"; \
    case "${arch}" in \
        amd64|x86_64) nuclei_arch=amd64 ;; \
        arm64|aarch64) nuclei_arch=arm64 ;; \
        *) echo "Unsupported architecture: ${arch}" >&2; exit 1 ;; \
    esac; \
    nuclei_tag="$(curl -fsSL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep -m 1 '\"tag_name\"' | sed -E 's/.*\"([^\"]+)\".*/\1/')"; \
    [ -n "${nuclei_tag}" ] || { echo 'Failed to determine latest nuclei tag' >&2; exit 1; }; \
    nuclei_version="${nuclei_tag#v}"; \
    curl -fsSLo /tmp/nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/${nuclei_tag}/nuclei_${nuclei_version}_linux_${nuclei_arch}.zip"; \
    unzip -jo /tmp/nuclei.zip nuclei -d /usr/local/bin/; \
    chmod +x /usr/local/bin/nuclei; \
    rm /tmp/nuclei.zip

WORKDIR /app

# Create non-root user for security first
RUN adduser -D -s /bin/sh sleuth && \
    mkdir -p data/intel

# Copy the binary from builder
COPY --from=builder /app/sleuth .
COPY --from=builder /app/ui ./ui
COPY --from=builder /app/config ./config

RUN chown -R sleuth:sleuth /app

# Switch to sleuth user before updating templates
USER sleuth

# Update nuclei templates as sleuth user
RUN nuclei -update-templates -silent || true

# Expose port
EXPOSE 8080

# Run the application
CMD ["./sleuth"]
