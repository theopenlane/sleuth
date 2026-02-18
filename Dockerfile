# Build stage
FROM golang:1.25 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o /go/bin/sleuth -a -buildvcs=false -tags osusergo .

# Runtime stage
FROM cgr.dev/chainguard/bash:latest

USER 65532:65532

COPY --from=builder /go/bin/sleuth /bin/sleuth
COPY --from=builder /app/config /config
COPY --from=builder /app/specs /specs
COPY --from=builder /app/ui /ui

EXPOSE 8080

ENTRYPOINT ["/bin/sleuth"]
CMD ["serve"]
