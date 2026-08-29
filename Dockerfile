# Stage 1: Build stage
FROM golang:1.27-alpine AS builder
RUN apk --no-cache add git gcc musl-dev make
WORKDIR /app

# Copy the source code into the container
COPY . .

# Build the Go application
RUN make

# Stage 2: Final stage
FROM alpine:latest
RUN apk --no-cache add curl

WORKDIR /app
# Copy the built binary from the previous stage
COPY --from=builder /app/dist/aws-sso .

# Set the entrypoint for the container
EXPOSE 4144

# The server listens over HTTPS when an SSL cert/key is configured, so try TLS first and
# fall back to plaintext.  -k is safe here: this only ever talks to the loopback
# interface inside the container.
HEALTHCHECK --interval=1s --timeout=2s --start-period=1s --retries=90 \
  CMD curl -fsk https://localhost:4144/healthcheck || curl -fs http://localhost:4144/healthcheck || exit 1
ENTRYPOINT ["./aws-sso", "ecs", "server", "--docker"]
