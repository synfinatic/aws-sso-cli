# Stage 1: Build stage
FROM golang:1.21-alpine AS builder
RUN apk --no-cache add git gcc musl-dev make
WORKDIR /app

# Copy the source code into the container
COPY . .

# Build the Go application
RUN make

# Stage 2: Final stage
FROM alpine:latest

WORKDIR /app
# Copy the built binary from the previous stage
COPY --from=builder /app/dist/aws-sso .

# Set the entrypoint for the container
EXPOSE 4144

ENTRYPOINT ["./aws-sso", "ecs", "run", "--docker"]