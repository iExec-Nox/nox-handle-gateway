FROM rust:1.94.0-alpine3.23 AS builder

# Install build dependency
RUN apk add --no-cache openssl-dev=3.5.5-r0 openssl-libs-static=3.5.5-r0

WORKDIR /app

# Copy manifest and source files
COPY . .

# Build the application
RUN cargo build --release

FROM alpine:3.23 AS runtime

RUN apk upgrade --no-cache

# Set working directory
WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /app/target/release/nox-handle-gateway .

# Run the application
ENTRYPOINT ["/app/nox-handle-gateway"]
