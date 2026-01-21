FROM rust:1.92.0-alpine3.23 AS builder

WORKDIR /app

# Copy manifest and source files
COPY . .

# Build the application
RUN cargo build --release

FROM alpine:3.23 AS runtime

# Set working directory
WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /app/target/release/nox-handle-gateway .

# Run the application
ENTRYPOINT ["/app/nox-handle-gateway"]
