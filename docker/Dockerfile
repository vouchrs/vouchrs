# Ultra-minimal distroless static Dockerfile
FROM rust:1.82-slim AS builder

# Install required system dependencies for static linking
RUN apt-get update && apt-get install -y \
    libssl-dev \
    musl-dev \
    musl-tools \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Add musl target for static linking
RUN rustup target add x86_64-unknown-linux-musl

# Set working directory
WORKDIR /app

# Copy dependency files first for better caching
COPY Cargo.toml Cargo.lock ./

# Create a dummy main.rs to build dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build dependencies with musl target for static linking
ENV CC_x86_64_unknown_linux_musl=musl-gcc
ENV RUSTFLAGS="-C target-feature=+crt-static"
RUN cargo build --release --target x86_64-unknown-linux-musl --locked
RUN rm src/main.rs

# Copy source code
COPY src ./src
COPY Settings.toml ./

# Build the application with static linking
RUN cargo build --release --target x86_64-unknown-linux-musl --locked

# Runtime stage - distroless static (smallest possible)
FROM gcr.io/distroless/static-debian12:18d48b0eeb51dfb9769b782a97fc868470b7c3c5

# Set working directory for the application
WORKDIR /app

# Copy the statically linked binary
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/vouchrs /app/vouchrs

# Copy static files from builder stage
COPY --from=builder /app/src/static /app/static

# Copy default configuration 
COPY --from=builder /app/Settings.toml /app/Settings.toml

# Use non-root user
USER nonroot:nonroot

# Expose port
EXPOSE 8080

# Set environment variables
ENV STATIC_FOLDER_PATH=/app/static

# Set the secrets directory where Settings.toml will be loaded with higher priority than default
# Settings are loaded with the following precedence:
# 1. Environment variables (highest priority)
# 2. Settings.toml in VOUCHR_SECRETS_DIR (if exists)
# 3. Default Settings.toml (lowest priority)
ENV VOUCHR_SECRETS_DIR=/app/secrets

# Run the application
ENTRYPOINT ["/app/vouchrs"]
