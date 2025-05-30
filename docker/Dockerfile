# Ultra-minimal distroless static Dockerfile
FROM rust:1.82-slim AS builder

# Define build arguments for multiplatform support
ARG TARGETPLATFORM
ARG BUILDPLATFORM

# Install required system dependencies for static linking
RUN apt-get update && apt-get install -y \
    libssl-dev \
    musl-dev \
    musl-tools \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Set target architecture based on platform
RUN case "$TARGETPLATFORM" in \
    "linux/amd64") echo "x86_64-unknown-linux-musl" > /target.txt ;; \
    "linux/arm64") echo "aarch64-unknown-linux-musl" > /target.txt ;; \
    *) echo "Unsupported platform: $TARGETPLATFORM" && exit 1 ;; \
    esac

# Add musl targets for static linking
RUN rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl

# Set working directory
WORKDIR /app

# Copy dependency files first for better caching
COPY Cargo.toml Cargo.lock ./

# Create a dummy main.rs to build dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build dependencies with the appropriate target for static linking
ENV RUSTFLAGS="-C target-feature=+crt-static"
RUN TARGET=$(cat /target.txt) && \
    case "$TARGET" in \
    "x86_64-unknown-linux-musl") export CC_x86_64_unknown_linux_musl=musl-gcc ;; \
    "aarch64-unknown-linux-musl") export CC_aarch64_unknown_linux_musl=musl-gcc ;; \
    esac && \
    cargo build --release --target $TARGET --locked
RUN rm src/main.rs

# Copy source code
COPY src ./src
COPY Settings.toml ./

# Build the application with static linking for the target platform
RUN TARGET=$(cat /target.txt) && \
    case "$TARGET" in \
    "x86_64-unknown-linux-musl") export CC_x86_64_unknown_linux_musl=musl-gcc ;; \
    "aarch64-unknown-linux-musl") export CC_aarch64_unknown_linux_musl=musl-gcc ;; \
    esac && \
    cargo build --release --target $TARGET --locked

# Copy the binary to a predictable location for the runtime stage
RUN TARGET=$(cat /target.txt) && \
    cp /app/target/$TARGET/release/vouchrs /app/vouchrs

# Runtime stage - distroless static (smallest possible)
FROM gcr.io/distroless/static-debian12:18d48b0eeb51dfb9769b782a97fc868470b7c3c5

# Set working directory for the application
WORKDIR /app

# Copy the statically linked binary from builder stage
COPY --from=builder /app/vouchrs /app/vouchrs

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
