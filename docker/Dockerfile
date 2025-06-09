# Ultra-minimal distroless static Dockerfile with vendored OpenSSL
FROM rust:1.87-slim AS builder

# Define build arguments for multiplatform support
ARG TARGETPLATFORM
ARG BUILDPLATFORM

# Install required system dependencies for static linking with vendored OpenSSL
RUN apt-get update && apt-get install -y \
    libssl-dev \
    musl-dev \
    musl-tools \
    pkg-config \
    perl \
    make \
    && rm -rf /var/lib/apt/lists/*

# Set target architecture based on platform (using musl for static linking)
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

# Build dependencies with static OpenSSL and musl
ENV RUSTFLAGS="-C target-feature=+crt-static"
ENV OPENSSL_STATIC=1
ENV OPENSSL_VENDOR=1
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    TARGET=$(cat /target.txt) && \
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
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    TARGET=$(cat /target.txt) && \
    case "$TARGET" in \
    "x86_64-unknown-linux-musl") export CC_x86_64_unknown_linux_musl=musl-gcc ;; \
    "aarch64-unknown-linux-musl") export CC_aarch64_unknown_linux_musl=musl-gcc ;; \
    esac && \
    cargo build --release --target $TARGET --locked && \
    cp /app/target/$TARGET/release/vouchrs /app/vouchrs

# Copy the static files that were built
RUN TARGET=$(cat /target.txt) && \
    if [ -d "/app/target/$TARGET/release/static" ]; then \
    cp -r /app/target/$TARGET/release/static /app/static; \
    elif [ -d "src/static" ]; then \
    cp -r src/static /app/static; \
    fi

# Runtime stage - distroless static (smallest possible)
FROM gcr.io/distroless/static-debian12:18d48b0eeb51dfb9769b782a97fc868470b7c3c5

# Set working directory for the application
WORKDIR /app

# Copy the statically linked binary from builder stage
COPY --from=builder /app/vouchrs /app/vouchrs

# Copy default configuration
COPY --from=builder /app/Settings.toml /app/Settings.toml

# Copy static files from builder stage with proper ownership for nonroot user
# This allows the application to write generated HTML files to the static directory
COPY --from=builder --chown=nonroot:nonroot /app/static /app/static

# Use non-root user
USER nonroot:nonroot

# Expose port
EXPOSE 8080

# Set the secrets directory where Settings.toml will be loaded with higher priority than default
# Settings are loaded with the following precedence:
# 1. Environment variables (highest priority)
# 2. Settings.toml in VOUCHR_SECRETS_DIR (if exists)
# 3. Default Settings.toml (lowest priority)
ENV VOUCHR_SECRETS_DIR=/app/secrets

# Run the application
ENTRYPOINT ["/app/vouchrs"]
