# Multi-stage build for Rex CLI
# Stage 1: Build stage
FROM rustlang/rust:nightly-slim AS builder

# Install system dependencies needed for building
RUN apt-get update && apt-get install -y \
    git \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /rex

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY cli/ ./cli/
COPY sdk/ ./sdk/

# Build the CLI binary with optimizations
RUN cargo build --release --bin rex

# Stage 2: Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -r -s /bin/false rex

# Copy the built binary from builder stage
COPY --from=builder /rex/target/release/rex /usr/local/bin/rex

# Set permissions
RUN chmod +x /usr/local/bin/rex

# Switch to non-root user
USER rex

# Set entrypoint
ENTRYPOINT ["rex"]
CMD ["--help"]