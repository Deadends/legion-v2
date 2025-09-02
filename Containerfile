# Use Quay.io (Red Hat registry) - better for Podman
FROM quay.io/fedora/fedora:39 as builder
WORKDIR /app

# Install Rust and build tools
RUN dnf install -y rust cargo gcc openssl-devel pkg-config && dnf clean all

# Copy source
COPY Cargo.toml Cargo.lock ./
COPY src ./src/

# Build release binary
RUN cargo build --release --bin legion-server

# Runtime stage
FROM quay.io/fedora/fedora-minimal:39
RUN microdnf install -y ca-certificates && microdnf clean all

# Copy binary
COPY --from=builder /app/target/release/legion-server /usr/local/bin/legion-server

# Create user
RUN useradd -r -s /sbin/nologin legion
USER legion

EXPOSE 8080
CMD ["legion-server"]