# Multi-stage build for the urban-definitions service.
#
# The build context is the REPO ROOT (not service/): the service depends on the
# `urban-definitions-wire` lib at the workspace root via `path = ".."`.
#   docker build -f service/Dockerfile -t urban-definitions .
FROM rust:1-bookworm AS builder
WORKDIR /build
COPY . .
RUN cargo build --release --locked -p urban-definitions-service

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl openssh-client \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/urban-definitions-service /usr/local/bin/
RUN groupadd --system --gid 10003 urban \
    && useradd --system --uid 10003 --gid 10003 --no-create-home --shell /usr/sbin/nologin urban
USER urban
EXPOSE 3003
HEALTHCHECK --interval=30s --timeout=3s CMD curl -fsS http://localhost:3003/health || exit 1
ENTRYPOINT ["/usr/local/bin/urban-definitions-service"]
