# crenel — the published OCI image (ghcr.io/crenelhq/crenel).
#
# This is the RELEASE image, built and pushed by .github/workflows/release.yml on
# every v* tag. It is distinct from bundle/Dockerfile, which stays as the
# local-build image for the turnkey demo bundle (docker compose up in bundle/).
#
# Base-image decision: alpine, NOT scratch. The binary itself is CGO-free and
# static — scratch would work for the pure admin-API path and would match the
# zero-dependency brand. But crenel's exec seams (the ssh-exec transport, the
# durable-persist `caddy_persist` file/caddy channels, nginx test/reload
# commands) all land a POSIX `sh`, and `docker compose exec <svc> crenel …` is
# the documented way to drive a containerized crenel. scratch has no shell and
# no CA roots, which silently amputates those paths. alpine costs ~8 MB and
# keeps every documented topology usable; ca-certificates covers HTTPS DNS
# providers (Cloudflare) and ntfy. Tradeoff documented, pragmatism chosen.
# (No docker-cli or caddy binary here — see docs/CONTAINER.md for the thin
# derived image the durable-persist topology needs.)
FROM golang:1.22-alpine AS build
WORKDIR /src
# Module graph is std-lib only (no network needed), so copy everything and build.
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/crenel ./cmd/crenel

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /out/crenel /usr/local/bin/crenel

LABEL org.opencontainers.image.title="crenel" \
      org.opencontainers.image.description="Agent-ready control plane for the self-hosted edge: read-live, plan, apply, read-back-verify against Caddy/Traefik/nginx and DNS." \
      org.opencontainers.image.source="https://github.com/crenelhq/crenel" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.documentation="https://github.com/crenelhq/crenel/blob/main/docs/CONTAINER.md"

ENTRYPOINT ["crenel"]
CMD ["--help"]
