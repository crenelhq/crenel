# crenel — the brain, as a static zero-dependency binary.
#
# Multi-stage: build the CGO-free static binary against the repo, then ship it on
# a minimal base. Mirrors `make build` (CGO_ENABLED=0, version stamp). The build
# context is the REPO ROOT (see docker-compose.yml `build.context: ..`).
FROM golang:1.22-alpine AS build
WORKDIR /src
# Module graph is std-lib only (no network needed), so copy everything and build.
COPY . .
ARG VERSION=bundle-v0
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/crenel ./cmd/crenel

# Runtime: alpine gives us a shell for `docker compose exec` ergonomics + curl for
# the healthcheck. crenel itself needs nothing but the kernel.
FROM alpine:3.20
RUN apk add --no-cache curl ca-certificates
COPY --from=build /out/crenel /usr/local/bin/crenel
# Read-only dashboard port (published by the caddy service, whose netns we share).
EXPOSE 8080
ENTRYPOINT ["crenel"]
CMD ["serve", "--addr", ":8080"]
