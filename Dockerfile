# -----------------------------------------------------------------
# Build stage
# -----------------------------------------------------------------
FROM golang:1.26-bookworm AS builder
WORKDIR /app

# 1) Copy module files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# 2) Copy source code
COPY . .

# 3) Build the application
# Results in /app/tigerfetch
ARG VERSION=dev
ARG COMMIT=none
RUN go build -ldflags "-X main.version=${VERSION} -X main.commit=${COMMIT}" -o tigerfetch ./cmd/tigerfetch

# -----------------------------------------------------------------
# Runtime stage
# -----------------------------------------------------------------
FROM debian:bookworm-slim

# Pull in any base-image security patches at build time before installing
# what we actually need. Without this, debian:bookworm-slim ships with the
# package versions baked into the tagged image — which lag behind upstream
# fixes by however long it's been since the tag was rebuilt. Trivy gates
# the CI build on HIGH/CRITICAL CVEs in the base image, so a stale base
# fails CI even when our own code is clean.
RUN apt-get update \
    && apt-get -y upgrade \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN addgroup --system app && adduser --system --ingroup app app
USER app:app

WORKDIR /home/app

# Copy the binary
COPY --from=builder /app/tigerfetch /usr/local/bin/tigerfetch

# Copy migrations (required for the app to run them)
COPY --chown=app:app migrations ./migrations

# Bake the production Config.toml into the image. Structure-only —
# secrets come from env vars (DATABASE_URL, NVD_API_KEY, GHSA_TOKEN,
# ABUSECH_API_KEY) via viper's BindEnv. The dev Config.toml stays
# excluded by .dockerignore so local credentials don't leak.
COPY --chown=app:app Config.production.toml ./Config.toml

EXPOSE 9101
ENTRYPOINT ["tigerfetch"]
