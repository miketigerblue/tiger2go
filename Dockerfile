# -----------------------------------------------------------------
# Build stage
# -----------------------------------------------------------------
FROM golang:1.24-bookworm AS builder
WORKDIR /app

# 1) Copy module files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# 2) Copy source code
COPY . .

# 3) Build the application
# Results in /app/tigerfetch
RUN go build -o tigerfetch ./cmd/tigerfetch

# -----------------------------------------------------------------
# Runtime stage
# -----------------------------------------------------------------
FROM debian:bookworm-slim

# Install CA certs for HTTPS
RUN apt-get update \
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

# Note: Config.toml is optional - app uses defaults/env vars if not present
# Config.toml is excluded in .dockerignore to prevent secrets from being included

EXPOSE 9101
ENTRYPOINT ["tigerfetch"]
