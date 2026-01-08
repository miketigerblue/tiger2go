# 🐘 PostgREST Service for Tigerfetch

This directory contains the configuration and deployment setup for the **PostgREST** service used by the **Tigerfetch** platform.  
PostgREST provides a secure, RESTful API interface directly over the PostgreSQL database, enabling read-only or role-based access to enriched data.

---

## 📁 Directory Structure

```
postgrest/
├── Dockerfile          # Container definition for PostgREST
├── postgrest.conf      # Main configuration file
├── fly.toml            # Fly.io deployment configuration
└── README.md           # This documentation
```

---

## ⚙️ Configuration Overview

### `postgrest.conf`
This file defines how PostgREST connects to the database and exposes schemas.

Example:
```ini
db-uri = "$(PGRST_DB_URI)"
db-schemas = "public"
db-anon-role = "web_anon"
server-port = 3000
```

**Key parameters:**
- `db-uri`: Connection string to the PostgreSQL database.  
  - In production, this is injected via Fly.io secrets.
  - Example:  
    `postgres://user:password@tigerblue-db.internal:5432/tigerfetch`
- `db-schemas`: The schema(s) PostgREST exposes as REST endpoints.
- `db-anon-role`: The role used for unauthenticated requests.
- `server-port`: The internal port PostgREST listens on (default: `3000`).

---

## 🐳 Docker Setup

### Dockerfile
```Dockerfile
FROM postgrest/postgrest:latest
COPY postgrest.conf /etc/postgrest.conf
CMD ["postgrest", "/etc/postgrest.conf"]
```

This builds a lightweight container that runs PostgREST with your configuration baked in.

### Local Development
To run locally using Docker Compose:
```bash
docker compose up -d postgrest
```

Ensure your `db-uri` in `postgrest.conf` points to your local or legacy database, e.g.:
```
db-uri = "postgres://user:password@host.docker.internal:5432/osint"
```

---

## ☁️ Fly.io Deployment

### 1. Create a Fly App
```bash
fly launch --name tigerfetch-postgrest --no-deploy
```

### 2. Set Secrets
```bash
fly secrets set PGRST_DB_URI="postgres://user:password@tigerblue-db.internal:5432/tigerfetch"
```

### 3. Deploy
```bash
fly deploy --config fly.toml --dockerfile Dockerfile
```

### 4. Verify
```bash
fly logs
curl https://tigerfetch-postgrest.fly.dev/
```

---

## 🔒 Security

- **TLS only:** The Fly.io configuration enforces HTTPS (port 443) for all external traffic.
- **Internal DB access:** PostgREST connects to the managed PostgreSQL instance via Fly’s internal network (`.internal` domain).
- **Secrets management:** Database credentials are stored securely using Fly secrets, overriding any values in `fly.toml`.

---

## 🧠 Tips

- To inspect the active environment variables:
  ```bash
  fly ssh console -C 'printenv | grep PGRST'
  ```
- To redeploy after config changes:
  ```bash
  fly deploy
  ```
- To scale PostgREST:
  ```bash
  fly scale count 2
  ```

---

## 🧩 Integration Notes

- The PostgREST service complements the main **Tigerfetch API** by providing direct, schema-driven access to the database.
- It’s ideal for:
  - Internal dashboards
  - Data analysis tools
  - Read-only API consumers

---

## 🔐 Restricting Access to Internal Fly Apps Only

To make PostgREST accessible only to other Fly.io apps (and not the public internet):

1. Remove the public ports from `fly.toml`:
   ```toml
   [[services]]
     internal_port = 3000
     protocol = "tcp"
   ```

2. Use Fly’s **private networking** to connect from your other Fly apps:
   ```bash
   curl http://tigerfetch-postgrest.internal:3000/
   ```

This ensures PostgREST is only reachable within your Fly.io organization’s internal network.

---

## 🧾 License

This configuration and documentation are part of the **Tigerfetch** project.  
Licensed under the Apache License 2.0.
