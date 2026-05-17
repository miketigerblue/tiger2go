# PostgREST — analyst surface over the tiger2go lake

> **This directory is retained for historical reference.**
> Canonical PostgREST deployment artefacts (Dockerfile, Fly config,
> JWKS publishing, JWT mint flow) now live in
> [`tigerblue-deployment`](https://github.com/miketigerblue/tigerblue-deployment).

## What's still here

| File | Purpose |
|---|---|
| `Dockerfile` | Legacy image build. Frozen — does **not** match the production image. |
| `postgrest.conf` | Legacy config. Reference value only; the live config is sourced from Fly secrets. |
| `fly.toml` | Legacy Fly app definition. The production app `tigerblue-postgrest` deploys from `tigerblue-deployment`, not from here. |

## Where to go for the live deployment

- **Service URL:** `https://tigerblue-postgrest.fly.dev`
- **Schema exposed:** `api` (`PGRST_DB_SCHEMA=api`)
- **Auth:** RS256 JWT against the JWKS at
  `https://miketigerblue.github.io/malware-fingerprints/.well-known/jwks.json`
- **Token mint flow:** `tigerblue-deployment/mint_postgrest_token.py`
  reading the signing key from
  `op://tigerblue/postgrest-signing-2026q2/private`. See
  `tigerblue-deployment/postgrest-jwt-setup.md` for the end-to-end flow.
- **Endpoint catalogue:** [`docs/API_ENDPOINTS_SECURITY_TRIAGE_GUIDE.md`](../docs/API_ENDPOINTS_SECURITY_TRIAGE_GUIDE.md)

## Why the split

PostgREST is the *analyst surface* over the lake; tigerfetch is the
*ingestion service* that fills the lake. Keeping deployment artefacts
for the analyst surface alongside the lake-owning repo created two
sources of truth (this directory and the `tigerblue-deployment`
working copy) that drifted. Consolidating to one source.

The `api` schema definitions themselves stay in tigerfetch's
`migrations/` (they're part of the data model); only the PostgREST
*service* deployment moved.
