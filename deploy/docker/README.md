# deploy/docker — plain-Docker deployment

Run `tamp.findings` as two containers — the app and Postgres — with **no
Kubernetes**. This is the simplest way to self-host it, and what most users
want.

## Prerequisites
- Docker with the Compose plugin.
- A GitHub OAuth app (for sign-in).

## Run it
```bash
cp deploy/docker/.env.example deploy/docker/.env      # then fill it in
docker compose -f deploy/docker/docker-compose.yml --env-file deploy/docker/.env up -d --build
```
Open `http://localhost:5080` (or your `TAMP_FINDINGS_PORT`). Sign in with GitHub;
the `GITHUB_BOOTSTRAP_ADMIN_LOGIN` account is promoted to admin on first sign-in.
On a brand-new instance, the very first registration must present the **setup
token** printed in the api container's logs:
```bash
docker compose -f deploy/docker/docker-compose.yml logs api | grep -i setup
```

## Behind a reverse proxy (production)
Terminate TLS at a proxy of your choice (Caddy, nginx, Traefik, a tunnel, …) on
your public host and forward it to the published api port. The app trusts
`X-Forwarded-Proto` / `X-Forwarded-Host` from the proxy, so:
- set the GitHub OAuth callback to `https://<your-host>/auth/github/callback`,
- set the **Instance URL** under System settings to `https://<your-host>`.

Keep the app reachable **only** through the proxy — don't expose the published
port directly to the internet.

## Data & backups
All state lives in Postgres — findings, SBOMs, attestations, **and** the
data-protection key ring that signs sessions (so a restart doesn't sign everyone
out). Back up the `pgdata` volume; e.g.:
```bash
docker compose -f deploy/docker/docker-compose.yml exec postgres \
  pg_dump -U tamp tamp_findings > tamp-findings-backup.sql
```
See [`docs/OPERATIONS.md`](../../docs/OPERATIONS.md) for cadence and retention.

## Updating
```bash
git pull
docker compose -f deploy/docker/docker-compose.yml --env-file deploy/docker/.env up -d --build
```
Migrations apply automatically on startup.

## Health
- `GET /health` — process liveness, does not touch the DB (the container
  healthcheck uses this).
- `GET /ready` — checks the database; poll this from a load balancer.

## Kubernetes instead?
For a cluster deployment, see [`../k8s/`](../k8s/).
