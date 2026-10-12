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
Open `http://localhost:5080` (or your `TAMP_FINDINGS_PORT`) and sign in with GitHub.

**Claiming the admin seat.** A brand-new instance has no users, and the first sign-in
is the one that becomes administrator. Either of two credentials claims it:

- **`GITHUB_BOOTSTRAP_ADMIN_LOGIN`** — set it to your GitHub login and sign in as that
  account. Nothing else to paste.
- **The setup token**, printed in the api container's log at every startup while the
  seat is unclaimed:
  ```bash
  docker compose -f deploy/docker/docker-compose.yml logs api | grep -i setup
  ```

Either way the claim is once-only: as soon as a user exists, the seat is taken, the
token is disarmed, and the bootstrap variable stops conferring admin — later arrivals
register as ordinary users an administrator has to approve. The variable then only
promotes an account that already exists, which is its recovery path for "the admin
signed in before the variable was set".

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

## Changing configuration — recreate, do not restart

**A container's environment is fixed when the container is created.** `docker restart`
reuses the existing container and therefore the *old* environment, so an edit to your
env file silently does not take effect — the app keeps running with the previous value
and nothing says so.

| How you started it | After editing the env file |
|---|---|
| `docker compose … up -d` | Run `up -d` again — compose re-reads `--env-file` and recreates the container |
| `docker run --env-file …` | `docker stop` + `docker rm`, then `docker run` again. **`docker restart` will not pick it up** |

This bites hardest while fixing OAuth credentials, because the symptom of a wrong
`GITHUB_CLIENT_ID` (a GitHub 404, or no "Continue with GitHub" button) is identical
before and after a restart that changed nothing. If a config fix appears to have had no
effect, confirm the container was recreated before looking anywhere else.

One related moving part: **the setup token is regenerated on every start** while the
admin seat is unclaimed, and is never stored. That is deliberate — a claim token that
outlived its claim would be a standing credential — but it means the token from an
earlier log is stale. Always read it from the current container's log.

## Health
- `GET /health` — process liveness, does not touch the DB (the container
  healthcheck uses this).
- `GET /ready` — checks the database; poll this from a load balancer.

## Kubernetes instead?
For a cluster deployment, see [`../k8s/`](../k8s/).
