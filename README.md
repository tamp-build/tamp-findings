# tamp.findings

Self-hosted findings hub for tamp-built software. Aggregates every scanner's output
across a **Client → Project → Component → Version** hierarchy, normalizes into one
Finding model with role-scoped RBAC, supports suppressions/waivers by named project
roles, and exposes everything to humans (Sonar-grade UI) and agents (MCP server).

Tracking: YouTrack project **TFND** at https://yt.brewingcoder.com — epic **TFND-1**,
features TFND-2..TFND-13.

> **Status:** POC. Local only, no remote yet. Surface is still being shaped.

## Stack

- **API:** ASP.NET minimal API (.NET 10), native OpenAPI
- **Storage:** Postgres (bundled in dev docker-compose, BYO in production)
- **UI:** React + shadcn/ui SPA (Vite)
- **MCP:** in-process MCP server for agent retrieval (stub)
- **Deployment target:** single OCI image bundling API + SPA

## Layout

```
src/
  Tamp.Findings.Domain/   POCOs + domain rules
  Tamp.Findings.Data/     EF Core DbContext, Npgsql provider, migrations
  Tamp.Findings.Api/      Minimal API host; serves the SPA in prod
  Tamp.Findings.Mcp/      MCP server (stub for now)
tests/
  Tamp.Findings.Domain.Tests/
  Tamp.Findings.Api.Tests/
web/                      Vite + React + shadcn/ui SPA
docker/                   docker-compose.dev.yml with bundled Postgres
docs/adr/                 architecture decision records
```

## Dev workflow

```pwsh
# 1. Bring up Postgres
docker compose -f docker/docker-compose.dev.yml up -d

# 2. Run the API (auto-applies migrations on startup once F3.2 lands)
dotnet run --project src/Tamp.Findings.Api

# 3. Run the SPA (in another shell)
cd web; pnpm install; pnpm dev
```

API: http://localhost:5080 — health at `/health`, OpenAPI at `/openapi/v1.json`
SPA: http://localhost:5173 — proxies API calls to the API port

## Why "tamp.findings" and not bolted onto tamp-beacon?

Beacon's job is build status and build-failure alerts. Findings has a much richer
data model (multi-scanner, SBOM, dep graphs, RBAC) and a heavier UI. They share the
ADR 0018 emission contract (owned by tamp-build) but nothing else — no shared code,
no shared runtime.
