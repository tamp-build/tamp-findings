# syntax=docker/dockerfile:1.7
#
# Multi-stage build for tamp.findings.
#
# Stages:
#   1. web-build   — Node 22 alpine, pnpm install + vite build the SPA
#   2. api-build   — .NET 10 SDK, copies the SPA dist into wwwroot, dotnet
#                    publish the API
#   3. runtime     — ASP.NET 10 alpine, copies the publish output
#
# Final image serves SPA + API on a single :5080 listener (no nginx pod
# needed). Postgres is external — provided by the StatefulSet in the
# tamp-findings namespace.
#
# Build context is the repo root. Produces ~150 MB image.

# -----------------------------------------------------------------------------
# Stage 1 — SPA build (Node 22 alpine + pnpm)
# -----------------------------------------------------------------------------
FROM node:22-alpine AS web-build

WORKDIR /work/web

# Match pnpm version the dev env uses (see web/package.json's packageManager
# field if you ever pin it). Corepack ships with Node 22 and resolves the
# right pnpm transparently.
RUN corepack enable && corepack prepare pnpm@10.32.1 --activate

# Copy lockfiles first so installs cache across SPA source edits.
COPY web/package.json web/pnpm-lock.yaml ./
RUN --mount=type=cache,id=pnpm,target=/root/.local/share/pnpm/store \
    pnpm install --frozen-lockfile

COPY web/ .

# Vite emits to dist/ by default. tsconfig + vite.config.ts already in
# place; no env vars needed at build time (API base is "/api", served
# same-origin).
RUN pnpm run build

# -----------------------------------------------------------------------------
# Stage 2 — API publish (.NET 10 SDK)
# -----------------------------------------------------------------------------
FROM mcr.microsoft.com/dotnet/sdk:10.0-alpine AS api-build

WORKDIR /work

# Copy MSBuild central-package + lock files first for restore cache.
COPY Directory.Build.props Directory.Packages.props global.json Tamp.Findings.slnx ./
COPY src/Tamp.Findings.Domain/Tamp.Findings.Domain.csproj   src/Tamp.Findings.Domain/
COPY src/Tamp.Findings.Data/Tamp.Findings.Data.csproj       src/Tamp.Findings.Data/
COPY src/Tamp.Findings.Application/Tamp.Findings.Application.csproj src/Tamp.Findings.Application/
COPY src/Tamp.Findings.Web/Tamp.Findings.Web.csproj         src/Tamp.Findings.Web/
COPY src/Tamp.Findings.Api/Tamp.Findings.Api.csproj         src/Tamp.Findings.Api/

# Restore only what the API needs — Domain + Data + Api transitively. Skip
# build/ project, test projects.
RUN dotnet restore src/Tamp.Findings.Api/Tamp.Findings.Api.csproj

# Now copy source. Putting source COPY after restore keeps the restore
# layer cached across pure-source edits.
COPY src/ src/

# Pull in the SPA dist as wwwroot so UseStaticFiles serves it.
COPY --from=web-build /work/web/dist/ src/Tamp.Findings.Api/wwwroot/

RUN dotnet publish src/Tamp.Findings.Api/Tamp.Findings.Api.csproj \
    -c Release \
    -o /app/publish \
    --no-restore \
    /p:UseAppHost=false

# -----------------------------------------------------------------------------
# Stage 3 — runtime (ASP.NET 10 alpine)
# -----------------------------------------------------------------------------
FROM mcr.microsoft.com/dotnet/aspnet:10.0-alpine AS runtime

# Non-root user — Kubernetes pod security standards "restricted" profile
# expects pods to run as a non-root UID. The aspnet:10.0-alpine base
# image already ships an `app` user / group; we reuse it rather than
# creating a duplicate (addgroup -S app would fail with "group in use").
WORKDIR /app
COPY --from=api-build --chown=app:app /app/publish .

# Numeric UID — Kubernetes PSS restricted requires runAsNonRoot to be
# proven by a numeric user (string usernames can't be verified non-root
# without resolving /etc/passwd inside the image at admission time).
# aspnet:10.0-alpine's `app` user is uid 1654 / gid 1654; pinning the
# numeric form lets the kubelet pass admission. Stay in sync with
# deploy/k8s/api.yaml's runAsUser / runAsGroup.
USER 1654:1654

# Match the dev API's port + the Service / probe config in deploy/k8s.
EXPOSE 5080
ENV ASPNETCORE_URLS=http://+:5080 \
    ASPNETCORE_ENVIRONMENT=Production \
    DOTNET_RUNNING_IN_CONTAINER=true \
    DOTNET_NOLOGO=true

# Health probe — same path the readiness/liveness probes in the Deployment
# manifest target. Anonymous, no DB call (just a static OK).
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD wget --quiet --tries=1 --spider http://localhost:5080/health || exit 1

ENTRYPOINT ["dotnet", "Tamp.Findings.Api.dll"]
