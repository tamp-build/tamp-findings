# syntax=docker/dockerfile:1.7
#
# Multi-stage build for tamp.findings.
#
# Stages:
#   1. api-build   — .NET 10 SDK, dotnet publish the API (Blazor RCL included)
#   2. runtime     — ASP.NET 10 alpine, copies the publish output
#
# TFND-128 retired the React SPA and with it the Node build stage. There is no
# JS bundle in this image any more: the front end is a Blazor Server RCL that
# publishes as part of the API, so the toolchain is one SDK rather than two.
#
# Final image serves the app + API on a single :5080 listener (no nginx pod
# needed). Postgres is external — provided by the StatefulSet in the
# tamp-findings namespace.
#
# Build context is the repo root.

# -----------------------------------------------------------------------------
# Stage 1 — API publish (.NET 10 SDK)
# -----------------------------------------------------------------------------
FROM mcr.microsoft.com/dotnet/sdk:10.0-alpine AS api-build

WORKDIR /work

# Copy MSBuild central-package + lock files first for restore cache.
COPY Directory.Build.props Directory.Packages.props global.json Tamp.Findings.slnx ./
COPY src/Tamp.Findings.Domain/Tamp.Findings.Domain.csproj   src/Tamp.Findings.Domain/
COPY src/Tamp.Findings.Data/Tamp.Findings.Data.csproj       src/Tamp.Findings.Data/
COPY src/Tamp.Findings.Application/Tamp.Findings.Application.csproj src/Tamp.Findings.Application/
COPY src/Tamp.Findings.Web/Tamp.Findings.Web.csproj         src/Tamp.Findings.Web/
COPY src/Tamp.Findings.Workflows/Tamp.Findings.Workflows.csproj src/Tamp.Findings.Workflows/
# The MCP server (TFND-12). The Api references it, so restore needs its csproj
# here — a ProjectReference added without a matching COPY fails only at
# `dotnet publish --no-restore`, which no test run reaches.
COPY src/Tamp.Findings.Mcp/Tamp.Findings.Mcp.csproj         src/Tamp.Findings.Mcp/
COPY src/Tamp.Findings.Api/Tamp.Findings.Api.csproj         src/Tamp.Findings.Api/

# Restore only what the API needs — Domain + Data + Api transitively. Skip
# build/ project, test projects.
RUN dotnet restore src/Tamp.Findings.Api/Tamp.Findings.Api.csproj

# Now copy source. Putting source COPY after restore keeps the restore
# layer cached across pure-source edits.
COPY src/ src/

RUN dotnet publish src/Tamp.Findings.Api/Tamp.Findings.Api.csproj \
    -c Release \
    -o /app/publish \
    --no-restore \
    /p:UseAppHost=false

# -----------------------------------------------------------------------------
# Stage 2 — runtime (ASP.NET 10 alpine)
# -----------------------------------------------------------------------------
FROM mcr.microsoft.com/dotnet/aspnet:10.0-alpine AS runtime

# ICU. The alpine runtime images ship WITHOUT it and set
# DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1, under which constructing any named
# culture throws — including the "en" this app sets as its default request
# culture (Program.cs, TFND-67). The container exited 139 on startup with
# "Only the invariant culture is supported in globalization-invariant mode".
#
# It had been broken since the localisation work landed and nothing noticed,
# because CI built the image but never RAN it. Building an image proves it
# compiles; starting it is a different claim.
#
# icu-data-full rather than the default slice: the pseudo-locale (qps-ploc)
# used to verify ~40% string expansion is not in the trimmed data set, so a
# partial install would swap a hard crash for a feature that silently does not
# work.
#
# Must run BEFORE the USER line below — apk needs root.
#
# krb5-libs is for Npgsql, which probes for GSSAPI at startup and logs
# "Error: Error loading shared library libgssapi_krb5.so.2" without it. The
# app runs fine either way — but a permanent, harmless line reading "Error:"
# in the startup log of a compliance tool is how operators learn to skim past
# errors, and the fix is one package.
RUN apk add --no-cache icu-libs icu-data-full tzdata krb5-libs
ENV DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=0

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
