using System.Text.Json.Serialization;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Authentication;
using Tamp.Findings.Api.Endpoints;
using Tamp.Findings.Api.Services;
using Tamp.Findings.Data;

var builder = WebApplication.CreateBuilder(args);

// Raise both the request-body limit (Kestrel) and the form value count limit
// so coverage ingest, which bundles every source file in the scan scope, can
// post a few MB of payload without the framework refusing it. 100 MB ceiling
// is generous for a single-repo scan; cap stays well below shenanigan territory.
builder.WebHost.ConfigureKestrel(k => k.Limits.MaxRequestBodySize = 100L * 1024 * 1024);

// Behind the Cloudflare tunnel in prod: the tunnel terminates TLS at
// the edge and forwards plain HTTP to the in-cluster Service. Without
// this, ASP.NET Core builds OAuth redirect URIs from the Host it
// actually sees (an internal pod IP, scheme http://) — which GitHub
// rejects with "redirect_uri is not associated with this application".
//
// Trust X-Forwarded-Proto + X-Forwarded-Host (Cloudflare adds both)
// so HttpContext.Request reflects the public-origin URL.
//
// Empty KnownNetworks/KnownProxies + ForwardLimit=null = trust the
// tunnel regardless of source IP. Safe because the cluster Service is
// only reachable via the tunnel; no direct LAN ingress to the pod.
builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    o.ForwardedHeaders = ForwardedHeaders.XForwardedFor
                       | ForwardedHeaders.XForwardedProto
                       | ForwardedHeaders.XForwardedHost;
    o.KnownIPNetworks.Clear();
    o.KnownProxies.Clear();
});

builder.Services.AddOpenApi();

// Enums on the wire are strings, not ints — friendlier for hand-written
// payloads from scanners and for the agent surface in F11.
builder.Services.ConfigureHttpJsonOptions(o =>
    o.SerializerOptions.Converters.Add(new JsonStringEnumConverter()));

// Postgres connection comes from configuration. In dev the bundled
// docker-compose Postgres exposes this on localhost:5432; in prod, set
// TAMP_FINDINGS_DB or ConnectionStrings:Findings to point at a real Postgres.
var connectionString =
    builder.Configuration["ConnectionStrings:Findings"]
    ?? Environment.GetEnvironmentVariable("TAMP_FINDINGS_DB")
    ?? "Host=localhost;Port=5544;Database=tamp_findings;Username=tamp;Password=tamp";

builder.Services.AddFindingsDb(connectionString);

// IHttpClientFactory powers the SBOM registry enrichment service. A
// single named client is registered so the factory can pool sockets
// across enrichment calls.
builder.Services.AddHttpClient("registries");
builder.Services.AddScoped<SbomEnrichmentService>();
// Builds RiskInputs for an explicit CV-id set — drives the per-build
// evaluator. /aggregates still computes its own inline against the
// latest-canonical set; a future refactor can consolidate.
builder.Services.AddScoped<Tamp.Findings.Api.Services.RiskInputsBuilder>();
// TFND-25: project-scoped VEX statements suppress matching vulns from
// CVE counts + KEV count.
builder.Services.AddScoped<Tamp.Findings.Api.Services.VexResolver>();

// TFND-26: CISA Known Exploited Vulnerabilities catalog. Service does
// the actual upsert; the hosted worker schedules it (startup + daily).
builder.Services.AddScoped<Tamp.Findings.Api.Services.KevFeedSyncService>();
builder.Services.AddHostedService<Tamp.Findings.Api.Services.KevFeedSyncWorker>();

builder.Services.AddCors(options =>
{
    // POC dev posture: any origin allowed. The SPA uses Vite's /api proxy
    // so same-origin via the dev server is the normal path — this opens
    // direct API access for ad-hoc curl from other machines, the MCP
    // server, and any future tools. Tighten to an allow-list before any
    // non-local deployment.
    options.AddDefaultPolicy(p =>
        p.AllowAnyOrigin()
         .AllowAnyHeader()
         .AllowAnyMethod());
});

// TFND-4 OIDC sign-in. Cookie session + GitHub OAuth challenge.
builder.Services.AddTampFindingsAuth(builder.Configuration);

// Bearer-token auth for /ingest/*. Each request brings a cli_/prj_
// token; the filter validates + stashes the row, the endpoints
// scope-check resolved Client/Project against it.
builder.Services.AddScoped<Tamp.Findings.Api.Authentication.IngestTokenService>();
builder.Services.AddScoped<Tamp.Findings.Api.Authentication.IngestAuthFilter>();

var app = builder.Build();

// Run pending migrations on startup so adopters don't need to remember
// `dotnet ef`. Test hosts opt out via the TAMP_FINDINGS_SKIP_MIGRATE env var.
if (Environment.GetEnvironmentVariable("TAMP_FINDINGS_SKIP_MIGRATE") != "true")
{
    using var scope = app.Services.CreateScope();
    var db = scope.ServiceProvider.GetRequiredService<FindingsDbContext>();
    db.Database.Migrate();
    // Ensure exactly one system-default RiskPolicy exists. Seeded from
    // RiskPolicyDefaults so the v1 weights stay in one place; admins can
    // edit the seed row in place after first run.
    if (!await db.RiskPolicies.AnyAsync(p => p.IsDefault))
    {
        db.RiskPolicies.Add(new Tamp.Findings.Domain.Entities.RiskPolicy
        {
            Name = Tamp.Findings.Domain.Risk.RiskPolicyDefaults.TampStandardV1Name,
            Description = "System-seeded default. Editable — admins can tune the weights or clone to start a new policy.",
            IsDefault = true,
            IsSeeded = true,
            Config = Tamp.Findings.Domain.Risk.RiskPolicyDefaults.BuildTampStandardV1(),
        });
        await db.SaveChangesAsync();
    }
}

// ForwardedHeaders MUST run before anything that reads Request.Scheme
// / Request.Host (auth, redirect builders, OAuth challenge URL
// generation). Goes first in the pipeline.
app.UseForwardedHeaders();

app.UseCors();

// Serve the bundled SPA from wwwroot/ in prod. In dev the SPA runs
// under Vite at :5173 and proxies /api/* to this host, so the
// API never needs to serve static files locally. In the container
// build the Dockerfile copies web/dist/ into wwwroot/ before
// `dotnet publish`, so UseStaticFiles + MapFallbackToFile is the
// pair that takes us from "white screen" to "SPA loads".
//
// UseDefaultFiles rewrites `/` requests to `/index.html` BEFORE
// UseStaticFiles so the root URL hits the file middleware. Both
// middlewares are no-ops when wwwroot/ is missing (dev runs).
app.UseDefaultFiles();
app.UseStaticFiles();

app.UseAuthentication();
app.UseAuthorization();
app.MapOpenApi().AllowAnonymous();

app.MapGet("/health", () => Results.Ok(new { status = "ok", service = "tamp.findings.api" }))
   .WithName("Health")
   .WithSummary("Liveness probe")
   .AllowAnonymous();

app.MapGet("/version", () => Results.Ok(new
{
    service = "tamp.findings.api",
    version = typeof(Program).Assembly.GetName().Version?.ToString() ?? "0.0.0",
}))
   .WithName("Version")
   .WithSummary("Build version")
   .AllowAnonymous();

// Auth surface — challenge, callback (registered by the OAuth handler at
// /auth/github/callback), /auth/me, /auth/logout, /auth/denied.
app.MapAuth();

// Ingest-token CRUD — SPA-facing, behind the cookie-auth fallback.
app.MapIngestTokens();

// Ingest endpoints — anonymous. Build script + future CI runners post to
// these from outside a browser; bearer-token auth for them is TFND-4
// follow-up work. Each endpoint flags itself .AllowAnonymous() to opt out
// of the FallbackPolicy.
app.MapIngest();
app.MapSbomIngest();
app.MapCoverageIngest();
app.MapScanRunIngest();
app.MapSbomEnrich();
app.MapSbomVulnerabilities();

// SPA-facing query endpoints — protected by the fallback policy
// (RequireAuthenticatedUser; see AuthExtensions).
app.MapCoverageDetail();
app.MapTestResults();
app.MapFindingsQuery();
app.MapFindingsList();
app.MapFindingsTree();
app.MapSbomComponents();
app.MapSuppressions();
app.MapRoleAssignments();
app.MapAggregates();
app.MapRiskPolicies();
app.MapProjectScanReceipts();
app.MapBuildEvaluation();
app.MapVexStatements();
app.MapPoamItems();
app.MapSsdfAttestation();
app.MapProjectVdp();
app.MapSbomProvenance();

// SPA fallback — any URL the API doesn't match (i.e. client-side
// routes like /projects/<id>/attestation) serves index.html so the
// React Router can pick it up on hydration. MUST come after all
// API routes; otherwise it would shadow them. AllowAnonymous so a
// signed-out visitor sees the SignInView rather than a 401.
app.MapFallbackToFile("index.html").AllowAnonymous();

app.Run();

// Surfaced for WebApplicationFactory<Program> in tests.
public partial class Program;
