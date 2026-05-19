using System.Text.Json.Serialization;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Endpoints;
using Tamp.Findings.Api.Services;
using Tamp.Findings.Data;

var builder = WebApplication.CreateBuilder(args);

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

builder.Services.AddCors(options =>
{
    // POC dev posture: any origin allowed. The SPA uses Vite's /api proxy
    // so same-origin via the dev server is the normal path — this opens
    // direct API access for ad-hoc curl from other machines, the MCP
    // server, and any future tools. Tighten to an allow-list before any
    // non-local deployment (and definitely before OIDC + tokens land).
    options.AddDefaultPolicy(p =>
        p.AllowAnyOrigin()
         .AllowAnyHeader()
         .AllowAnyMethod());
});

var app = builder.Build();

// Run pending migrations on startup so adopters don't need to remember
// `dotnet ef`. Test hosts opt out via the TAMP_FINDINGS_SKIP_MIGRATE env var.
if (Environment.GetEnvironmentVariable("TAMP_FINDINGS_SKIP_MIGRATE") != "true")
{
    using var scope = app.Services.CreateScope();
    var db = scope.ServiceProvider.GetRequiredService<FindingsDbContext>();
    db.Database.Migrate();
}

app.UseCors();
app.MapOpenApi();

app.MapGet("/health", () => Results.Ok(new { status = "ok", service = "tamp.findings.api" }))
   .WithName("Health")
   .WithSummary("Liveness probe");

app.MapGet("/version", () => Results.Ok(new
{
    service = "tamp.findings.api",
    version = typeof(Program).Assembly.GetName().Version?.ToString() ?? "0.0.0",
}))
   .WithName("Version")
   .WithSummary("Build version");

app.MapIngest();
app.MapSbomIngest();
app.MapFindingsQuery();
app.MapFindingsList();
app.MapSbomComponents();
app.MapSuppressions();
app.MapRoleAssignments();
app.MapAggregates();
app.MapSbomEnrich();

app.Run();

// Surfaced for WebApplicationFactory<Program> in tests.
public partial class Program;
