using System.Text.Json.Serialization;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Endpoints;
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

builder.Services.AddCors(options =>
{
    // Vite dev server origin during POC. Tighten before any non-local deployment.
    options.AddDefaultPolicy(p =>
        p.WithOrigins("http://localhost:5173")
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
app.MapFindingsQuery();

app.Run();

// Surfaced for WebApplicationFactory<Program> in tests.
public partial class Program;
