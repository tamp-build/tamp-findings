using Tamp.Findings.Data;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();

// Postgres connection comes from configuration. In dev the bundled
// docker-compose Postgres exposes this on localhost:5432; in prod, set
// TAMP_FINDINGS_DB or ConnectionStrings:Findings to point at a real Postgres.
var connectionString =
    builder.Configuration["ConnectionStrings:Findings"]
    ?? Environment.GetEnvironmentVariable("TAMP_FINDINGS_DB")
    ?? "Host=localhost;Port=5432;Database=tamp_findings;Username=tamp;Password=tamp";

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

app.Run();

// Surfaced for WebApplicationFactory<Program> in tests.
public partial class Program;
