using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Tamp.Findings.Data;

namespace Tamp.Findings.Integration.Tests;

/// <summary>
/// A host backed by a REAL Postgres.
///
/// Everything else in this repo is tested without a database, which leaves one
/// gap that kept recurring: the query layer. The project hub, scope inheritance
/// and suppression authoring were all verified by hand against a seeded
/// database and asserted only at the contract level, so a broken join or a
/// wrong slug comparison would have shipped green.
///
/// Opt-in by design. Set TAMP_FINDINGS_TEST_DB and these run; leave it unset
/// and they skip. That keeps `dotnet test` working on a machine with no Docker
/// while letting CI — which has one — run the real thing.
/// </summary>
public sealed class DatabaseFixture : IAsyncLifetime
{
    public const string ConnectionEnvVar = "TAMP_FINDINGS_TEST_DB";

    public string? ConnectionString { get; private set; }
    public WebApplicationFactory<Program>? Factory { get; private set; }

    /// <summary>
    /// True when a database is configured. Every test checks this and returns
    /// early rather than failing — a skipped test on a laptop is fine; a
    /// failing one people learn to ignore is not.
    /// </summary>
    public bool Available => ConnectionString is not null;

    public Task InitializeAsync()
    {
        ConnectionString = Environment.GetEnvironmentVariable(ConnectionEnvVar);
        if (ConnectionString is null) return Task.CompletedTask;

        Factory = new IntegrationFactory(ConnectionString);

        // Force host construction now, so a misconfigured connection string
        // fails here rather than inside the first test that touches it.
        using var scope = Factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<FindingsDbContext>();
        db.Database.Migrate();

        return Task.CompletedTask;
    }

    public Task DisposeAsync()
    {
        Factory?.Dispose();
        return Task.CompletedTask;
    }

    public IServiceScope Scope() => Factory!.Services.CreateScope();

    public FindingsDbContext Db(IServiceScope scope) =>
        scope.ServiceProvider.GetRequiredService<FindingsDbContext>();

    private sealed class IntegrationFactory(string connectionString) : WebApplicationFactory<Program>
    {
        protected override IHost CreateHost(IHostBuilder builder)
        {
            // The app migrates on startup, which is what we want here — it is
            // the same path a real deployment takes, so a broken migration
            // fails the suite rather than only failing production.
            Environment.SetEnvironmentVariable("TAMP_FINDINGS_DB", connectionString);
            Environment.SetEnvironmentVariable("TAMP_FINDINGS_SKIP_MIGRATE", "false");
            return base.CreateHost(builder);
        }
    }
}

[CollectionDefinition(Name)]
public sealed class DatabaseCollection : ICollectionFixture<DatabaseFixture>
{
    public const string Name = "database";
}
