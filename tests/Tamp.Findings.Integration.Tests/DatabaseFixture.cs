using Microsoft.AspNetCore.Hosting;
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
        var baseConn = Environment.GetEnvironmentVariable(ConnectionEnvVar);
        if (baseConn is null) return Task.CompletedTask;

        // Own database, not the one Api.Tests uses (TFND-173).
        //
        // CI runs the whole solution in a single `dotnet test`, so this assembly
        // and Tamp.Findings.Api.Tests execute in parallel — and BOTH used to
        // Migrate() the SAME `tamp_findings_test` database. Two concurrent
        // Database.Migrate() calls against one database race: one writes the
        // migration-history row while the other is mid-DDL, and a column gets
        // skipped. It surfaced intermittently as
        //   42703: column "ActorId" of relation "ComponentVersions" does not exist
        // (the TFND-165 migration), reddening CI at random.
        //
        // Give this assembly a private database. EF's Migrate() creates it if it
        // does not exist, so no CREATE DATABASE plumbing is needed — the two
        // assemblies simply never touch the same schema again.
        ConnectionString = WithDatabaseSuffix(baseConn, "_integration");

        Factory = new IntegrationFactory(ConnectionString);

        // Force host construction now, so a misconfigured connection string
        // fails here rather than inside the first test that touches it.
        using var scope = Factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<FindingsDbContext>();
        db.Database.Migrate();

        return Task.CompletedTask;
    }

    // Rewrite the Database= key on a connection string, provider-agnostically.
    // DbConnectionStringBuilder parses the standard key/value form and indexes
    // keys case-insensitively, so it finds Database / Db regardless of casing.
    private static string WithDatabaseSuffix(string connectionString, string suffix)
    {
        var b = new System.Data.Common.DbConnectionStringBuilder { ConnectionString = connectionString };
        var key = b.ContainsKey("Database") ? "Database" : (b.ContainsKey("Db") ? "Db" : "Database");
        var current = b.TryGetValue(key, out var v) ? v?.ToString() : null;
        b[key] = (string.IsNullOrWhiteSpace(current) ? "tamp_findings_test" : current) + suffix;
        return b.ConnectionString;
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
        protected override void ConfigureWebHost(IWebHostBuilder builder) =>
            // HOST-LOCAL, not a process-global env var — a global set races the
            // other test hosts booting in parallel (TFND-173). Migration is left
            // ON (no skip-migrate setting): the app migrates this assembly's own
            // isolated database on startup, the same path a real deployment
            // takes, so a broken migration fails the suite rather than only
            // failing production.
            builder.UseSetting("ConnectionStrings:Findings", connectionString);
    }
}

[CollectionDefinition(Name)]
public sealed class DatabaseCollection : ICollectionFixture<DatabaseFixture>
{
    public const string Name = "database";
}
