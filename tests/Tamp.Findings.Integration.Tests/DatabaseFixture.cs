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

        // Migrate and empty BEFORE the host exists, using a standalone context.
        //
        // Order matters and got this wrong once. The host's startup seeds real reference
        // content — the shipped OSCAL control catalog, the frameworks, the EO mandate
        // corpus — and that seeding happens when the host is first constructed. Emptying
        // the database afterwards deleted all of it. Nothing failed at the time, because
        // no test then depended on seeded content, which made it a trap rather than a
        // bug: the first test to need the catalog found none. Emptying first means the
        // host seeds into a clean database and tests see a realistic instance.
        using (var standalone = new FindingsDbContext(
            new DbContextOptionsBuilder<FindingsDbContext>().UseNpgsql(ConnectionString).Options))
        {
            standalone.Database.Migrate();
            EmptyEveryTable(standalone);
        }

        Factory = new IntegrationFactory(ConnectionString);

        // Force host construction now, so a misconfigured connection string fails here
        // rather than inside the first test that touches it — and so the startup seeding
        // has run before any test reads it.
        using var scope = Factory.Services.CreateScope();
        _ = scope.ServiceProvider.GetRequiredService<FindingsDbContext>();

        return Task.CompletedTask;
    }

    /// <summary>
    /// Empty the database once per assembly run, after migrating.
    ///
    /// Nothing used to clean up, so locally this database only ever grew: a developer
    /// machine reached 14,847 projects and 12,199 clients accumulated over repeated
    /// runs. CI never noticed, because its Postgres is a fresh service container every
    /// time — which is exactly what made the symptoms look environmental.
    ///
    /// They were not. Any test that renders or queries something INSTANCE-WIDE scales
    /// with that junk: an instance admin's portfolio loads every project there is. So
    /// those tests got slower on every run until they timed out. That is the real story
    /// behind PageARenderSweepTests.Admin_renders_every_group_a_route failing locally at
    /// ~1m42s with a client abort while passing in CI, and it is why a component test
    /// that renders Portfolio as an admin could not finish inside 90 seconds.
    ///
    /// Truncating is safe because no migration seeds anything — there is not one HasData
    /// call in the model, and every test builds the world it needs. Doing it once at
    /// assembly init rather than per test is what keeps the parallel collections
    /// working: they share this fixture, and a per-test wipe would delete a concurrent
    /// test's rows out from under it.
    /// </summary>
    private static void EmptyEveryTable(FindingsDbContext db) =>
        db.Database.ExecuteSqlRaw(
            "DO $$ DECLARE t text; BEGIN " +
            "  FOR t IN SELECT tablename FROM pg_tables " +
            "           WHERE schemaname = 'public' AND tablename <> '__EFMigrationsHistory' " +
            "  LOOP EXECUTE format('TRUNCATE TABLE %I CASCADE', t); END LOOP; " +
            "END $$;");

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
