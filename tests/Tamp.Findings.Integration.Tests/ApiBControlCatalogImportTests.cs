using System.Net;
using System.Net.Http.Json;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Domain.Compliance;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;
using static Tamp.Findings.Integration.Tests.ApiAHarness;

namespace Tamp.Findings.Integration.Tests;

/// <summary>
/// Importing a control catalog over HTTP (TFND-180, v3 §6).
///
/// The /system/frameworks page has shipped since September with two disabled buttons
/// promising this ticket. The import itself already worked — but only at startup, from
/// the file that ships in Content/oscal, with the logic inline in Program.cs where no
/// second caller could reach it.
///
/// Every test here restores the catalog that was current when it started. These run
/// against a SHARED database, and the whole point of an import is that it retires the
/// current catalog — which every control-coverage and compliance-profile test resolves
/// against. Leaving a test catalog current would break them from a distance.
/// </summary>
[Collection(DatabaseCollection.Name)]
public class ApiBControlCatalogImportTests
{
    private readonly DatabaseFixture _fx;
    public ApiBControlCatalogImportTests(DatabaseFixture fx) => _fx = fx;

    private const string Catalog = """
    {"catalog":{"metadata":{"version":"9.9.9","oscal-version":"1.2.2"},"groups":[
      {"id":"cm","title":"Configuration Management","controls":[
        {"id":"cm-6","title":"Configuration Settings",
         "parts":[{"name":"statement","prose":"Establish settings for [Assignment: organization-defined components]."}]}
      ]},
      {"id":"sc","title":"System and Communications Protection","controls":[
        {"id":"sc-7","title":"Boundary Protection","parts":[{"name":"statement","prose":"Protect the boundary."}]}
      ]}
    ]}}
    """;

    private const string LowProfile = """
    {"profile":{"imports":[{"href":"catalog.json","include-controls":[{"with-ids":["cm-6"]}]}]}}
    """;

    private const string EmptyCatalog = """
    {"catalog":{"metadata":{"version":"0.0.1","oscal-version":"1.2.2"},"groups":[]}}
    """;

    private async Task<HttpClient> AdminAsync() => Http(_fx, await UserAsync(_fx, admin: true));

    /// <summary>
    /// Run a body that imports, then put the database back: the catalog that was current
    /// before is current again, and anything the body created is gone.
    /// </summary>
    private async Task RestoringCatalogAsync(Func<Task> body)
    {
        Guid? wasCurrent;
        HashSet<Guid> before;
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            wasCurrent = (await db.ControlCatalogs.FirstOrDefaultAsync(c => c.IsCurrent))?.Id;
            before = (await db.ControlCatalogs.Select(c => c.Id).ToListAsync()).ToHashSet();
        }

        try
        {
            await body();
        }
        finally
        {
            using var scope = _fx.Scope();
            var db = _fx.Db(scope);
            var added = await db.ControlCatalogs.Where(c => !before.Contains(c.Id)).ToListAsync();
            db.ControlCatalogs.RemoveRange(added);
            await db.SaveChangesAsync();

            if (wasCurrent is { } id && await db.ControlCatalogs.FindAsync(id) is { } prior)
            {
                prior.IsCurrent = true;
                await db.SaveChangesAsync();
            }
        }
    }

    private static MultipartFormDataContent Upload(string catalog, string? lowProfile = null)
    {
        var form = new MultipartFormDataContent();
        form.Add(new ByteArrayContent(Encoding.UTF8.GetBytes(catalog)), "catalog", "catalog.json");
        if (lowProfile is not null)
            form.Add(new ByteArrayContent(Encoding.UTF8.GetBytes(lowProfile)), "baseline-low", "low.json");
        return form;
    }

    [SkippableFact]
    public async Task An_uploaded_catalog_becomes_the_current_one_and_reports_what_it_holds()
    {
        Skip.IfNot(_fx.Available);
        await RestoringCatalogAsync(async () =>
        {
            var admin = await AdminAsync();

            var response = await admin.PostAsync("/system/control-catalog", Upload(Catalog, LowProfile));

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var body = await response.Content.ReadFromJsonAsync<Dictionary<string, object>>();

            Assert.Equal("9.9.9", body!["version"].ToString());
            Assert.Equal("1.2.2", body["oscalVersion"].ToString());
            Assert.Equal("2", body["controls"].ToString());
            Assert.Equal("False", body["unchanged"].ToString(), ignoreCase: true);

            // Baseline membership is REAL — read from the profile, not approximated. Only
            // cm-6 is in the Low profile.
            Assert.Equal("1", body["low"].ToString());

            // The parameter count is computed by the depth-counting parser, not stored.
            Assert.Equal("1", body["parameters"].ToString());

            using var scope = _fx.Scope();
            var current = await _fx.Db(scope).ControlCatalogs.SingleAsync(c => c.IsCurrent);
            Assert.Equal("9.9.9", current.Version);
            Assert.Contains("catalog.json", current.Source, StringComparison.Ordinal);
        });
    }

    [SkippableFact]
    public async Task Re_uploading_the_same_bytes_changes_nothing_and_says_so()
    {
        Skip.IfNot(_fx.Available);
        await RestoringCatalogAsync(async () =>
        {
            var admin = await AdminAsync();
            await admin.PostAsync("/system/control-catalog", Upload(Catalog));

            int rowsAfterFirst;
            using (var scope = _fx.Scope())
                rowsAfterFirst = await _fx.Db(scope).ControlCatalogs.CountAsync();

            var again = await admin.PostAsync("/system/control-catalog", Upload(Catalog));
            var body = await again.Content.ReadFromJsonAsync<Dictionary<string, object>>();

            // Reported, not silently treated as success: an operator who just uploaded a
            // file to fix something needs to know it changed nothing.
            Assert.Equal(HttpStatusCode.OK, again.StatusCode);
            Assert.Equal("True", body!["unchanged"].ToString(), ignoreCase: true);

            using var after = _fx.Scope();
            Assert.Equal(rowsAfterFirst, await _fx.Db(after).ControlCatalogs.CountAsync());
        });
    }

    [SkippableFact]
    public async Task The_prior_catalog_is_retained_so_a_signed_attestation_stays_reproducible()
    {
        Skip.IfNot(_fx.Available);
        await RestoringCatalogAsync(async () =>
        {
            var admin = await AdminAsync();

            Guid priorId;
            using (var scope = _fx.Scope())
                priorId = (await _fx.Db(scope).ControlCatalogs.SingleAsync(c => c.IsCurrent)).Id;

            await admin.PostAsync("/system/control-catalog", Upload(Catalog));

            using var after = _fx.Scope();
            var db = _fx.Db(after);

            // Still there, no longer current. An attestation cites the catalog version it
            // was signed against, so deleting this row would make it unreproducible.
            var prior = await db.ControlCatalogs.FindAsync(priorId);
            Assert.NotNull(prior);
            Assert.False(prior!.IsCurrent);

            // And exactly one is current, which the partial unique index also enforces.
            Assert.Equal(1, await db.ControlCatalogs.CountAsync(c => c.IsCurrent));
        });
    }

    [SkippableFact]
    public async Task Without_profiles_nothing_claims_baseline_membership()
    {
        Skip.IfNot(_fx.Available);
        await RestoringCatalogAsync(async () =>
        {
            // Uploading a catalog alone is allowed — it still carries every control and
            // parameter. What it cannot carry is baseline membership, and the honest
            // result is "in no baseline" rather than a guess.
            var admin = await AdminAsync();

            var response = await admin.PostAsync("/system/control-catalog", Upload(Catalog));
            var body = await response.Content.ReadFromJsonAsync<Dictionary<string, object>>();

            Assert.Equal("0", body!["low"].ToString());
            Assert.Equal("0", body["moderate"].ToString());
            Assert.Equal("0", body["high"].ToString());
        });
    }

    // ---- what must not get through ------------------------------------------

    [SkippableFact]
    public async Task A_catalog_with_no_controls_is_refused()
    {
        Skip.IfNot(_fx.Available);
        await RestoringCatalogAsync(async () =>
        {
            // It parses perfectly. Accepting it would retire the real catalog and quietly
            // empty every framework and control-coverage view on the instance.
            var admin = await AdminAsync();
            Guid priorId;
            using (var scope = _fx.Scope())
                priorId = (await _fx.Db(scope).ControlCatalogs.SingleAsync(c => c.IsCurrent)).Id;

            var response = await admin.PostAsync("/system/control-catalog", Upload(EmptyCatalog));

            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Contains("no controls", await response.Content.ReadAsStringAsync(), StringComparison.OrdinalIgnoreCase);

            using var after = _fx.Scope();
            Assert.Equal(priorId, (await _fx.Db(after).ControlCatalogs.SingleAsync(c => c.IsCurrent)).Id);
        });
    }

    [SkippableFact]
    public async Task A_file_that_is_not_an_OSCAL_catalog_is_refused_and_says_what_it_was_not()
    {
        Skip.IfNot(_fx.Available);
        await RestoringCatalogAsync(async () =>
        {
            var admin = await AdminAsync();
            Guid priorId;
            using (var scope = _fx.Scope())
                priorId = (await _fx.Db(scope).ControlCatalogs.SingleAsync(c => c.IsCurrent)).Id;

            var response = await admin.PostAsync("/system/control-catalog", Upload("this is not json at all"));

            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Contains("OSCAL", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);

            using var after = _fx.Scope();
            Assert.Equal(priorId, (await _fx.Db(after).ControlCatalogs.SingleAsync(c => c.IsCurrent)).Id);
        });
    }

    [SkippableFact]
    public async Task A_request_with_no_file_is_refused()
    {
        Skip.IfNot(_fx.Available);
        var admin = await AdminAsync();

        var response = await admin.PostAsync("/system/control-catalog", new MultipartFormDataContent());

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [SkippableFact]
    public async Task An_auditor_cannot_replace_the_catalog()
    {
        Skip.IfNot(_fx.Available);

        // Importing a catalog replaces instance-wide reference content that every client
        // and project resolves against — the same authority that applies a policy pack
        // (EditPolicyWeights), not a reading role.
        var tree = await ClientProjectAsync(_fx);
        var userId = await UserAsync(_fx, admin: false);
        await GrantAsync(_fx, userId, ProjectRole.Auditor, tree.ClientId, null);

        var response = await Http(_fx, userId)
            .PostAsync("/system/control-catalog", Upload(Catalog));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [SkippableFact]
    public async Task An_anonymous_caller_cannot_replace_the_catalog()
    {
        Skip.IfNot(_fx.Available);

        var response = await Http(_fx, null).PostAsync("/system/control-catalog", Upload(Catalog));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [SkippableFact]
    public async Task The_import_is_audited_with_what_it_brought_in()
    {
        Skip.IfNot(_fx.Available);
        await RestoringCatalogAsync(async () =>
        {
            var admin = await AdminAsync();

            await admin.PostAsync("/system/control-catalog", Upload(Catalog, LowProfile));

            using var scope = _fx.Scope();
            var db = _fx.Db(scope);
            var catalogId = (await db.ControlCatalogs.SingleAsync(c => c.IsCurrent)).Id;
            var entry = await db.AuditEntries.SingleAsync(
                a => a.SubjectId == catalogId && a.Action == "controlcatalog.imported");

            Assert.Equal(nameof(ControlCatalog), entry.SubjectKind);
            Assert.Contains("2 controls", entry.Detail!, StringComparison.Ordinal);
        });
    }
}
