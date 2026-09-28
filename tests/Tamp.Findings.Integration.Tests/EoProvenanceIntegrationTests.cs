using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Eo;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Integration.Tests;

// tamp-EOProvenance (ADR 0011). Exercises the ingestion pipeline + the point-in-time
// engine against a real DB, on the worked example the whole design turns on: EO 14306
// striking directives of EO 14144, forward-dated, never deleted. Uses run-unique
// identifiers so it coexists with the shipped corpus the app seeds on startup.
[Collection(DatabaseCollection.Name)]
public class EoProvenanceIntegrationTests
{
    private readonly DatabaseFixture _fx;
    public EoProvenanceIntegrationTests(DatabaseFixture fx) => _fx = fx;

    private static EoCorpus BuildCorpus(string s) => new()
    {
        Version = $"test-{s}",
        Instruments =
        [
            new() { Identifier = $"EO T{s}-028", Title = "foundational", Type = "ExecutiveOrder", IssueDate = D("2021-05-12"), ReviewStatus = "Reviewed" },
            new() { Identifier = $"EO T{s}-144", Title = "late", Type = "ExecutiveOrder", IssueDate = D("2025-01-16"), ReviewStatus = "Reviewed" },
            new() { Identifier = $"EO T{s}-306", Title = "amender", Type = "ExecutiveOrder", IssueDate = D("2025-06-06"), ReviewStatus = "Reviewed",
                    Relations = [ new() { Type = "Amends", To = $"EO T{s}-144" } ] },
            new() { Identifier = $"M T{s}-09", Title = "zt strategy", Type = "OmbMemo", IssueDate = D("2022-01-26"), ReviewStatus = "Reviewed",
                    Relations = [ new() { Type = "Implements", To = $"EO T{s}-028" } ] },
        ],
        Directives =
        [
            new() { Ref = $"{s}-mfa", Instrument = $"M T{s}-09", Who = "agencies", MustDo = "MFA", Type = "SelfExecutingDated",
                    ByWhen = new() { Kind = "Absolute", Date = D("2024-09-30") }, Crosswalk = new() { Target = "Ztt", Ref = $"mfa-{s}" }, ReviewStatus = "Reviewed" },
            new() { Ref = $"{s}-struck", Instrument = $"EO T{s}-144", Who = "CISA", MustDo = "machine-readable attestation", Type = "SelfExecutingDated",
                    ByWhen = new() { Kind = "Relative", OffsetDays = 365, Anchor = "SigningDate" }, Crosswalk = new() { Target = "Findings", Ref = $"attest-{s}" }, ReviewStatus = "Reviewed" },
            new() { Ref = $"{s}-pending", Instrument = $"EO T{s}-144", Who = "agencies", MustDo = "await predicate memo", Type = "Delegation",
                    ByWhen = new() { Kind = "Relative", OffsetDays = 90, Anchor = "PredicateMemoIssue", AnchorInstrument = $"M T{s}-absent" }, ReviewStatus = "Reviewed" },
        ],
        Rescissions =
        [
            new() { ByInstrument = $"EO T{s}-306", EffectiveDate = D("2025-06-06"), Directives = [ $"{s}-struck" ] },
        ],
    };

    private static DateTimeOffset D(string d) => DateTimeOffset.Parse(d);

    [SkippableFact]
    public async Task Seeds_resolves_dates_rescinds_forward_and_answers_point_in_time()
    {
        Skip.IfNot(_fx.Available);
        var s = Guid.NewGuid().ToString("N")[..6];

        using (var scope = _fx.Scope())
            await EoCorpusSeeder.SeedAsync(_fx.Db(scope), BuildCorpus(s));

        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);

            // Instruments + authority graph.
            var amender = await db.Instruments.SingleAsync(i => i.Identifier == $"EO T{s}-306");
            var amended = await db.Instruments.SingleAsync(i => i.Identifier == $"EO T{s}-144");
            Assert.True(await db.InstrumentRelations.AnyAsync(r =>
                r.FromInstrumentId == amender.Id && r.ToInstrumentId == amended.Id && r.Type == InstrumentRelationType.Amends));

            // Date-anchor: relative-to-signing resolves; predicate-absent stays Pending.
            var struck = await db.Directives.SingleAsync(d => d.Ref == $"{s}-struck");
            Assert.Equal(ByWhenKind.Relative, struck.ByWhenKind);
            Assert.Equal(D("2025-01-16").AddDays(365), struck.ResolvedDate);
            var pending = await db.Directives.SingleAsync(d => d.Ref == $"{s}-pending");
            Assert.Equal(ByWhenKind.Pending, pending.ByWhenKind);
            Assert.Null(pending.ResolvedDate);

            // Crosswalk recorded with the right analyzer.
            var cx = await db.DirectiveCrosswalks.SingleAsync(c => c.DirectiveId == struck.Id);
            Assert.Equal(MandateTool.Findings, cx.Target);
            Assert.Equal($"attest-{s}", cx.TargetRef);

            // Point-in-time: the struck directive was in force before the rescind and
            // dormant after — never deleted.
            var q = scope.ServiceProvider.GetRequiredService<EoRegistryQuery>();
            var before = await q.InForceAsOfAsync(D("2025-05-01"));
            Assert.Contains(before, v => v.Ref == $"{s}-struck");
            var after = await q.InForceAsOfAsync(D("2025-07-01"));
            Assert.DoesNotContain(after, v => v.Ref == $"{s}-struck");
            var afterAll = await q.AsOfAsync(D("2025-07-01"));
            Assert.Equal(DirectiveStatus.Rescinded, afterAll.Single(v => v.Ref == $"{s}-struck").Status);

            // The row is preserved (append-only history), not deleted.
            Assert.Equal(2, await db.DirectiveStatusChanges.CountAsync(c => c.DirectiveId == struck.Id));
        }

        // Idempotent: re-seeding does not duplicate status changes.
        using (var scope = _fx.Scope())
            await EoCorpusSeeder.SeedAsync(_fx.Db(scope), BuildCorpus(s));
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var struck = await db.Directives.SingleAsync(d => d.Ref == $"{s}-struck");
            Assert.Equal(2, await db.DirectiveStatusChanges.CountAsync(c => c.DirectiveId == struck.Id));
        }
    }

    [SkippableFact]
    public async Task Draft_directives_do_not_enter_the_in_force_set()
    {
        Skip.IfNot(_fx.Available);
        var s = Guid.NewGuid().ToString("N")[..6];
        var corpus = BuildCorpus(s);
        corpus.Directives.Add(new() { Ref = $"{s}-draft", Instrument = $"M T{s}-09", Who = "x", MustDo = "unreviewed",
            Type = "SelfExecutingDated", ByWhen = new() { Kind = "Absolute", Date = D("2024-01-01") }, ReviewStatus = "Draft" });

        using (var scope = _fx.Scope())
            await EoCorpusSeeder.SeedAsync(_fx.Db(scope), corpus);

        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var draft = await db.Directives.SingleAsync(d => d.Ref == $"{s}-draft");
            // Fail-closed: no Active status change was written for a Draft directive.
            Assert.Equal(0, await db.DirectiveStatusChanges.CountAsync(c => c.DirectiveId == draft.Id));
            var q = scope.ServiceProvider.GetRequiredService<EoRegistryQuery>();
            Assert.DoesNotContain(await q.AsOfAsync(DateTimeOffset.UtcNow), v => v.Ref == $"{s}-draft");
        }
    }
}
