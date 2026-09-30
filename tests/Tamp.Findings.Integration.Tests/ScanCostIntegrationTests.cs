using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Costs;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Integration.Tests;

// TFND-204: per-project LLM scan cost. Findings owns the dated price table and computes cost from the
// price in effect when the scan ran; a model with no price is surfaced, not silently zero.
[Collection(DatabaseCollection.Name)]
public class ScanCostIntegrationTests
{
    private readonly DatabaseFixture _fx;
    public ScanCostIntegrationTests(DatabaseFixture fx) => _fx = fx;

    [SkippableFact]
    public async Task Costs_usage_against_the_price_in_effect_when_it_ran()
    {
        Skip.IfNot(_fx.Available);
        var s = Guid.NewGuid().ToString("N")[..8];
        Guid projectId;
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var client = new Client { Name = $"sc-{s}" };
            db.Clients.Add(client);
            var project = new Project { ClientId = client.Id, Name = $"scp-{s}" };
            db.Projects.Add(project);
            var cv = new ComponentVersion { ProjectId = project.Id, VersionString = "1.0.0", CommitSha = $"{s}sha", BranchName = "main" };
            db.ComponentVersions.Add(cv);

            var model = $"test-model-{s}";
            // Old price, then a newer price from mid-year.
            db.ModelPrices.Add(new ModelPrice { ModelId = model, InputPerMillion = 10m, OutputPerMillion = 30m, EffectiveFrom = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero) });
            db.ModelPrices.Add(new ModelPrice { ModelId = model, InputPerMillion = 20m, OutputPerMillion = 60m, EffectiveFrom = new DateTimeOffset(2026, 6, 1, 0, 0, 0, TimeSpan.Zero) });

            // One scan in Feb (old price), one in July (new price).
            db.ScanUsageObservations.Add(new ScanUsageObservation
            {
                ComponentVersionId = cv.Id, Adapter = "adr-conformance", ModelId = model,
                InputTokens = 1_000_000, OutputTokens = 500_000,
                ObservedAt = new DateTimeOffset(2026, 2, 1, 0, 0, 0, TimeSpan.Zero),
            });
            db.ScanUsageObservations.Add(new ScanUsageObservation
            {
                ComponentVersionId = cv.Id, Adapter = "adr-conformance", ModelId = model,
                InputTokens = 1_000_000, OutputTokens = 500_000,
                ObservedAt = new DateTimeOffset(2026, 7, 1, 0, 0, 0, TimeSpan.Zero),
            });
            await db.SaveChangesAsync();
            projectId = project.Id;
        }

        using (var scope = _fx.Scope())
        {
            var q = scope.ServiceProvider.GetRequiredService<ScanCostQuery>();
            var sc = await q.ForProjectAsync(projectId);
            Assert.NotNull(sc);
            Assert.Equal(2_000_000, sc!.InputTokens);
            Assert.Equal(1_000_000, sc.OutputTokens);
            // Feb: 1M*10 + 0.5M*30 = 25. Jul: 1M*20 + 0.5M*60 = 50. Total 75 — priced by-era.
            Assert.Equal(75m, sc.TotalCost);
            Assert.Empty(sc.UnpricedModels);
            Assert.Single(sc.ByModel);
        }
    }

    [SkippableFact]
    public async Task An_unpriced_model_is_surfaced_not_silently_zero()
    {
        Skip.IfNot(_fx.Available);
        var s = Guid.NewGuid().ToString("N")[..8];
        Guid projectId;
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var client = new Client { Name = $"sc2-{s}" };
            db.Clients.Add(client);
            var project = new Project { ClientId = client.Id, Name = $"scp2-{s}" };
            db.Projects.Add(project);
            var cv = new ComponentVersion { ProjectId = project.Id, VersionString = "1.0.0", CommitSha = $"{s}sha2", BranchName = "main" };
            db.ComponentVersions.Add(cv);
            db.ScanUsageObservations.Add(new ScanUsageObservation
            {
                ComponentVersionId = cv.Id, Adapter = "x", ModelId = $"unknown-model-{s}",
                InputTokens = 1000, OutputTokens = 1000, ObservedAt = DateTimeOffset.UtcNow,
            });
            await db.SaveChangesAsync();
            projectId = project.Id;
        }
        using (var scope = _fx.Scope())
        {
            var sc = await scope.ServiceProvider.GetRequiredService<ScanCostQuery>().ForProjectAsync(projectId);
            Assert.NotNull(sc);
            Assert.Equal(0m, sc!.TotalCost);
            Assert.Single(sc.UnpricedModels);   // named, so it's fixable, not hidden
        }
    }
}
