using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Data;

namespace Tamp.Findings.Application.Costs;

/// <summary>
/// Per-project LLM scan cost (TFND-204). Rolls up the usage observations across a project's builds and
/// prices each against the dated <see cref="Domain.Entities.ModelPrice"/> table — the price in effect
/// when the scan RAN, so a later pricing correction re-flows without re-ingesting. A model with no
/// price row is surfaced (UnpricedModels) rather than silently costed at zero.
/// </summary>
public sealed class ScanCostQuery(FindingsDbContext db)
{
    public async Task<ScanCostSummary?> ForProjectAsync(Guid projectId, CancellationToken ct = default)
    {
        var usage = await db.ScanUsageObservations.AsNoTracking()
            .Where(u => u.ComponentVersion!.ProjectId == projectId)
            .Select(u => new { u.ModelId, u.InputTokens, u.OutputTokens, u.ObservedAt, CommitSha = u.ComponentVersion!.CommitSha })
            .ToListAsync(ct);
        if (usage.Count == 0) return null;

        var prices = await db.ModelPrices.AsNoTracking().ToListAsync(ct);
        Domain.Entities.ModelPrice? PriceFor(string model, DateTimeOffset at) =>
            prices.Where(x => x.ModelId == model && x.EffectiveFrom <= at)
                  .OrderByDescending(x => x.EffectiveFrom).FirstOrDefault();

        long totalIn = 0, totalOut = 0;
        decimal totalCost = 0m;
        var unpriced = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var byModel = new Dictionary<string, (long In, long Out, decimal Cost)>();

        foreach (var u in usage)
        {
            totalIn += u.InputTokens;
            totalOut += u.OutputTokens;
            var p = PriceFor(u.ModelId, u.ObservedAt);
            decimal c = p is null ? 0m
                : u.InputTokens / 1_000_000m * p.InputPerMillion + u.OutputTokens / 1_000_000m * p.OutputPerMillion;
            if (p is null) unpriced.Add(u.ModelId);
            totalCost += c;
            var cur = byModel.GetValueOrDefault(u.ModelId);
            byModel[u.ModelId] = (cur.In + u.InputTokens, cur.Out + u.OutputTokens, cur.Cost + c);
        }

        var models = byModel
            .Select(kv => new ModelCost(kv.Key, kv.Value.In, kv.Value.Out, kv.Value.Cost))
            .OrderByDescending(m => m.Cost).ThenByDescending(m => m.InputTokens + m.OutputTokens)
            .ToList();

        return new ScanCostSummary(
            totalIn, totalOut, totalCost, "USD",
            models, usage.Select(u => u.CommitSha).Distinct().Count(), usage.Count,
            unpriced.ToArray());
    }
}

public sealed record ScanCostSummary(
    long InputTokens, long OutputTokens, decimal TotalCost, string Currency,
    IReadOnlyList<ModelCost> ByModel, int Builds, int Observations, IReadOnlyList<string> UnpricedModels);

public sealed record ModelCost(string ModelId, long InputTokens, long OutputTokens, decimal Cost);
