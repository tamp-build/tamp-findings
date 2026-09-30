namespace Tamp.Findings.Domain.Entities;

/// <summary>
/// Seed pricing for the models a scan is likely to use (TFND-204). APPROXIMATE published list prices,
/// USD per 1,000,000 tokens — a starting point an admin corrects/extends; findings owns the table so a
/// fix re-flows through every historical scan's cost. Effective-from a single anchor date; add a newer
/// row (not edit in place) to change a price from a date forward.
/// </summary>
public static class ModelPriceDefaults
{
    // The anchor the seed prices are "effective from". A real price change is a NEW row from its date.
    public static readonly DateTimeOffset SeedEffectiveFrom = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    public static IReadOnlyList<ModelPrice> Build()
    {
        (string Model, string Provider, decimal In, decimal Out)[] rows =
        [
            ("claude-opus-5-5",   "anthropic", 15.00m, 75.00m),
            ("claude-opus-4-8",   "anthropic", 15.00m, 75.00m),
            ("claude-sonnet-5",   "anthropic",  3.00m, 15.00m),
            ("claude-haiku-4-5",  "anthropic",  0.80m,  4.00m),
            ("gpt-4o",            "openai",     2.50m, 10.00m),
            ("gpt-4o-mini",       "openai",     0.15m,  0.60m),
        ];
        return rows.Select(r => new ModelPrice
        {
            ModelId = r.Model,
            Provider = r.Provider,
            InputPerMillion = r.In,
            OutputPerMillion = r.Out,
            Currency = "USD",
            EffectiveFrom = SeedEffectiveFrom,
            IsSeeded = true,
        }).ToList();
    }
}
