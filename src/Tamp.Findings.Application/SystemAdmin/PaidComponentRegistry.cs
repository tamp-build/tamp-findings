using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Projects;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.SystemAdmin;

/// <summary>
/// The paid-component registry (TFND-8 / F7.2).
///
/// Instance-scoped, so it sits with the other System panels. The rows are
/// seeded with what is stable and checkable — vendor, package prefix, licence
/// model, pricing page — and DELIBERATELY not with prices. See
/// <see cref="PaidComponent.AnnualCostPerSeat"/>: a list price shipped in a
/// compliance tool becomes a figure quoted in somebody's budget meeting as
/// though this product knew what they pay.
/// </summary>
public sealed class PaidComponentRegistry
{
    private readonly FindingsDbContext _db;
    private readonly CapabilityEvaluator _capabilities;
    private readonly AuditLog _audit;

    public PaidComponentRegistry(
        FindingsDbContext db, CapabilityEvaluator capabilities, AuditLog audit)
    {
        _db = db;
        _capabilities = capabilities;
        _audit = audit;
    }

    public async Task<IReadOnlyList<PaidComponentRow>> ListAsync(
        DateTimeOffset asOf, CancellationToken ct = default)
    {
        var rows = await _db.PaidComponents.AsNoTracking().ToArrayAsync(ct);

        return rows
            .Select(r => new PaidComponentRow(
                r.Id, r.Vendor, r.Product, r.PackagePrefix, r.Ecosystem,
                r.AnnualCostPerSeat, r.Currency, r.CostAsOf,
                r.AnnualCostPerSeat is not null
                    && r.CostAsOf is not null
                    && (asOf - r.CostAsOf.Value).TotalDays > 365,
                r.LicenseModel, r.PricingUrl, r.SupportEndsAt, r.Notes,
                r.IsBuiltIn, r.Enabled))
            // Unpriced first: those are the ones asking for an operator's
            // attention, and the screen exists mostly to get them filled in.
            .OrderBy(r => r.AnnualCostPerSeat is not null)
            .ThenBy(r => r.Vendor, StringComparer.OrdinalIgnoreCase)
            .ThenBy(r => r.Product, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    /// <summary>
    /// Record what this instance actually pays, and whether an entry is live.
    ///
    /// The only fields an operator edits on a built-in row. Vendor and prefix
    /// are ours to keep correct across upgrades; the price is theirs and
    /// nothing here overwrites it.
    /// </summary>
    public async Task<Result<bool>> UpdateCostAsync(
        Principal actor, Guid id, decimal? annualCostPerSeat, string currency,
        DateTimeOffset? supportEndsAt, bool enabled, DateTimeOffset asOf,
        CancellationToken ct = default)
    {
        // The same capability that edits policy weights. Both change a number
        // this product then reports as though it were a finding, and both want
        // the same person deciding.
        var decision = _capabilities.Evaluate(actor, Capability.EditPolicyWeights);
        if (!decision.Allowed) return Result<bool>.Denied(decision.Reason!);

        if (annualCostPerSeat is < 0)
            return Result<bool>.Invalid("A cost cannot be negative.");

        currency = (currency ?? "").Trim().ToUpperInvariant();
        if (currency.Length is < 3 or > 8)
            return Result<bool>.Invalid("Use a currency code — USD, EUR, GBP.");

        var entry = await _db.PaidComponents.SingleOrDefaultAsync(p => p.Id == id, ct);
        if (entry is null) return Result<bool>.Invalid("That registry entry no longer exists.");

        var was = entry.AnnualCostPerSeat;

        entry.AnnualCostPerSeat = annualCostPerSeat;
        entry.Currency = currency;
        entry.SupportEndsAt = supportEndsAt;
        entry.Enabled = enabled;
        // Stamped on change rather than on save, so re-saving an unchanged row
        // does not launder a three-year-old figure into a fresh one.
        if (was != annualCostPerSeat) entry.CostAsOf = annualCostPerSeat is null ? null : asOf;
        entry.UpdatedAt = asOf;

        // Other, not Risk: a price is not a security posture. It still belongs
        // in the trail, because "who put that number on the budget screen" is a
        // question somebody eventually asks.
        _audit.Record(actor, "paid_component.updated", AuditClass.Other, ScopeTarget.Instance,
            subjectId: entry.Id, subjectKind: nameof(PaidComponent),
            detail: $"{entry.Vendor} {entry.Product}: "
                  + $"{Describe(was, entry.Currency)} → {Describe(annualCostPerSeat, currency)}"
                  + (enabled ? "" : " (disabled)"));

        await _db.SaveChangesAsync(ct);
        return Result<bool>.Ok(true);
    }

    /// <summary>
    /// Add a vendor this instance uses that the seed does not know about.
    /// </summary>
    public async Task<Result<Guid>> AddAsync(
        Principal actor, string vendor, string product, string packagePrefix, string? ecosystem,
        CancellationToken ct = default)
    {
        var decision = _capabilities.Evaluate(actor, Capability.EditPolicyWeights);
        if (!decision.Allowed) return Result<Guid>.Denied(decision.Reason!);

        vendor = (vendor ?? "").Trim();
        product = (product ?? "").Trim();
        packagePrefix = (packagePrefix ?? "").Trim();
        ecosystem = string.IsNullOrWhiteSpace(ecosystem) ? null : ecosystem.Trim().ToLowerInvariant();

        if (vendor.Length == 0 || product.Length == 0)
            return Result<Guid>.Invalid("A registry entry needs a vendor and a product.");

        if (packagePrefix.Length < 2)
        {
            // A one-character prefix matches most of a registry. The screen
            // reports what it matches as a cost, so an over-broad prefix is a
            // wrong number rather than a harmless one.
            return Result<Guid>.Invalid(
                "A package prefix needs at least two characters — a shorter one would match "
                + "most of an SBOM and report it all as paid.");
        }

        var clash = await _db.PaidComponents
            .AnyAsync(p => p.Ecosystem == ecosystem
                           && p.PackagePrefix.ToLower() == packagePrefix.ToLower(), ct);
        if (clash)
            return Result<Guid>.Invalid($"An entry already covers \"{packagePrefix}\" in that ecosystem.");

        var entry = new PaidComponent
        {
            Vendor = vendor,
            Product = product,
            PackagePrefix = packagePrefix,
            Ecosystem = ecosystem,
            IsBuiltIn = false,
        };
        _db.PaidComponents.Add(entry);

        _audit.Record(actor, "paid_component.added", AuditClass.Other, ScopeTarget.Instance,
            subjectId: entry.Id, subjectKind: nameof(PaidComponent),
            detail: $"{vendor} {product} matching {packagePrefix}* ({ecosystem ?? "any ecosystem"})");

        await _db.SaveChangesAsync(ct);
        return Result<Guid>.Ok(entry.Id);
    }

    public async Task<Result<bool>> RemoveAsync(
        Principal actor, Guid id, CancellationToken ct = default)
    {
        var decision = _capabilities.Evaluate(actor, Capability.EditPolicyWeights);
        if (!decision.Allowed) return Result<bool>.Denied(decision.Reason!);

        var entry = await _db.PaidComponents.SingleOrDefaultAsync(p => p.Id == id, ct);
        if (entry is null) return Result<bool>.Ok(false);

        if (entry.IsBuiltIn)
        {
            // Deleting it would only bring it back on the next upgrade, with
            // the operator's price gone. Disabling is the durable answer and
            // the one they meant.
            return Result<bool>.Invalid(
                "Built-in entries cannot be deleted — the next upgrade would re-seed this one and "
                + "lose the cost recorded against it. Disable it instead.");
        }

        _db.PaidComponents.Remove(entry);

        _audit.Record(actor, "paid_component.removed", AuditClass.Other, ScopeTarget.Instance,
            subjectId: entry.Id, subjectKind: nameof(PaidComponent),
            detail: $"{entry.Vendor} {entry.Product}");

        await _db.SaveChangesAsync(ct);
        return Result<bool>.Ok(true);
    }

    /// <summary>
    /// Bring the built-in rows up to date, without touching anything an
    /// operator owns.
    ///
    /// Run at startup. Vendor, product, prefix and pricing URL are ours to keep
    /// correct; the cost, the currency, the support date and the enabled flag
    /// are theirs, and this never writes them.
    /// </summary>
    public static async Task SeedAsync(FindingsDbContext db, CancellationToken ct = default)
    {
        var existing = await db.PaidComponents.ToDictionaryAsync(p => p.Id, ct);

        foreach (var seed in PaidComponentSeed.All())
        {
            if (existing.TryGetValue(seed.Id, out var row))
            {
                row.Vendor = seed.Vendor;
                row.Product = seed.Product;
                row.PackagePrefix = seed.PackagePrefix;
                row.Ecosystem = seed.Ecosystem;
                row.LicenseModel = seed.LicenseModel;
                row.PricingUrl = seed.PricingUrl;
                row.Notes = seed.Notes;
                row.IsBuiltIn = true;
                continue;
            }

            db.PaidComponents.Add(seed);
        }

        await db.SaveChangesAsync(ct);
    }

    private static string Describe(decimal? cost, string currency) =>
        cost is null ? "unpriced" : $"{currency} {cost:N0}";
}

public sealed record PaidComponentRow(
    Guid Id, string Vendor, string Product, string PackagePrefix, string? Ecosystem,
    decimal? AnnualCostPerSeat, string Currency, DateTimeOffset? CostAsOf, bool Stale,
    string? LicenseModel, string? PricingUrl, DateTimeOffset? SupportEndsAt, string? Notes,
    bool IsBuiltIn, bool Enabled);
