namespace Tamp.Findings.Domain.Entities;

/// <summary>
/// One entry on the global unauthorized-component list (CM-8(3), TFND-211): a package that must not be
/// present in any build's SBOM. Keyed by the version-less purl; <see cref="Versions"/> narrows it to
/// specific versions (empty = every version). Entries are either hand-authored by an admin or synced
/// from a malicious-package feed (OSV <c>MAL-*</c> advisories), distinguished by <see cref="Source"/>.
/// </summary>
public sealed class BannedComponent
{
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>Version-less package url, lower-cased type, e.g. <c>pkg:npm/evil-pkg</c>, <c>pkg:nuget/Bunifu.Form</c>.</summary>
    public required string Purl { get; set; }

    /// <summary>Exact affected versions. Empty means all versions are banned.</summary>
    public List<string> Versions { get; set; } = [];

    public BannedComponentKind Kind { get; set; } = BannedComponentKind.Banned;

    /// <summary><c>manual</c> or the feed name (<c>osv-malicious</c>).</summary>
    public required string Source { get; set; }

    /// <summary>The upstream advisory id (e.g. <c>MAL-2024-11505</c>); null for manual entries.</summary>
    public string? SourceId { get; set; }

    public string? Reason { get; set; }
    public bool Active { get; set; } = true;
    public string? AddedByLogin { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
}

public enum BannedComponentKind
{
    /// <summary>The org decided this package is not permitted.</summary>
    Banned = 0,

    /// <summary>A feed reports this package as malicious (typosquat, backdoor, dependency-confusion payload).</summary>
    Malicious = 1,
}
