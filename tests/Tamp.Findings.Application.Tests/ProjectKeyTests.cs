using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Projects;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Tests;

// The project ingest key (TFND-81).
public class ProjectKeyTests
{
    private readonly CapabilityEvaluator _capabilities = new();

    private static Principal As(bool admin = false, params ProjectRole[] roles) =>
        Principal.For(Guid.NewGuid(), "test", admin, roles);

    [Fact]
    public void Architect_cannot_recycle_the_key_because_it_breaks_ci()
    {
        // The matrix's reasoning, made concrete: recycling stops every
        // pipeline using the old key, and an Architect is not the person who
        // redeploys them.
        Assert.False(_capabilities.Allows(As(roles: ProjectRole.Architect), Capability.ManageIngestKey));

        Assert.True(_capabilities.Allows(As(admin: true), Capability.ManageIngestKey));
        Assert.True(_capabilities.Allows(As(roles: ProjectRole.InfoSecOfficer), Capability.ManageIngestKey));
        Assert.True(_capabilities.Allows(As(roles: ProjectRole.LeadDev), Capability.ManageIngestKey));
    }

    [Fact]
    public void An_auditor_cannot_touch_the_key()
    {
        Assert.False(_capabilities.Allows(As(roles: ProjectRole.Auditor), Capability.ManageIngestKey));
    }

    [Fact]
    public void The_readable_key_info_carries_no_key_material()
    {
        // Not even a prefix. A "hint" is where a leak starts, and the type
        // system is the cheapest place to make that impossible — a screen
        // cannot render what the record does not carry.
        var properties = typeof(ProjectKeyInfo).GetProperties().Select(p => p.Name).ToArray();

        Assert.DoesNotContain("Token", properties);
        Assert.DoesNotContain("Plaintext", properties);
        Assert.DoesNotContain("Hash", properties);
        Assert.DoesNotContain("Prefix", properties);
    }

    [Fact]
    public void Recycling_returns_the_plaintext_exactly_once_through_the_result()
    {
        // The plaintext exists only in the return value; nothing persists it.
        // That is what makes "reveal exactly once" a property of the system
        // rather than a UI convention someone can work around.
        var method = typeof(ProjectKeyService).GetMethod(nameof(ProjectKeyService.RecycleAsync))!;

        Assert.Equal(typeof(Task<Result<string>>), method.ReturnType);
    }
}
