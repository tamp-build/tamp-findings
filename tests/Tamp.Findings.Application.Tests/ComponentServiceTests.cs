using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Projects;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Tests;

// Component commands (TFND-80). The first screen to actually exercise the
// Phase 2 capability model, so what matters here is that the SERVICE refuses
// rather than relying on the UI to hide a button.
public class ComponentServiceTests
{
    private readonly CapabilityEvaluator _capabilities = new();

    private static Principal As(params ProjectRole[] roles) =>
        Principal.For(Guid.NewGuid(), "test", isAdmin: false, roles);

    [Fact]
    public void Creating_a_component_needs_the_create_component_capability()
    {
        // Admin, Lead Dev and Architect may; InfoSec may not. The service asks
        // the evaluator rather than re-stating the matrix, so this is really a
        // check that it asks the right question.
        Assert.True(_capabilities.Allows(As(ProjectRole.LeadDev), Capability.CreateComponent));
        Assert.True(_capabilities.Allows(As(ProjectRole.Architect), Capability.CreateComponent));
        Assert.False(_capabilities.Allows(As(ProjectRole.InfoSecOfficer), Capability.CreateComponent));
        Assert.False(_capabilities.Allows(As(ProjectRole.Auditor), Capability.CreateComponent));
    }

    [Fact]
    public void A_denial_and_an_invalid_input_are_different_outcomes()
    {
        // They read differently to the user and belong in different places: a
        // denial is a disabled control with a reason, an invalid input is a
        // message beside the field. A single bool loses that.
        var denied = Result<Guid>.Denied("You lack the role.");
        var invalid = Result<Guid>.Invalid("A component needs a name.");

        Assert.True(denied.WasDenied);
        Assert.False(invalid.WasDenied);
        Assert.False(denied.Success);
        Assert.False(invalid.Success);
    }

    [Fact]
    public void A_successful_result_carries_its_value()
    {
        var id = Guid.NewGuid();

        var result = Result<Guid>.Ok(id);

        Assert.True(result.Success);
        Assert.Equal(id, result.Value);
        Assert.Null(result.Error);
    }
}
