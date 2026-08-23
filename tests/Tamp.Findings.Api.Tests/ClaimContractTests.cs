using Tamp.Findings.Api.Authentication;
using Tamp.Findings.Web.Security;

namespace Tamp.Findings.Api.Tests;

// The user-id claim is a wire contract between two projects that deliberately
// cannot reference each other (ADR 0002: Web must not depend on Api).
//
// So the constant is declared twice, and a silent divergence would mean the UI
// resolves nobody while the API resolves everybody — an authorization failure
// that looks like an empty screen.
public class ClaimContractTests
{
    [Fact]
    public void The_user_id_claim_type_agrees_across_the_api_and_the_ui()
    {
        Assert.Equal(AuthExtensions.TampUserIdClaim, CurrentUser.TampUserIdClaim);
    }
}
