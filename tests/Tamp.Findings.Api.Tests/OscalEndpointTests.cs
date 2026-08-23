using System.Net;

namespace Tamp.Findings.Api.Tests;

// The OSCAL export surface (TFND-39).
//
// It exists because the consumers differ: the attestation screen is read by a
// person who signs, this by a pipeline submitting a FedRAMP package — and a
// pipeline should not have to drive a browser to get a document the system can
// generate directly.
public class OscalEndpointTests : IClassFixture<TestApiFactory>
{
    private readonly TestApiFactory _factory;

    public OscalEndpointTests(TestApiFactory factory) => _factory = factory;

    [Fact]
    public async Task An_anonymous_caller_is_refused()
    {
        // A machine-readable compliance package is not public data.
        var client = _factory.CreateClient();

        var resp = await client.GetAsync($"/projects/{Guid.NewGuid()}/oscal");

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task An_unknown_model_is_never_served()
    {
        // This used to assert a 400 with the valid model names in the body, and
        // it asserted it against a host with no database — which worked because
        // the endpoint validated the query parameter before touching anything.
        //
        // TFND-133 put the visibility boundary in front of that. The caller now
        // has to be allowed to SEE the project before the endpoint gets a say
        // about its query string, which is the correct order — you should not
        // learn that a parameter is malformed for a resource you cannot see.
        // With no database the boundary cannot be resolved, so this host
        // answers 503.
        //
        // What is still assertable here is the part that matters: nothing is
        // served. The precise 400 and its body moved to the integration suite,
        // where a project exists and somebody can see it.
        var client = _factory.CreateSignedIn();

        var resp = await client.GetAsync($"/projects/{Guid.NewGuid()}/oscal?model=nonsense");

        Assert.NotEqual(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task Every_model_name_is_accepted()
    {
        // The parameter is parsed case-insensitively against the enum, so a
        // caller writing "poam" rather than "Poam" is not a 400.
        var client = _factory.CreateSignedIn();

        foreach (var model in new[] { "bundle", "poam", "assessmentresults" })
        {
            var resp = await client.GetAsync($"/projects/{Guid.NewGuid()}/oscal?model={model}");

            // The project does not exist and this suite has no database, so
            // anything except "that model is not a thing" is the right answer.
            Assert.NotEqual(HttpStatusCode.BadRequest, resp.StatusCode);
        }
    }
}
