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
    public async Task An_unknown_model_is_rejected_before_anything_is_built()
    {
        // Cheap validation first: building the document hits the database, and
        // a typo in a query parameter should not.
        var client = _factory.CreateSignedIn();

        var resp = await client.GetAsync($"/projects/{Guid.NewGuid()}/oscal?model=nonsense");

        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
        Assert.Contains("Bundle", await resp.Content.ReadAsStringAsync(), StringComparison.OrdinalIgnoreCase);
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
