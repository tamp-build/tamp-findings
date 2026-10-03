using System.Net;

namespace Tamp.Findings.Integration.Tests;

// TFND-230: GET /findings/file without its required `path` used to fail model binding and surface as a 500; a
// missing required query parameter is a client error and must be a 400 that names the parameter.
[Collection(DatabaseCollection.Name)]
public class FindingsFileValidationTests
{
    private readonly DatabaseFixture _fx;
    public FindingsFileValidationTests(DatabaseFixture fx) => _fx = fx;

    private async Task<HttpClient> AdminAsync()
    {
        ApiBSupport.World w;
        using (var scope = _fx.Scope()) w = await ApiBSupport.SeedWorldAsync(_fx.Db(scope), ApiBSupport.Suffix());
        return _fx.Factory!.WithTestAuth().As(w.AdminId);
    }

    [SkippableTheory]
    [InlineData("/findings/file")]
    [InlineData("/findings/file?path=")]
    [InlineData("/findings/file?path=%20%20")]
    [InlineData("/findings/file?projectId=00000000-0000-0000-0000-000000000000")]
    public async Task A_missing_or_blank_path_is_a_400_that_names_the_parameter(string url)
    {
        Skip.IfNot(_fx.Available);
        var http = await AdminAsync();

        var resp = await http.GetAsync(url);

        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
        Assert.Contains("path", await resp.Content.ReadAsStringAsync(), StringComparison.OrdinalIgnoreCase);
    }
}
