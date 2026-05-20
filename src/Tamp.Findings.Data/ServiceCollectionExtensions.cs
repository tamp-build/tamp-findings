using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;

namespace Tamp.Findings.Data;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddFindingsDb(this IServiceCollection services, string connectionString)
    {
        // Npgsql 8+ requires opt-in for serializing arbitrary types into
        // jsonb. We use List<Dictionary<string,string?>> for
        // SbomSnapshot.MetadataTools and Dictionary<string,string> for
        // SbomComponent.Hashes — both need dynamic JSON to round-trip.
        var dsBuilder = new NpgsqlDataSourceBuilder(connectionString);
        dsBuilder.EnableDynamicJson();
        var dataSource = dsBuilder.Build();
        services.AddSingleton(dataSource);
        services.AddDbContext<FindingsDbContext>(o => o.UseNpgsql(dataSource));
        return services;
    }
}
