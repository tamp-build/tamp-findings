using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Tamp.Findings.Data;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddFindingsDb(this IServiceCollection services, string connectionString)
    {
        services.AddDbContext<FindingsDbContext>(o => o.UseNpgsql(connectionString));
        return services;
    }
}
