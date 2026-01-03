using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;

namespace Auth.Infrastructure.Persistence;

public sealed class AuthDbContextFactory : IDesignTimeDbContextFactory<AuthDbContext>
{
    public AuthDbContext CreateDbContext(string[] args)
    {
        // Caminho relativo do Infrastructure até o API (ajuste se necessário)
        var apiProjectPath = Path.Combine(Directory.GetCurrentDirectory(), "..", "Auth.API");

        var configuration = new ConfigurationBuilder()
            .SetBasePath(apiProjectPath)
            .AddJsonFile("appsettings.json", optional: false)
            .AddJsonFile("appsettings.Development.json", optional: true)
            .AddEnvironmentVariables()
            .Build();

        var connectionString =
            Environment.GetEnvironmentVariable("ConnectionStrings__DefaultConnection")
            ?? throw new InvalidOperationException("Set ConnectionStrings__DefaultConnection.");

        var optionsBuilder = new DbContextOptionsBuilder<AuthDbContext>();
        optionsBuilder.UseNpgsql(connectionString);

        return new AuthDbContext(optionsBuilder.Options);
    }
}