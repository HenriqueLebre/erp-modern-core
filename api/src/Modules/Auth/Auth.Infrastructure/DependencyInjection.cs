using Auth.Domain.Interfaces;
using Auth.Infrastructure.Persistence;
using Auth.Infrastructure.Repositories;
using Auth.Infrastructure.Security;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using SharedKernel.Application.Interfaces;

namespace Auth.Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddAuthInfrastructure(this IServiceCollection services, IConfiguration configuration)
    {
        // DbContext (PostgreSQL)
        services.AddDbContext<AuthDbContext>(options =>
        {
            options.UseNpgsql(configuration.GetConnectionString("AuthDb"));
        });

        // Repositório de usuário
        services.AddScoped<IUserRepository, UserRepository>();

        // Hasher de senha (PBKDF2 como padrão; legado é verificado no fluxo de login)
        services.AddScoped<IPasswordHasher, Pbkdf2PasswordHasher>();

        // Validador de senha
        services.AddScoped<IPasswordValidator, PasswordValidator>();

        // Gerador de JWT
        services.AddSingleton<IJwtTokenGenerator, JwtTokenGenerator>();

        return services;
    }
}