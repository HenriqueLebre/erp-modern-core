using System.Reflection;
using MediatR;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.Application;

public static class DependencyInjection
{
    public static IServiceCollection AddAuthApplication(this IServiceCollection services)
    {
        // Versão compatível com MediatR 11.x
        services.AddMediatR(Assembly.GetExecutingAssembly());

        return services;
    }
}