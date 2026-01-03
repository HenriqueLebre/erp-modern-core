using ERP.Blazor.Models;

namespace ERP.Blazor.Services;

/// <summary>
/// Interface para serviço de autenticação
/// </summary>
public interface IAuthService
{
    /// <summary>
    /// Realiza login do usuário
    /// </summary>
    Task<LoginResult> LoginAsync(string username, string password);

    /// <summary>
    /// Realiza logout do usuário
    /// </summary>
    Task LogoutAsync();

    /// <summary>
    /// Verifica se usuário está autenticado
    /// </summary>
    Task<bool> IsAuthenticatedAsync();

    /// <summary>
    /// Obtém token JWT atual
    /// </summary>
    Task<string?> GetTokenAsync();

    /// <summary>
    /// Obtém informações do usuário autenticado
    /// </summary>
    Task<LoginResult?> GetCurrentUserAsync();
}
