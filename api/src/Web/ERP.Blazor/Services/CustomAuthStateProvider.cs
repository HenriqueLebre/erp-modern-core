using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;

namespace ERP.Blazor.Services;

/// <summary>
/// Provider customizado para gerenciar o estado de autenticação
/// </summary>
public class CustomAuthStateProvider : AuthenticationStateProvider
{
    private readonly IAuthService _authService;
    private readonly ILogger<CustomAuthStateProvider> _logger;

    public CustomAuthStateProvider(
        IAuthService authService,
        ILogger<CustomAuthStateProvider> logger)
    {
        _authService = authService;
        _logger = logger;
    }

    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        try
        {
            var user = await _authService.GetCurrentUserAsync();

            if (user != null && user.Success)
            {
                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.Username),
                    new Claim(ClaimTypes.NameIdentifier, user.UserId),
                    new Claim(ClaimTypes.Role, user.Role),
                    new Claim("token", user.Token)
                };

                var identity = new ClaimsIdentity(claims, "jwt");
                var claimsPrincipal = new ClaimsPrincipal(identity);

                _logger.LogDebug("User authenticated: {Username}", user.Username);

                return new AuthenticationState(claimsPrincipal);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting authentication state");
        }

        // Usuário não autenticado
        var anonymous = new ClaimsPrincipal(new ClaimsIdentity());
        return new AuthenticationState(anonymous);
    }

    /// <summary>
    /// Notifica que o estado de autenticação mudou
    /// </summary>
    public void NotifyAuthenticationStateChanged()
    {
        NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
    }
}
