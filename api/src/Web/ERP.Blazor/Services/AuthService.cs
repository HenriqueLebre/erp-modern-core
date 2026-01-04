using System.Net.Http.Json;
using ERP.Blazor.Models;

namespace ERP.Blazor.Services;

/// <summary>
/// Serviço de autenticação que integra com a Auth API
/// </summary>
public class AuthService : IAuthService
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<AuthService> _logger;
    private LoginResult? _currentUser;  // ← ADICIONAR ESTA LINHA!

    public AuthService(
        IHttpClientFactory httpClientFactory,
        ILogger<AuthService> logger)
    {
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    public async Task<LoginResult> LoginAsync(string username, string password)
    {
        try
        {
            var client = _httpClientFactory.CreateClient("AuthAPI");
            
            var request = new AuthRequest
            {
                Username = username,
                Password = password
            };

            _logger.LogInformation("Attempting login for user: {Username}", username);

            var response = await client.PostAsJsonAsync("/auth/login", request);

            if (response.IsSuccessStatusCode)
            {
                var authResponse = await response.Content.ReadFromJsonAsync<AuthResponse>();

                if (authResponse != null)
                {
                    var loginResult = new LoginResult
                    {
                        Success = true,
                        Token = authResponse.Token,
                        Username = authResponse.Username,
                        UserId = authResponse.UserId,
                        Role = authResponse.Role,
                        ExpiresAt = authResponse.ExpiresAt
                    };

                    // ✅ ARMAZENAR USUÁRIO ATUAL!
                    _currentUser = loginResult;

                    _logger.LogInformation("Login successful for user: {Username}. Token stored.", username);

                    return loginResult;
                }
            }
            else
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                _logger.LogWarning("Login failed for user: {Username}. Status: {Status}, Error: {Error}",
                    username, response.StatusCode, errorContent);

                return new LoginResult
                {
                    Success = false,
                    ErrorMessage = response.StatusCode switch
                    {
                        System.Net.HttpStatusCode.Unauthorized => "Usuário ou senha inválidos",
                        System.Net.HttpStatusCode.BadRequest => "Dados de login inválidos",
                        _ => $"Erro ao realizar login: {response.StatusCode}"
                    }
                };
            }
        }
        catch (HttpRequestException ex)
        {
            _logger.LogError(ex, "HTTP error during login for user: {Username}", username);
            return new LoginResult
            {
                Success = false,
                ErrorMessage = "Erro de conexão com o servidor. Verifique se a API está rodando."
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during login for user: {Username}", username);
            return new LoginResult
            {
                Success = false,
                ErrorMessage = "Erro inesperado ao realizar login"
            };
        }

        return new LoginResult
        {
            Success = false,
            ErrorMessage = "Resposta inválida do servidor"
        };
    }

    public Task LogoutAsync()
    {
        _logger.LogInformation("Logging out user");
        _currentUser = null;  // ✅ LIMPAR USUÁRIO
        return Task.CompletedTask;
    }

    public Task<bool> IsAuthenticatedAsync()
    {
        return Task.FromResult(_currentUser != null && _currentUser.Success);
    }

    public Task<string?> GetTokenAsync()
    {
        return Task.FromResult(_currentUser?.Token);
    }

    public Task<LoginResult?> GetCurrentUserAsync()
    {
        return Task.FromResult(_currentUser);  // ✅ RETORNAR USUÁRIO ARMAZENADO
    }
}