namespace ERP.Blazor.Models;

/// <summary>
/// Request para a API de autenticação
/// </summary>
public class AuthRequest
{
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
}
