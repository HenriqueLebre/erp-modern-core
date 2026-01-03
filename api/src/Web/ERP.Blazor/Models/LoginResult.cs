namespace ERP.Blazor.Models;

/// <summary>
/// Resultado da operação de login
/// </summary>
public class LoginResult
{
    public bool Success { get; set; }
    public string Token { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string UserId { get; set; } = string.Empty;
    public string Role { get; set; } = string.Empty;
    public string ErrorMessage { get; set; } = string.Empty;
    public DateTime? ExpiresAt { get; set; }
}
