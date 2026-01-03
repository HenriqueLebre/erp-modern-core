using System.ComponentModel.DataAnnotations;

namespace ERP.Blazor.Models;

/// <summary>
/// Model para o formulário de login
/// </summary>
public class LoginModel
{
    [Required(ErrorMessage = "Usuário é obrigatório")]
    [MinLength(3, ErrorMessage = "Usuário deve ter pelo menos 3 caracteres")]
    public string Username { get; set; } = string.Empty;

    [Required(ErrorMessage = "Senha é obrigatória")]
    [MinLength(4, ErrorMessage = "Senha deve ter pelo menos 4 caracteres")]
    public string Password { get; set; } = string.Empty;

    public bool RememberMe { get; set; }
}
