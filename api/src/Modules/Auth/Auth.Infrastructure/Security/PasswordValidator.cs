using System.Text.RegularExpressions;
using Auth.Domain.Interfaces;

namespace Auth.Infrastructure.Security;

/// <summary>
/// Implementação de validação de senha com requisitos de segurança.
/// </summary>
public sealed class PasswordValidator : IPasswordValidator
{
    private const int MinimumLength = 8;
    private const int MaximumLength = 128;

    public PasswordValidationResult Validate(string password)
    {
        var errors = new List<string>();

        if (string.IsNullOrWhiteSpace(password))
        {
            errors.Add("Password cannot be empty.");
            return PasswordValidationResult.Failure(errors);
        }

        // Comprimento
        if (password.Length < MinimumLength)
        {
            errors.Add($"Password must be at least {MinimumLength} characters long.");
        }

        if (password.Length > MaximumLength)
        {
            errors.Add($"Password must not exceed {MaximumLength} characters.");
        }

        // Deve conter pelo menos uma letra maiúscula
        if (!Regex.IsMatch(password, @"[A-Z]"))
        {
            errors.Add("Password must contain at least one uppercase letter (A-Z).");
        }

        // Deve conter pelo menos uma letra minúscula
        if (!Regex.IsMatch(password, @"[a-z]"))
        {
            errors.Add("Password must contain at least one lowercase letter (a-z).");
        }

        // Deve conter pelo menos um dígito
        if (!Regex.IsMatch(password, @"[0-9]"))
        {
            errors.Add("Password must contain at least one digit (0-9).");
        }

        // Deve conter pelo menos um caractere especial
        if (!Regex.IsMatch(password, @"[!@#$%^&*()_+\-=\[\]{};':""\\|,.<>\/?]"))
        {
            errors.Add("Password must contain at least one special character (!@#$%^&*()_+-=[]{}; etc).");
        }

        // Verificar sequências comuns (opcional, para maior segurança)
        if (ContainsCommonSequence(password))
        {
            errors.Add("Password contains common sequences. Please choose a more unique password.");
        }

        return errors.Count == 0 
            ? PasswordValidationResult.Success() 
            : PasswordValidationResult.Failure(errors);
    }

    private static bool ContainsCommonSequence(string password)
    {
        var commonSequences = new[]
        {
            "123456", "password", "qwerty", "abc123", "111111", 
            "admin", "letmein", "welcome", "monkey", "dragon"
        };

        return commonSequences.Any(seq => 
            password.Contains(seq, StringComparison.OrdinalIgnoreCase));
    }
}
