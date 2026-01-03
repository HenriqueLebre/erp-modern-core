namespace Auth.Domain.Interfaces;

/// <summary>
/// Interface para validação de complexidade de senha.
/// </summary>
public interface IPasswordValidator
{
    /// <summary>
    /// Valida se uma senha atende aos requisitos mínimos de segurança.
    /// </summary>
    /// <param name="password">Senha a ser validada</param>
    /// <returns>Resultado da validação com mensagens de erro se houver</returns>
    PasswordValidationResult Validate(string password);
}

/// <summary>
/// Resultado da validação de senha.
/// </summary>
public sealed class PasswordValidationResult
{
    public bool IsValid { get; }
    public IReadOnlyList<string> Errors { get; }

    private PasswordValidationResult(bool isValid, IReadOnlyList<string> errors)
    {
        IsValid = isValid;
        Errors = errors;
    }

    public static PasswordValidationResult Success() 
        => new(true, Array.Empty<string>());

    public static PasswordValidationResult Failure(params string[] errors) 
        => new(false, errors);

    public static PasswordValidationResult Failure(IEnumerable<string> errors) 
        => new(false, errors.ToList());
}
