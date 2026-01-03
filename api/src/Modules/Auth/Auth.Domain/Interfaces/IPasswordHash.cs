namespace Auth.Domain.Interfaces;

/// <summary>
/// Serviço de hash de senha (será implementado em Infrastructure).
/// </summary>

public interface IPasswordHasher
{
    string HashPassword(string password);
    bool VerifyPassword(string hashedPassword, string providedPassword);
}