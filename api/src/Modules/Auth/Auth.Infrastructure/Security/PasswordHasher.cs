using System.Security.Cryptography;
using System.Text;
using Auth.Domain.Interfaces;

namespace Auth.Infrastructure.Security;

/// <summary>
/// Implementação simples de hash de senha usando SHA256.
/// </summary>
public class PasswordHasher : IPasswordHasher
{
    public string HashPassword(string password)
    {
        using var sha256 = SHA256.Create();
        var bytes = Encoding.UTF8.GetBytes(password);
        var hash = sha256.ComputeHash(bytes);
        return Convert.ToBase64String(hash);
    }

    public bool VerifyPassword(string hashedPassword, string providedPassword)
    {
        var providedHash = HashPassword(providedPassword);
        return hashedPassword == providedHash;
    }
}