using System.Security.Cryptography;
using Auth.Domain.Interfaces;

namespace Auth.Infrastructure.Security;

public sealed class Pbkdf2PasswordHasher : IPasswordHasher
{
    private const string Prefix = "pbkdf2";
    private const int SaltSize = 16;     // 128-bit
    private const int KeySize = 32;      // 256-bit
    private const int Iterations = 210_000; // bom baseline (ajuste conforme CPU)

    public string HashPassword(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltSize);

        var hash = Rfc2898DeriveBytes.Pbkdf2(
            password: password,
            salt: salt,
            iterations: Iterations,
            hashAlgorithm: HashAlgorithmName.SHA256,
            outputLength: KeySize
        );

        return $"{Prefix}${Iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    public bool VerifyPassword(string hashedPassword, string providedPassword)
    {
        if (string.IsNullOrWhiteSpace(hashedPassword))
            return false;

        // só valida PBKDF2 aqui
        if (!hashedPassword.StartsWith(Prefix + "$", StringComparison.OrdinalIgnoreCase))
            return false;

        var parts = hashedPassword.Split('$', 4);
        if (parts.Length != 4) return false;

        if (!int.TryParse(parts[1], out var iterations)) return false;

        byte[] salt, expectedHash;
        try
        {
            salt = Convert.FromBase64String(parts[2]);
            expectedHash = Convert.FromBase64String(parts[3]);
        }
        catch
        {
            return false;
        }

        var actualHash = Rfc2898DeriveBytes.Pbkdf2(
            password: providedPassword,
            salt: salt,
            iterations: iterations,
            hashAlgorithm: HashAlgorithmName.SHA256,
            outputLength: expectedHash.Length
        );

        return CryptographicOperations.FixedTimeEquals(actualHash, expectedHash);
    }
}