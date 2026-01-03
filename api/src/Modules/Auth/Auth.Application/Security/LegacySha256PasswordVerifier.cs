using System.Security.Cryptography;
using System.Text;

namespace Auth.Application.Security;

public static class LegacySha256PasswordVerifier
{
    // compatível com o legado atual: SHA256 -> Base64
    public static bool Verify(string storedHashBase64, string providedPassword)
    {
        if (string.IsNullOrWhiteSpace(storedHashBase64) || string.IsNullOrWhiteSpace(providedPassword))
            return false;

        try
        {
            using var sha256 = SHA256.Create();
            var bytes = Encoding.UTF8.GetBytes(providedPassword);
            var hash = sha256.ComputeHash(bytes);
            var providedHashBase64 = Convert.ToBase64String(hash);

            // Usar comparação de tempo constante para prevenir timing attacks
            var storedBytes = Convert.FromBase64String(storedHashBase64);
            var providedBytes = Convert.FromBase64String(providedHashBase64);

            return CryptographicOperations.FixedTimeEquals(storedBytes, providedBytes);
        }
        catch
        {
            // Em caso de erro (ex: Base64 inválido), retornar false
            return false;
        }
    }
}