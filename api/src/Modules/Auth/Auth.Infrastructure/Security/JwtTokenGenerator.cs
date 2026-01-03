using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using SharedKernel.Application.Interfaces;
using Microsoft.Extensions.Options;
using SharedKernel.Application.Options;

namespace Auth.Infrastructure.Security;

/// <summary>
/// Gera JWT com base em uma chave segura configurada.
/// A chave deve ter no mínimo 32 caracteres para garantir segurança adequada.
/// </summary>
public class JwtTokenGenerator : IJwtTokenGenerator
{
    private readonly JwtOptions _options;
    private const int MinimumKeyLength = 32;

    public JwtTokenGenerator(IOptions<JwtOptions> options)
    {
        _options = options.Value;
        ValidateOptions();
    }

    private void ValidateOptions()
    {
        if (string.IsNullOrWhiteSpace(_options.Key))
        {
            throw new InvalidOperationException(
                "JWT Key cannot be null or empty. Set via JWT_SECRET_KEY environment variable.");
        }

        if (_options.Key.Length < MinimumKeyLength)
        {
            throw new InvalidOperationException(
                $"JWT Key must be at least {MinimumKeyLength} characters long for security. " +
                $"Current length: {_options.Key.Length}. Generate a secure key using: openssl rand -base64 64");
        }

        if (string.IsNullOrWhiteSpace(_options.Issuer))
        {
            throw new InvalidOperationException("JWT Issuer cannot be null or empty.");
        }

        if (string.IsNullOrWhiteSpace(_options.Audience))
        {
            throw new InvalidOperationException("JWT Audience cannot be null or empty.");
        }

        if (_options.ExpirationHours <= 0)
        {
            throw new InvalidOperationException("JWT ExpirationHours must be greater than 0.");
        }
    }

    public string GenerateToken(Guid userId, string username, string role)
    {
        if (userId == Guid.Empty)
        {
            throw new ArgumentException("UserId cannot be empty.", nameof(userId));
        }

        if (string.IsNullOrWhiteSpace(username))
        {
            throw new ArgumentException("Username cannot be null or empty.", nameof(username));
        }

        if (string.IsNullOrWhiteSpace(role))
        {
            throw new ArgumentException("Role cannot be null or empty.", nameof(role));
        }

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_options.Key));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, userId.ToString()),
            new Claim(JwtRegisteredClaimNames.UniqueName, username),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()), // Token ID único
            new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
            new Claim(ClaimTypes.Role, role)
        };

        var token = new JwtSecurityToken(
            issuer: _options.Issuer,
            audience: _options.Audience,
            claims: claims,
            notBefore: DateTime.UtcNow,
            expires: DateTime.UtcNow.AddHours(_options.ExpirationHours),
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}