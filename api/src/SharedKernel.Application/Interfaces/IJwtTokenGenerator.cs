namespace SharedKernel.Application.Interfaces;

/// <summary>
/// Serviço de geração de token JWT (será implementado na camada Infrastructure).
/// </summary>
public interface IJwtTokenGenerator
{
    string GenerateToken(Guid userId, string username, string role);
}