using Auth.Domain.Entities;

namespace Auth.Domain.Interfaces;

/// <summary>
/// Contrato de acesso a dados de usuário (será implementado na camada Infrastructure).
/// </summary>

public interface IUserRepository
{
    Task<User?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default);
    Task<User?> GetByUsernameAsync(string username, CancellationToken cancellationToken = default);
    Task AddAsync(User user, CancellationToken cancellationToken = default);
    Task UpdateAsync(User user, CancellationToken cancellationToken = default);
}