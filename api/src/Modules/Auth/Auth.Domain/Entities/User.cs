namespace Auth.Domain.Entities;

/// <summary>
/// Usuário do sistema (será autenticado via /auth/login).
/// </summary>
public class User
{
    public Guid Id { get; private set; }
    public string Username { get; private set; } = default!;
    public string PasswordHash { get; private set; } = default!;
    public string Email { get; private set; } = default!;
    public string Role { get; private set; } = default!;
    public bool IsActive { get; private set; }
    public int FailedLoginAttempts { get; private set; } = 0;
    public DateTime? LockedUntil { get; private set; }

    // Construtor usado para criar um novo usuário
    public User(string username, string passwordHash, string email, string role, bool isActive = true)
    {
        Id = Guid.NewGuid();
        Username = username;
        PasswordHash = passwordHash;
        Email = email;
        Role = role;
        IsActive = isActive;
    }

    // Construtor privado para o EF Core
    private User() { }

    public void UpdatePasswordHash(string newPasswordHash)
    {
        if (string.IsNullOrWhiteSpace(newPasswordHash))
            throw new ArgumentException("Password hash cannot be empty.", nameof(newPasswordHash));

        PasswordHash = newPasswordHash;
    }

    public void Deactivate() => IsActive = false;
    public void Activate() => IsActive = true;

    public void UpdateRole(string newRole)
    {
        if (string.IsNullOrWhiteSpace(newRole))
            throw new ArgumentException("Role cannot be empty.", nameof(newRole));

        Role = newRole;
    }

    public void RecordFailedLogin()
    {
        FailedLoginAttempts++;
        
        // Bloquear conta após 5 tentativas falhas
        if (FailedLoginAttempts >= 5)
        {
            LockedUntil = DateTime.UtcNow.AddMinutes(15); // Bloquear por 15 minutos
        }
    }

    public void ResetFailedLoginAttempts()
    {
        FailedLoginAttempts = 0;
        LockedUntil = null;
    }

    public bool IsLocked()
    {
        return LockedUntil.HasValue && LockedUntil.Value > DateTime.UtcNow;
    }

    public void UnlockAccount()
    {
        LockedUntil = null;
        FailedLoginAttempts = 0;
    }
}