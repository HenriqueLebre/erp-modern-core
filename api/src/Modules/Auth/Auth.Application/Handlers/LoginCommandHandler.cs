using Auth.Application.Commands;
using Auth.Application.Security;   // só para LegacySha256PasswordVerifier
using Auth.Domain.Interfaces;      // aqui vem o IPasswordHasher correto
using MediatR;
using SharedKernel.Application.Interfaces;
using Microsoft.Extensions.Logging;

namespace Auth.Application.Handlers;

public class LoginCommandHandler : IRequestHandler<LoginCommand, LoginResponse>
{
    private readonly IUserRepository _userRepository;
    private readonly IPasswordHasher _passwordHasher; 
    private readonly IJwtTokenGenerator _jwtTokenGenerator;
    private readonly ILogger<LoginCommandHandler> _logger;

    public LoginCommandHandler(
        IUserRepository userRepository,
        IPasswordHasher passwordHasher,
        IJwtTokenGenerator jwtTokenGenerator,
        ILogger<LoginCommandHandler> logger)
    {
        _userRepository = userRepository;
        _passwordHasher = passwordHasher;
        _jwtTokenGenerator = jwtTokenGenerator;
        _logger = logger;
    }

    public async Task<LoginResponse> Handle(LoginCommand request, CancellationToken cancellationToken)
    {
        var user = await _userRepository.GetByUsernameAsync(request.Username, cancellationToken);

        // Usar mensagem genérica para prevenir enumeração de usuários
        if (user is null || !user.IsActive)
        {
            _logger.LogWarning(
                "Login failed: User not found or inactive. Username: {Username}, IP: {IpAddress}", 
                request.Username, 
                "N/A"); // IP será adicionado via middleware
            
            return new LoginResponse(false, null, null, null, null, "Invalid username or password.");
        }

        // Verificar se a conta está bloqueada
        if (user.IsLocked())
        {
            _logger.LogWarning(
                "Login failed: Account is locked. UserId: {UserId}, Username: {Username}, LockedUntil: {LockedUntil}", 
                user.Id, 
                user.Username,
                user.LockedUntil);
            
            return new LoginResponse(false, null, null, null, null, 
                "Account is temporarily locked due to multiple failed login attempts. Please try again later.");
        }

        var storedHash = user.PasswordHash;
        var providedPassword = request.Password;

        // Detecta se é o formato novo
        var isPbkdf2 = storedHash.StartsWith("pbkdf2$", StringComparison.OrdinalIgnoreCase);

        bool passwordOk;

        if (isPbkdf2)
        {
            // Novo: PBKDF2 (via IPasswordHasher)
            passwordOk = _passwordHasher.VerifyPassword(storedHash, providedPassword);
        }
        else
        {
            // Legado: SHA256 Base64 (compatível com o PasswordHasher atual)
            passwordOk = LegacySha256PasswordVerifier.Verify(storedHash, providedPassword);

            // Migração automática: se o legado passar, rehash PBKDF2 e salva
            if (passwordOk)
            {
                var newHash = _passwordHasher.HashPassword(providedPassword);
                user.UpdatePasswordHash(newHash);

                await _userRepository.UpdateAsync(user, cancellationToken);
            }
        }

        if (!passwordOk)
        {
            // Registrar tentativa falha e possivelmente bloquear a conta
            user.RecordFailedLogin();
            await _userRepository.UpdateAsync(user, cancellationToken);
            
            _logger.LogWarning(
                "Login failed: Invalid password. UserId: {UserId}, Username: {Username}, FailedAttempts: {FailedAttempts}", 
                user.Id, 
                user.Username,
                user.FailedLoginAttempts);
            
            return new LoginResponse(false, null, null, null, null, "Invalid username or password.");
        }

        // Login bem-sucedido - resetar tentativas falhas
        if (user.FailedLoginAttempts > 0)
        {
            user.ResetFailedLoginAttempts();
            await _userRepository.UpdateAsync(user, cancellationToken);
        }

        var token = _jwtTokenGenerator.GenerateToken(user.Id, user.Username, user.Role);

        _logger.LogInformation(
            "Login successful. UserId: {UserId}, Username: {Username}, Role: {Role}", 
            user.Id, 
            user.Username, 
            user.Role);

        return new LoginResponse(true, token, user.Username, user.Id, user.Role, "Login successful.");
    }
}