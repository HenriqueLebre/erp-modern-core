using MediatR;

namespace Auth.Application.Commands;

public record LoginCommand(string Username, string Password) : IRequest<LoginResponse>;

public record LoginResponse(
    bool Success,
    string? Token,
    string? Username,
    Guid? UserId,
    string? Role,
    string Message
);