using Auth.Application.Commands;
using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.Options;
using System.IdentityModel.Tokens.Jwt;

namespace Auth.API.Controllers;

[ApiController]
[Route("auth")]
public class AuthController : ControllerBase
{
    private readonly IMediator _mediator;

    public AuthController(IMediator mediator)
    {
        _mediator = mediator;
    }

    [HttpPost("login")]
    public async Task<ActionResult<LoginResponse>> Login([FromBody] LoginCommand command)
    {
        // Adicionar um pequeno delay para prevenir timing attacks na enumeração de usuários
        await Task.Delay(Random.Shared.Next(50, 150));
        
        var result = await _mediator.Send(command);

        if (!result.Success)
            return Unauthorized(result);

        return Ok(result);
    }

        [Authorize]
    [HttpGet("me")]
    public IActionResult Me()
    {
        var userId =
            User.FindFirstValue(ClaimTypes.NameIdentifier) ??
            User.FindFirstValue("sub");

        var username =
            User.Identity?.Name ??
            User.FindFirstValue(ClaimTypes.Name) ??
            User.FindFirstValue("unique_name");

        var role = User.FindFirstValue(ClaimTypes.Role);

        return Ok(new { userId, username, role });
    }

    [HttpPost("validate")]
    public IActionResult ValidateToken([FromBody] ValidateTokenRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Token))
        {
            return BadRequest(new { success = false, message = "Token is required" });
        }

        try
        {
            // Get JWT options from configuration
            var jwtOptions = HttpContext.RequestServices.GetRequiredService<IOptions<SharedKernel.Application.Options.JwtOptions>>().Value;
            
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = System.Text.Encoding.UTF8.GetBytes(jwtOptions.Key);
            
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = jwtOptions.Issuer,
                ValidAudience = jwtOptions.Audience,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ClockSkew = TimeSpan.FromSeconds(30)
            };

                        var principal = tokenHandler.ValidateToken(request.Token, validationParameters, out SecurityToken validatedToken);
            
            var claims = principal.Claims.ToDictionary(c => c.Type, c => c.Value);
                    
            return Ok(new 
            { 
                success = true, 
                valid = true,
                userId = claims.GetValueOrDefault(ClaimTypes.NameIdentifier) ?? claims.GetValueOrDefault("sub"),
                username = claims.GetValueOrDefault(ClaimTypes.Name) ?? claims.GetValueOrDefault("unique_name"),
                role = claims.GetValueOrDefault(ClaimTypes.Role),
                expires = claims.GetValueOrDefault("exp")
            });
        }
        catch (SecurityTokenException)
        {
            return Ok(new { success = true, valid = false, message = "Token validation failed" });
        }
        catch (Exception)
        {
            // Não vazar detalhes de erro interno
            return StatusCode(500, new { success = false, message = "Internal server error" });
        }
    }
}