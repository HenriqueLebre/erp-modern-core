using Auth.Domain.Interfaces;
using Microsoft.AspNetCore.Mvc;

namespace Auth.API.Controllers;

[ApiController]
[Route("auth/password")]
public class PasswordController : ControllerBase
{
    private readonly IPasswordValidator _passwordValidator;

    public PasswordController(IPasswordValidator passwordValidator)
    {
        _passwordValidator = passwordValidator;
    }

    /// <summary>
    /// Valida a força de uma senha sem armazená-la.
    /// Útil para validação no lado do cliente antes de submeter.
    /// </summary>
    [HttpPost("validate")]
    public IActionResult ValidatePassword([FromBody] ValidatePasswordRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Password))
        {
            return BadRequest(new { success = false, message = "Password is required" });
        }

        var result = _passwordValidator.Validate(request.Password);

        if (result.IsValid)
        {
            return Ok(new { success = true, valid = true, message = "Password meets security requirements" });
        }

        return Ok(new 
        { 
            success = true, 
            valid = false, 
            errors = result.Errors,
            message = "Password does not meet security requirements"
        });
    }
}

public record ValidatePasswordRequest(string Password);
