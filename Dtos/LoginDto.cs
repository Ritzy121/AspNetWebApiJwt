using System.ComponentModel.DataAnnotations;

namespace WebApi.Dtos;

public class LoginDto
{
    [Required(ErrorMessage = "UserName is required")]
    public string UserName { get; set; }

    [Required(ErrorMessage = "Password is required")]
    [MinLength(3, ErrorMessage = "Password must be at least 3 characters long")]
    public string Password { get; set; }
}