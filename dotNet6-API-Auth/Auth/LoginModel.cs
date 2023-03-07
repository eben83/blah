using System.ComponentModel.DataAnnotations;

namespace dotNet6_API_Auth.Auth;

public class LoginModel
{
    [Required(ErrorMessage = "User name is required")]
    public string? Username { get; set; }

    [Required(ErrorMessage = "Password is required")]
    public string? Password { get; set; }
}