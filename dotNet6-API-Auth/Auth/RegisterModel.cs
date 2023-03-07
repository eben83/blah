using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authentication;

namespace dotNet6_API_Auth.Auth;

public class RegisterModel
{
    [Required(ErrorMessage = "User Name is Required")]
    public string? UserName { get; set; }
    
    [EmailAddress]
    [Required(ErrorMessage = "Email is required")]
    public string? Email { get; set; }

    [Required(ErrorMessage = "Password is required")]
    public string? Password { get; set; }
}