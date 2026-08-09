using System.ComponentModel.DataAnnotations;

namespace Api.DTOs
{
    public class LoginRequest
    {
        [Required(ErrorMessage = "Username is required")]
        [StringLength(20, MinimumLength = 5, ErrorMessage = "Username must be between 5 and 20 characters")]
        public string Username { get; set; } = string.Empty;

        [Required(ErrorMessage = "Password is required")]
        [StringLength(12, MinimumLength = 5, ErrorMessage = "Password must be between 5 and 12 characters")]
        public string Password { get; set; } = string.Empty;
    }
}