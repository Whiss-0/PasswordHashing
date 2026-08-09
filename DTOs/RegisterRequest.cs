using System.ComponentModel.DataAnnotations;

namespace Api.DTOs
{
    public class RegisterRequest
    {
        [Required(ErrorMessage = "Username is required")]
        [StringLength(12, MinimumLength = 6, ErrorMessage = "Username must be between 3 and 12 characters")]
        public string Username { get; set; } = string.Empty;

        [Required(ErrorMessage = "Password is required")]
        [StringLength(12, MinimumLength = 5, ErrorMessage = "Password must be between 5 and 12 characters")]
        public string Password { get; set; } = string.Empty;

        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email address")]
        public string Email { get; set; } = string.Empty;
    }
}