using System.ComponentModel.DataAnnotations;

namespace Api.DTOs
{
    public class RegisterAdminRequest
    {
        [Required(ErrorMessage = "Username is required")]
        [StringLength(30, MinimumLength = 3, ErrorMessage = "Username must be between 3 and 30 characters")]
        public string Username { get; set; } = string.Empty;

        [Required(ErrorMessage = "Password is required")]
        [StringLength(64, MinimumLength = 5, ErrorMessage = "Password must be between 5 and 64 characters")]
        public string Password { get; set; } = string.Empty;

        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email address")]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "Role is required")]
        [Range(1, 6, ErrorMessage = "Role must be between 1 and 6")]
        public int RoleId { get; set; }
    }
}