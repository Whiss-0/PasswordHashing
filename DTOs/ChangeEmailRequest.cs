using System.ComponentModel.DataAnnotations;

namespace Api.DTOs{
    public class ChangeEmailRequest
    {
        [Required(ErrorMessage = "Current email is required")]
        [StringLength(100, MinimumLength = 5, ErrorMessage = "Current email must be between 5 and 100 characters")]
        [EmailAddress(ErrorMessage = "Invalid email address")]
        public string CurrentEmail { get; set; } = string.Empty;

        [Required(ErrorMessage = "New email is required")]
        [StringLength(100, MinimumLength = 5, ErrorMessage = "New email must be between 5 and 100 characters")]
        [EmailAddress(ErrorMessage = "Invalid email address")]
        public string NewEmail { get; set; } = string.Empty;
    }
}