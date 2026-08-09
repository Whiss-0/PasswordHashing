using System.ComponentModel.DataAnnotations;

namespace Api.DTOs
{
    public class ChangePasswordRequest
    {
        [Required(ErrorMessage = "Current password is required")]
        [StringLength(12, MinimumLength = 5, ErrorMessage = "Current password must be between 5 and 12 characters")]
        public string CurrentPassword { get; set; } = string.Empty;

        [Required(ErrorMessage = "New password is required")]
        [StringLength(12, MinimumLength = 5, ErrorMessage = "New password must be between 5 and 12 characters")]
        public string NewPassword { get; set; } = string.Empty;
    }
}