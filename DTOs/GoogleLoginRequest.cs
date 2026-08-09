using System.ComponentModel.DataAnnotations;

namespace Api.DTOs
{
    /// <summary>
    /// Request body for <c>POST /api/auth/google</c>.
    /// The frontend obtains this token from the Google Sign-In JavaScript SDK
    /// (<c>credential</c> field from the <c>CredentialResponse</c> callback).
    /// </summary>
    public sealed class GoogleLoginRequest
    {
        /// <summary>
        /// The Google-signed JWT (ID token) returned by Google Sign-In.
        /// The backend validates this token against Google's public keys.
        /// </summary>
        [Required(ErrorMessage = "Google ID token is required.")]
        public string IdToken { get; set; } = string.Empty;
    }
}
