using Api.DTOs;
using Api.Modules.AuthorizationModule;

namespace Api.Modules.LoginModule
{
    /// <summary>
    /// Handles login, OTP verification, Google OAuth, and token refresh.
    /// </summary>
    public interface ILoginService
    {
        /// <summary>
        /// Validates credentials and either issues a session (trusted device)
        /// or sends an OTP and waits for verification.
        /// </summary>
        Task<ServiceResult> LoginAsync(LoginRequest dto, string? ip, string? deviceId);

        /// <summary>
        /// Verifies the OTP sent during login and issues a full JWT session.
        /// </summary>
        Task<ServiceResult> VerifyLoginOtpAsync(
            string  otpCode,
            string? pendingEmail,
            string? pendingDeviceId,
            string? ip,
            bool    trustDevice = true);

        /// <summary>
        /// Validates a Google ID token, finds or creates the user, and
        /// issues a JWT session. No OTP required — Google verified the email.
        /// </summary>
        Task<ServiceResult> GoogleLoginAsync(GoogleLoginRequest dto, string? ip, string? deviceId);

        /// <summary>
        /// Rotates the access token using a valid refresh token.
        /// </summary>
        Task<ServiceResult> RefreshAsync(string? accessToken, string? refreshToken);
    }
}
