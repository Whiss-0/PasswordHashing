using Api.DTOs;
using Api.Modules.AuthorizationModule;

namespace Api.Modules.AccountModule
{
    /// <summary>
    /// Handles post-login account management:
    /// passwords, email changes, profile lookup, and logout.
    /// </summary>
    public interface IAccountService
    {
        /// <summary>Initiates a password reset — generates and emails an OTP.</summary>
        Task<ServiceResult> ForgotPasswordAsync(ForgotPasswordRequest dto);

        /// <summary>Verifies the reset OTP and sets the new password.</summary>
        Task<ServiceResult> ResetPasswordAsync(ResetPasswordRequest dto, string? pendingEmail);

        /// <summary>Changes the authenticated user's password (requires current password).</summary>
        Task<ServiceResult> ChangePasswordAsync(
            ChangePasswordRequest dto,
            Guid adminPublicId,
            int  internalUserId);

        /// <summary>
        /// Step 1 of email change: sends an OTP to the new email address.
        /// </summary>
        Task<ServiceResult> RequestChangeEmailAsync(RequestChangeEmailRequest dto, Guid currentUserId);

        /// <summary>
        /// Step 2 of email change: verifies the OTP and commits the new email.
        /// </summary>
        Task<ServiceResult> ChangeEmailAsync(
            VerifyOtpRequest dto,
            Guid    currentUserId,
            string? pendingNewEmail);

        /// <summary>Returns the public profile of the currently authenticated user.</summary>
        Task<ServiceResult> GetCurrentUserAsync(Guid currentUserId);

        /// <summary>Completes profile for first-time Google logins (sets name details + verifies OTP).</summary>
        Task<ServiceResult> CompleteProfileAsync(CompleteProfileRequest dto, string? pendingEmail, string? ip, string? deviceId, bool isOtpAlreadyVerified);

        /// <summary>Verifies the OTP for first-time Google logins before profile completion.</summary>
        Task<ServiceResult> VerifyProfileOtpAsync(VerifyOtpRequest dto, string? pendingEmail);

        /// <summary>Updates profile names for the current authenticated user.</summary>
        Task<ServiceResult> UpdateProfileAsync(UpdateProfileRequest dto, Guid currentUserId);

        /// <summary>Terminates the user's session and marks the device as logged out.</summary>
        ServiceResult Logout(int internalUserId, Guid publicUserId, string? deviceId);
    }
}
