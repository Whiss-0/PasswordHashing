using Api.DTOs;
using Api.Modules.AuthorizationModule;

namespace Api.Modules.RegisterModule
{
    /// <summary>
    /// Handles all user registration flows:
    /// standard register, OTP verification, admin-created accounts.
    /// </summary>
    public interface IRegistrationService
    {
        /// <summary>
        /// Initiates standard registration (username/password).
        /// Creates a PENDING user and sends an OTP.
        /// </summary>
        Task<ServiceResult> RegisterAsync(RegisterRequest dto);

        /// <summary>
        /// Verifies the OTP sent during registration, activates the account,
        /// and issues a JWT session.
        /// </summary>
        Task<ServiceResult> VerifyRegisterOtpAsync(
            string  otpCode,
            string? pendingEmail,
            string? deviceId,
            string? ip);

        /// <summary>
        /// Admin-initiated: stores a pending admin registration and sends an OTP
        /// to the requesting admin's email for confirmation.
        /// </summary>
        Task<ServiceResult> RegisterAdminAsync(RegisterAdminRequest dto, Guid adminPublicId);

        /// <summary>
        /// Verifies the admin's OTP and creates the new staff account.
        /// </summary>
        Task<ServiceResult> VerifyRegisterAdminOtpAsync(string otpCode, Guid adminPublicId);

        /// <summary>
        /// Resends an OTP based on the verification context and pending email cookie / admin public ID.
        /// </summary>
        Task<ServiceResult> ResendOtpAsync(string context, string? pendingEmail, Guid adminPublicId);
    }
}
