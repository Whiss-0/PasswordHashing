using Api.DTOs;
using Api.Modules.UserModule;
using Api.Modules.AuthorizationModule;
using Api.Security;

namespace Api.Modules.AccountModule
{
    /// <inheritdoc />
    public sealed class AccountService : IAccountService
    {
        private readonly IUserRepository    _userRepository;
        private readonly IOtpService        _otpService;
        private readonly IOtpEmailSender    _otpEmailSender;
        private readonly IRefreshTokenStore _refreshTokenStore;
        private readonly ISessionService    _sessionService;
        private readonly IJwtTokenService   _jwtTokenService;

        public AccountService(
            IUserRepository    userRepository,
            IOtpService        otpService,
            IOtpEmailSender    otpEmailSender,
            IRefreshTokenStore refreshTokenStore,
            ISessionService    sessionService,
            IJwtTokenService   jwtTokenService)
        {
            _userRepository    = userRepository;
            _otpService        = otpService;
            _otpEmailSender    = otpEmailSender;
            _refreshTokenStore = refreshTokenStore;
            _sessionService    = sessionService;
            _jwtTokenService   = jwtTokenService;
        }

        // ── Password Reset ────────────────────────────────────────────────────

        public async Task<ServiceResult> ForgotPasswordAsync(ForgotPasswordRequest dto)
        {
            if (string.IsNullOrWhiteSpace(dto.Email))
                return ServiceResult.BadRequest("Email is required.");

            var user = await _userRepository.GetByEmailAsync(dto.Email);
            if (user != null)
            {
                var (rateLimited, otp) = await _otpService.GenerateAsync(user.UserId, "reset");
                if (!rateLimited)
                {
                    try { await _otpEmailSender.SendOtpAsync(dto.Email, otp!, "reset"); }
                    catch { /* Intentional — do not reveal existence of account */ }
                }
            }

            // Always return the same response to prevent email enumeration
            return ServiceResult.OkWithPending(
                new { message = "If an account with that email exists, an OTP has been sent." },
                user != null
                    ? new Dictionary<string, string> { ["pending_reset_email"] = dto.Email }
                    : new Dictionary<string, string>());
        }

        public async Task<ServiceResult> ResetPasswordAsync(
            ResetPasswordRequest dto, string? pendingEmail)
        {
            if (string.IsNullOrWhiteSpace(dto.OtpCode) ||
                string.IsNullOrWhiteSpace(dto.NewPassword))
                return ServiceResult.BadRequest("OTP code and new password are required.");

            if (string.IsNullOrWhiteSpace(pendingEmail))
                return ServiceResult.BadRequest(
                    "Password reset session expired. Please request a new OTP.", "SESSION_EXPIRED");

            var user = await _userRepository.GetByEmailAsync(pendingEmail);
            if (user == null)
                return ServiceResult.Unauthorized("OTP_INVALID", "Invalid OTP code.");

            var result = await _otpService.VerifyAsync(user.UserId, dto.OtpCode, "reset");
            if (result != OtpVerifyResult.Valid)
                return OtpFailResult(result);

            user.UserPass = PasswordHasher.Hash(dto.NewPassword);
            if (user.Status == "PROFILE_INCOMPLETE")
            {
                user.Status = "ACTIVE";
            }
            await _userRepository.UpdateAsync(user);

            _refreshTokenStore.RevokeRefreshToken(user.PublicId);
            _sessionService.MarkUserLoggedOut(user.UserId);

            return new ServiceResult
            {
                IsSuccess     = true,
                StatusCode    = 200,
                Payload       = new { message = "Password has been reset successfully. Please log in again." },
                ClearCookies  = ["pending_reset_email"],
                ShouldClearAuth = true
            };
        }

        // ── Authenticated Password Change ─────────────────────────────────────

        public async Task<ServiceResult> ChangePasswordAsync(
            ChangePasswordRequest dto,
            Guid currentUserId,
            int  internalUserId)
        {
            if (currentUserId == Guid.Empty)
                return ServiceResult.Unauthorized("UNAUTHENTICATED", "User not authenticated.");

            if (string.IsNullOrWhiteSpace(dto.CurrentPassword) ||
                string.IsNullOrWhiteSpace(dto.NewPassword))
                return ServiceResult.BadRequest("Current password and new password are required.");

            var user = await _userRepository.GetByIdAsync(currentUserId);
            if (user == null) return ServiceResult.Fail(404, null, "User not found.");

            bool isValid = PasswordHasher.IsHashed(user.UserPass)
                ? PasswordHasher.Verify(user.UserPass, dto.CurrentPassword)
                : string.Equals(user.UserPass, dto.CurrentPassword, StringComparison.Ordinal);

            if (!isValid)
                return ServiceResult.BadRequest("Current password is incorrect.");

            user.UserPass = PasswordHasher.Hash(dto.NewPassword);
            await _userRepository.UpdateAsync(user);

            _refreshTokenStore.RevokeRefreshToken(currentUserId);
            _sessionService.MarkUserLoggedOut(internalUserId);

            return new ServiceResult
            {
                IsSuccess       = true,
                StatusCode      = 200,
                Payload         = new { message = "Password changed successfully. Please log in again." },
                ShouldClearAuth = true
            };
        }

        // ── Email Change ──────────────────────────────────────────────────────

        public async Task<ServiceResult> RequestChangeEmailAsync(
            RequestChangeEmailRequest dto, Guid currentUserId)
        {
            if (currentUserId == Guid.Empty)
                return ServiceResult.Unauthorized("UNAUTHENTICATED", "User not authenticated.");

            if (string.IsNullOrWhiteSpace(dto.NewEmail))
                return ServiceResult.BadRequest("New email is required.");

            var conflict = await _userRepository.GetByEmailAsync(dto.NewEmail);
            if (conflict != null && conflict.PublicId != currentUserId)
                return ServiceResult.Conflict("EMAIL_TAKEN",
                    "Email is already in use by another account.");

            var user = await _userRepository.GetByIdAsync(currentUserId);
            if (user == null)
                return ServiceResult.Unauthorized("USER_NOT_FOUND", "User not found.");

            var (rateLimited, otp) = await _otpService.GenerateAsync(user.UserId, "change-email");
            if (rateLimited) return ServiceResult.TooManyRequests("RATE_LIMITED",
                "Too many OTP requests for this email. Please wait.");

            try { await _otpEmailSender.SendOtpAsync(dto.NewEmail, otp!, "change-email"); }
            catch (Exception ex)
            {
                Console.WriteLine($"[EMAIL CHANGE] SMTP failed → {dto.NewEmail}: {ex.Message}");
            }

            return ServiceResult.OkWithPending(
                new { message = "OTP sent to the new email address. Please verify to confirm the change." },
                new Dictionary<string, string> { ["pending_new_email"] = dto.NewEmail });
        }

        public async Task<ServiceResult> ChangeEmailAsync(
            VerifyOtpRequest dto, Guid currentUserId, string? pendingNewEmail)
        {
            if (currentUserId == Guid.Empty)
                return ServiceResult.Unauthorized("UNAUTHENTICATED", "User not authenticated.");

            if (string.IsNullOrWhiteSpace(dto.OtpCode))
                return ServiceResult.BadRequest("OTP code is required.");

            if (string.IsNullOrWhiteSpace(pendingNewEmail))
                return ServiceResult.BadRequest(
                    "Email change session expired. Please request a new OTP.", "SESSION_EXPIRED");

            var user = await _userRepository.GetByIdAsync(currentUserId);
            if (user == null)
                return ServiceResult.Unauthorized("USER_NOT_FOUND", "User not found.");

            var result = await _otpService.VerifyAsync(user.UserId, dto.OtpCode, "change-email");
            if (result != OtpVerifyResult.Valid)
                return OtpFailResult(result);

            var conflict = await _userRepository.GetByEmailAsync(pendingNewEmail);
            if (conflict != null && conflict.PublicId != currentUserId)
                return ServiceResult.Conflict("EMAIL_TAKEN",
                    "Email is already in use by another account.");

            user.UserEmail = pendingNewEmail;
            user.EmailVerified = true;
            await _userRepository.UpdateAsync(user);

            return new ServiceResult
            {
                IsSuccess    = true,
                StatusCode   = 200,
                Payload      = new { message = "Email updated successfully.", newEmail = pendingNewEmail },
                ClearCookies = ["pending_new_email"]
            };
        }

        // ── Profile & Session ─────────────────────────────────────────────────

        public async Task<ServiceResult> GetCurrentUserAsync(Guid currentUserId)
        {
            if (currentUserId == Guid.Empty)
                return ServiceResult.Unauthorized("UNAUTHENTICATED", "User not authenticated.");

            var user = await _userRepository.GetByIdAsync(currentUserId);
            if (user == null) return ServiceResult.Fail(404, null, "User not found.");

            return ServiceResult.Ok(payload: new
            {
                userId   = user.PublicId,
                dbUserId = user.UserId,
                username = user.UserName,
                email    = user.UserEmail,
                accessId = user.AccessId,
                userRole = user.UserRole,
                emailVerified = user.EmailVerified,
                status   = user.Status
            });
        }

        public async Task<ServiceResult> CompleteProfileAsync(
            CompleteProfileRequest dto, string? pendingEmail, string? ip, string? deviceId, bool isOtpAlreadyVerified)
        {
            if (string.IsNullOrWhiteSpace(dto.OtpCode))
                return ServiceResult.BadRequest("OTP code is required.");

            if (string.IsNullOrWhiteSpace(pendingEmail))
                return ServiceResult.BadRequest(
                    "Profile completion session expired. Please start again.", "SESSION_EXPIRED");

            var user = await _userRepository.GetByEmailAsync(pendingEmail);
            if (user == null)
                return ServiceResult.Unauthorized("USER_NOT_FOUND", "User not found.");

            if (!isOtpAlreadyVerified)
            {
                var result = await _otpService.VerifyAsync(user.UserId, dto.OtpCode, "profile-completion");
                if (result != OtpVerifyResult.Valid)
                    return OtpFailResult(result);
            }

            user.Status = "ACTIVE";
            user.EmailVerified = true;
            await _userRepository.UpdateAsync(user);

            deviceId ??= Guid.NewGuid().ToString();
            string token = _jwtTokenService.GenerateToken(user);
            string refreshToken = _refreshTokenStore.GenerateRefreshToken(
                user.PublicId, _jwtTokenService.RefreshTokenLifetime);

            _sessionService.MarkUserLoggedIn(user.UserId, user.RoleId, token, ip, deviceId);

            return ServiceResult.OkWithTokens(token, refreshToken, deviceId,
                new { 
                    message = "success", 
                    userId = user.PublicId,
                    dbUserId = user.UserId,
                    username = user.UserName, 
                    email = user.UserEmail, 
                    accessId = user.AccessId,
                    status = user.Status
                },
                clearCookies: new[] { "pending_login_email", "profile_otp_verified" });
        }

        public async Task<ServiceResult> VerifyProfileOtpAsync(
            VerifyOtpRequest dto, string? pendingEmail)
        {
            if (string.IsNullOrWhiteSpace(dto.OtpCode))
                return ServiceResult.BadRequest("OTP code is required.");

            if (string.IsNullOrWhiteSpace(pendingEmail))
                return ServiceResult.BadRequest(
                    "Profile completion session expired. Please start again.", "SESSION_EXPIRED");

            var user = await _userRepository.GetByEmailAsync(pendingEmail);
            if (user == null)
                return ServiceResult.Unauthorized("USER_NOT_FOUND", "User not found.");

            var result = await _otpService.VerifyAsync(user.UserId, dto.OtpCode, "profile-completion");
            if (result != OtpVerifyResult.Valid)
                return OtpFailResult(result);

            return ServiceResult.OkWithPending(
                new { message = "OTP verified successfully. Please complete your profile." },
                new Dictionary<string, string> { ["profile_otp_verified"] = "true" }
            );
        }

        public async Task<ServiceResult> UpdateProfileAsync(UpdateProfileRequest dto, Guid currentUserId)
        {
            if (currentUserId == Guid.Empty)
                return ServiceResult.Unauthorized("UNAUTHENTICATED", "User not authenticated.");

            var user = await _userRepository.GetByIdAsync(currentUserId);
            if (user == null)
                return ServiceResult.Fail(404, null, "User not found.");

            await _userRepository.UpdateAsync(user);

            return ServiceResult.Ok(payload: new
            {
                message = "Profile updated successfully.",
                username = user.UserName,
                email = user.UserEmail
            });
        }

        public ServiceResult Logout(int internalUserId, Guid publicUserId, string? deviceId)
        {
            if (internalUserId != 0)
                _sessionService.MarkUserLoggedOut(internalUserId);

            if (publicUserId != Guid.Empty)
                _refreshTokenStore.RevokeRefreshToken(publicUserId);

            if (!string.IsNullOrEmpty(deviceId))
                _sessionService.MarkDeviceLoggedOut(deviceId);

            return new ServiceResult
            {
                IsSuccess       = true,
                StatusCode      = 200,
                Payload         = new { message = "Logged out successfully." },
                ShouldClearAuth = true
            };
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private static ServiceResult OtpFailResult(OtpVerifyResult result) => result switch
        {
            OtpVerifyResult.Expired            => ServiceResult.Unauthorized("OTP_EXPIRED",
                "OTP has expired. Please request a new one."),
            OtpVerifyResult.MaxAttemptsReached => ServiceResult.Unauthorized("OTP_LOCKED",
                "Too many failed attempts. Please request a new OTP."),
            OtpVerifyResult.RateLimited        => ServiceResult.TooManyRequests("RATE_LIMITED",
                "Too many verification attempts. Please wait."),
            _                                  => ServiceResult.Unauthorized("OTP_INVALID",
                "Invalid OTP code.")
        };
    }
}

