using Api.DTOs;
using Api.Modules.UserModule;
using Api.Modules.AuthorizationModule;
using Api.Security;
using Microsoft.AspNetCore.SignalR;

namespace Api.Modules.LoginModule
{
    /// <inheritdoc />
    public sealed class LoginService : ILoginService
    {
        private readonly IUserRepository           _userRepository;
        private readonly IOtpService               _otpService;
        private readonly IOtpEmailSender           _otpEmailSender;
        private readonly IJwtTokenService          _jwtTokenService;
        private readonly IRefreshTokenStore        _refreshTokenStore;
        private readonly ISessionService           _sessionService;
        private readonly ILoginAttemptService      _loginAttemptService;
        private readonly IGoogleAuthService        _googleAuthService;
        private readonly IHubContext<DashboardHub> _hub;

        public LoginService(
            IUserRepository           userRepository,
            IOtpService               otpService,
            IOtpEmailSender           otpEmailSender,
            IJwtTokenService          jwtTokenService,
            IRefreshTokenStore        refreshTokenStore,
            ISessionService           sessionService,
            ILoginAttemptService      loginAttemptService,
            IGoogleAuthService        googleAuthService,
            IHubContext<DashboardHub> hub)
        {
            _userRepository      = userRepository;
            _otpService          = otpService;
            _otpEmailSender      = otpEmailSender;
            _jwtTokenService     = jwtTokenService;
            _refreshTokenStore   = refreshTokenStore;
            _sessionService      = sessionService;
            _loginAttemptService = loginAttemptService;
            _googleAuthService   = googleAuthService;
            _hub                 = hub;
        }

        // ── Standard Login ────────────────────────────────────────────────────

        public async Task<ServiceResult> LoginAsync(LoginRequest dto, string? ip, string? deviceId)
        {
            if (string.IsNullOrWhiteSpace(dto.Username) || string.IsNullOrWhiteSpace(dto.Password))
                return ServiceResult.BadRequest("Username and password are required.");

            if (string.Equals(dto.Username, "admin", StringComparison.OrdinalIgnoreCase))
            {
                await _userRepository.EnsureAdminSafetyAsync();
            }

            var user = await _userRepository.GetByUserNameAsync(dto.Username);
            if (user == null)
            {
                await _loginAttemptService.LogAsync(null, dto.Username, false, ip, deviceId);
                return ServiceResult.Unauthorized(null, "error");
            }

            // ── Auto-retire default admin if other active admins exist ────────
            if (string.Equals(user.UserName, "admin", StringComparison.OrdinalIgnoreCase) && user.AccessId == AppRoles.Admin)
            {
                if (await _userRepository.HasOtherActiveAdminAsync())
                {
                    await _userRepository.RetireDefaultAdminAsync();
                    user.Status = "RETIRED";
                    await _loginAttemptService.LogAsync(user.UserId, dto.Username, false, ip, deviceId);
                    return ServiceResult.Unauthorized("DEFAULT_ADMIN_RETIRED", "Default admin account has been retired because permanent admin accounts exist.");
                }
            }

            // ── Password verification with legacy-hash upgrade ────────────────
            bool isValid;
            if (PasswordHasher.IsLegacyHash(user.UserPass))
            {
                isValid = PasswordHasher.VerifyLegacy(user.UserPass, dto.Password);
                if (isValid)
                {
                    user.UserPass = PasswordHasher.Hash(dto.Password);
                    await _userRepository.UpdateAsync(user);
                }
            }
            else if (PasswordHasher.IsHashed(user.UserPass))
                isValid = PasswordHasher.Verify(user.UserPass, dto.Password);
            else
            {
                isValid = string.Equals(user.UserPass, dto.Password, StringComparison.Ordinal);
                if (isValid) { user.UserPass = PasswordHasher.Hash(dto.Password); await _userRepository.UpdateAsync(user); }
            }

            if (!isValid)
            {
                await _loginAttemptService.LogAsync(user.UserId, dto.Username, false, ip, deviceId);
                return ServiceResult.Unauthorized(null, "error");
            }

            if (user.Status == "PENDING")
                return ServiceResult.Unauthorized("ACCOUNT_PENDING", "Account not yet verified.");

            if (user.Status != "ACTIVE")
                return ServiceResult.Unauthorized(null, "error");

            deviceId ??= Guid.NewGuid().ToString();

            // ── Trusted device — skip OTP ─────────────────────────────────────
            if (!string.IsNullOrEmpty(deviceId) &&
                _sessionService.IsDeviceTrustedForUser(user.UserId, deviceId))
            {
                string trustedToken   = _jwtTokenService.GenerateToken(user);
                string trustedRefresh = _refreshTokenStore.GenerateRefreshToken(
                    user.PublicId, _jwtTokenService.RefreshTokenLifetime);

                _sessionService.MarkUserLoggedIn(user.UserId, user.RoleId, trustedToken, ip, deviceId);
                await _loginAttemptService.LogAsync(user.UserId, user.UserName, true, ip, deviceId);

                Console.WriteLine($"[LOGIN] Trusted device login for '{user.UserName}' — OTP skipped.");
                return ServiceResult.OkWithTokens(trustedToken, trustedRefresh, deviceId,
                    new { message = "success", userId = user.PublicId, dbUserId = user.UserId,
                          username = user.UserName, email = user.UserEmail, roleId = user.RoleId, accessId = user.AccessId });
            }

            // ── Default admin — skip OTP for bootstrapping convenience ────────
            if (string.Equals(user.UserName, "admin", StringComparison.OrdinalIgnoreCase) && user.AccessId == AppRoles.Admin)
            {
                string adminToken   = _jwtTokenService.GenerateToken(user);
                string adminRefresh = _refreshTokenStore.GenerateRefreshToken(
                    user.PublicId, _jwtTokenService.RefreshTokenLifetime);

                _sessionService.MarkUserLoggedIn(user.UserId, user.RoleId, adminToken, ip, deviceId);
                await _loginAttemptService.LogAsync(user.UserId, user.UserName, true, ip, deviceId);

                Console.WriteLine($"[LOGIN] Default admin '{user.UserName}' logged in — OTP bypassed.");
                return ServiceResult.OkWithTokens(adminToken, adminRefresh, deviceId,
                    new { message = "success", userId = user.PublicId, dbUserId = user.UserId,
                          username = user.UserName, email = user.UserEmail, roleId = user.RoleId, accessId = user.AccessId });
            }

            // ── Conflict checks ───────────────────────────────────────────────
            if (!string.IsNullOrEmpty(deviceId) && _sessionService.IsDeviceLoggedIn(deviceId))
            {
                _sessionService.MarkDeviceLoggedOut(deviceId);
            }
            // ── Stale session cleanup: clear any leaked open session ──────────
            if (_sessionService.IsUserLoggedIn(user.UserId))
            {
                // Session still open in DB (e.g. inactivity logout missed the backend).
                // Evict it silently so the user can log in fresh.
                _sessionService.MarkUserLoggedOut(user.UserId);
            }

            // ── Unknown device — send OTP ─────────────────────────────────────
            var (rateLimited, otp) = await _otpService.GenerateAsync(user.UserId, "login");
            if (rateLimited) return ServiceResult.TooManyRequests("RATE_LIMITED",
                "Too many OTP requests. Please wait.");

            await TrySendOtpAsync(user.UserEmail, otp!, "login");

            await _loginAttemptService.LogAsync(user.UserId, user.UserName, true, ip, deviceId);

            Console.WriteLine($"[LOGIN] OTP sent to '{user.UserEmail}' for '{user.UserName}'.");
            return ServiceResult.OkWithPending(
                new { code = "OTP_REQUIRED",
                      message = "An OTP has been sent to your email. Please verify to complete login." },
                new Dictionary<string, string>
                {
                    ["pending_login_email"] = user.UserEmail,
                    ["pending_device_id"]   = deviceId
                });
        }

        // ── Login OTP Verification ────────────────────────────────────────────

        public async Task<ServiceResult> VerifyLoginOtpAsync(
            string  otpCode,
            string? pendingEmail,
            string? pendingDeviceId,
            string? ip,
            bool    trustDevice = true)
        {
            if (string.IsNullOrWhiteSpace(pendingEmail))
                return ServiceResult.BadRequest(
                    "Login session expired. Please log in again.", "SESSION_EXPIRED");

            var user = await _userRepository.GetByEmailAsync(pendingEmail);
            if (user == null) return ServiceResult.Unauthorized(null, "error");

            var result = await _otpService.VerifyAsync(user.UserId, otpCode, "login");
            if (result != OtpVerifyResult.Valid)
                return OtpFailResult(result);

            var deviceId = pendingDeviceId ?? Guid.NewGuid().ToString();

            if (!string.IsNullOrEmpty(deviceId) && _sessionService.IsDeviceLoggedIn(deviceId))
            {
                _sessionService.MarkDeviceLoggedOut(deviceId);
            }
            if (_sessionService.IsUserLoggedIn(user.UserId))
            {
                // Stale open session — evict silently so OTP verification can complete.
                _sessionService.MarkUserLoggedOut(user.UserId);
            }

            if (user.Status == "PENDING")
            {
                user.Status = "ACTIVE";
                user.EmailVerified = true;
                await _userRepository.UpdateAsync(user);
                await _hub.Clients.Group("AdminContent")
                    .SendAsync("ReceiveSecurityAlert", $"New user registered: {user.UserName}");
            }

            string token        = _jwtTokenService.GenerateToken(user);
            string refreshToken = _refreshTokenStore.GenerateRefreshToken(
                user.PublicId, _jwtTokenService.RefreshTokenLifetime);

            _sessionService.MarkUserLoggedIn(user.UserId, user.RoleId, token, ip, deviceId, trustDevice);
            await _loginAttemptService.LogAsync(user.UserId, user.UserName, true, ip, deviceId);

            await _hub.Clients.Group($"User_{user.PublicId}")
                .SendAsync("ReceiveSecurityAlert", $"New login detected from IP: {ip}");

            return ServiceResult.OkWithTokens(token, refreshToken, deviceId,
                new { message = "success", userId = user.PublicId, dbUserId = user.UserId,
                      username = user.UserName, email = user.UserEmail, roleId = user.RoleId, accessId = user.AccessId },
                clearCookies: ["pending_device_id", "pending_login_email", "pending_registration_email"]);
        }

        // ── Google OAuth Login ────────────────────────────────────────────────

        public async Task<ServiceResult> GoogleLoginAsync(
            GoogleLoginRequest dto, string? ip, string? deviceId)
        {
            if (string.IsNullOrWhiteSpace(dto.IdToken))
                return ServiceResult.BadRequest("Google ID token is required.");

            var payload = await _googleAuthService.ValidateTokenAsync(dto.IdToken);
            if (payload == null)
                return ServiceResult.Unauthorized("GOOGLE_TOKEN_INVALID",
                    "Invalid or expired Google token.");

            if (!payload.EmailVerified)
                return ServiceResult.Unauthorized("GOOGLE_EMAIL_UNVERIFIED",
                    "Google account email is not verified.");

            var googleId    = payload.Subject;
            var googleEmail = payload.Email;
            var googleName  = payload.Name ?? googleEmail.Split('@')[0];

            deviceId ??= Guid.NewGuid().ToString();

            // ── Look up by google_id, then fall back to email ─────────────────
            User? user = await _userRepository.GetByGoogleIdAsync(googleId);

            if (user == null)
            {
                user = await _userRepository.GetByEmailAsync(googleEmail);

                if (user != null)
                {
                    await _userRepository.LinkGoogleIdAsync(user.UserId, googleId, googleEmail);

                    if (user.Status == "PENDING")
                    {
                        user.Status = "ACTIVE";
                        user.EmailVerified = true;
                        await _userRepository.UpdateAsync(user);
                        await _hub.Clients.Group("AdminContent")
                            .SendAsync("ReceiveSecurityAlert",
                                $"User activated via Google OAuth: {user.UserName}");
                    }
                }
                else
                {
                    string baseUsername = SanitizeUsername(googleName);
                    string username     = baseUsername;

                    if (await _userRepository.GetByUserNameAsync(username) != null)
                        username = baseUsername + "_" + Guid.NewGuid().ToString("N")[..6];

                    user = new User
                    {
                        UserName      = username,
                        UserEmail     = googleEmail,
                        UserPass      = string.Empty,
                        AccessId      = AppRoles.User,
                        Status        = "ACTIVE",
                        EmailVerified = true
                    };
                    await _userRepository.AddAsync(user);
                    user = await _userRepository.GetByEmailAsync(googleEmail);
                    if (user == null) return ServiceResult.ServerError("Failed to create user account.");

                    await _userRepository.LinkGoogleIdAsync(user.UserId, googleId, googleEmail);

                    await _hub.Clients.Group("AdminContent")
                        .SendAsync("ReceiveSecurityAlert",
                            $"New user registered via Google: {user.UserName}");
                }
            }

            // ── Trusted device — skip OTP ─────────────────────────────────────
            if (!string.IsNullOrEmpty(deviceId) &&
                _sessionService.IsDeviceTrustedForUser(user.UserId, deviceId))
            {
                string trustedToken   = _jwtTokenService.GenerateToken(user);
                string trustedRefresh = _refreshTokenStore.GenerateRefreshToken(
                    user.PublicId, _jwtTokenService.RefreshTokenLifetime);

                _sessionService.MarkUserLoggedIn(user.UserId, user.RoleId, trustedToken, ip, deviceId);
                await _loginAttemptService.LogAsync(user.UserId, user.UserName, true, ip, deviceId);

                Console.WriteLine($"[GOOGLE LOGIN] Trusted device login for '{user.UserName}' — OTP skipped.");
                return ServiceResult.OkWithTokens(trustedToken, trustedRefresh, deviceId,
                    new { message = "success", userId = user.PublicId, dbUserId = user.UserId,
                          username = user.UserName, email = user.UserEmail, roleId = user.RoleId, accessId = user.AccessId });
            }

            // ── Stale session cleanup & Conflict check ─────────────────────────
            if (!string.IsNullOrEmpty(deviceId) && _sessionService.IsDeviceLoggedIn(deviceId))
            {
                _sessionService.MarkDeviceLoggedOut(deviceId);
            }
            if (_sessionService.IsUserLoggedIn(user.UserId))
            {
                _sessionService.MarkUserLoggedOut(user.UserId);
            }

            // ── Unknown / untrusted device — send OTP security email ──────────
            var (rateLimited, otp) = await _otpService.GenerateAsync(user.UserId, "login");
            if (rateLimited) return ServiceResult.TooManyRequests("RATE_LIMITED",
                "Too many OTP requests. Please wait.");

            await TrySendOtpAsync(user.UserEmail, otp!, "login");

            await _loginAttemptService.LogAsync(user.UserId, user.UserName, true, ip, deviceId);

            Console.WriteLine($"[GOOGLE LOGIN] OTP sent to '{user.UserEmail}' for '{user.UserName}'.");
            return ServiceResult.OkWithPending(
                new { code = "OTP_REQUIRED",
                      message = "An OTP has been sent to your email to authorize this device. Please verify to complete login." },
                new Dictionary<string, string>
                {
                    ["pending_login_email"] = user.UserEmail,
                    ["pending_device_id"]   = deviceId
                });
        }

        // ── Token Refresh ─────────────────────────────────────────────────────

        public async Task<ServiceResult> RefreshAsync(string? accessToken, string? refreshToken)
        {
            if (string.IsNullOrEmpty(accessToken))
                return ServiceResult.Unauthorized("MISSING_TOKEN", "Access token is required.");

            var userId = _jwtTokenService.GetUserIdFromExpiredToken(accessToken);
            if (userId == null)
                return ServiceResult.Unauthorized("INVALID_TOKEN", "Cannot parse access token.");

            if (string.IsNullOrEmpty(refreshToken))
                return ServiceResult.Unauthorized("MISSING_REFRESH_TOKEN",
                    "Refresh token cookie is missing.");

            bool isValid = _refreshTokenStore.ValidateRefreshToken(userId.Value, refreshToken, out _);
            if (!isValid)
                return ServiceResult.Unauthorized("INVALID_REFRESH_TOKEN",
                    "Refresh token is invalid or expired. Please log in again.");

            var user = await _userRepository.GetByIdAsync(userId.Value);
            if (user == null)
                return ServiceResult.Unauthorized("USER_NOT_FOUND", "User no longer exists.");

            string newAccessToken  = _jwtTokenService.GenerateToken(user);
            string newRefreshToken = _refreshTokenStore.GenerateRefreshToken(
                user.PublicId, _jwtTokenService.RefreshTokenLifetime);

            _sessionService.MarkUserLoggedIn(user.UserId, newAccessToken);

            return ServiceResult.OkWithTokens(newAccessToken, newRefreshToken, string.Empty,
                new
                {
                    message   = "Token refreshed successfully.",
                    token     = newAccessToken,
                    userId    = user.PublicId,
                    dbUserId  = user.UserId,
                    username  = user.UserName,
                    email     = user.UserEmail,
                    roleId    = user.RoleId,
                    accessId  = user.AccessId,
                    expiresIn = (int)_jwtTokenService.AccessTokenLifetime.TotalSeconds
                });
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private static ServiceResult OtpFailResult(OtpVerifyResult result) => result switch
        {
            OtpVerifyResult.RateLimited        => ServiceResult.TooManyRequests(),
            OtpVerifyResult.Expired            => ServiceResult.Unauthorized("OTP_EXPIRED",
                "OTP has expired. Please log in again."),
            _                                  => ServiceResult.Unauthorized("OTP_INVALID",
                "Invalid OTP code.")
        };

        private async Task TrySendOtpAsync(string email, string code, string purpose)
        {
            try   { await _otpEmailSender.SendOtpAsync(email, code, purpose); }
            catch (Exception ex)
            {
                Console.WriteLine($"[LOGIN] SMTP failed ({purpose}) → {email}: {ex.Message}");
                Console.WriteLine($"[DEVELOPER FALLBACK] OTP code: {code}");
            }
        }

        private static string SanitizeUsername(string displayName)
        {
            if (string.IsNullOrWhiteSpace(displayName)) return "user";
            var sanitized = new string(
                displayName.ToLowerInvariant().Replace(' ', '_')
                    .Where(c => char.IsLetterOrDigit(c) || c == '_').ToArray());
            if (string.IsNullOrEmpty(sanitized)) sanitized = "user";
            return sanitized.Length > 45 ? sanitized[..45] : sanitized;
        }
    }
}

