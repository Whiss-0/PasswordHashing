using Api.DTOs;
using Api.Modules.UserModule;
using Api.Modules.AuthorizationModule;
using Api.Security;
using Microsoft.AspNetCore.SignalR;

namespace Api.Modules.RegisterModule
{
    /// <inheritdoc />
    public sealed class RegistrationService : IRegistrationService
    {
        private readonly IUserRepository           _userRepository;
        private readonly IOtpService               _otpService;
        private readonly IOtpEmailSender           _otpEmailSender;
        private readonly IPendingAdminRegStore      _pendingAdminRegStore;
        private readonly IJwtTokenService          _jwtTokenService;
        private readonly IRefreshTokenStore        _refreshTokenStore;
        private readonly ISessionService           _sessionService;
        private readonly IHubContext<DashboardHub> _hub;

        public RegistrationService(
            IUserRepository           userRepository,
            IOtpService               otpService,
            IOtpEmailSender           otpEmailSender,
            IPendingAdminRegStore      pendingAdminRegStore,
            IJwtTokenService          jwtTokenService,
            IRefreshTokenStore        refreshTokenStore,
            ISessionService           sessionService,
            IHubContext<DashboardHub> hub)
        {
            _userRepository      = userRepository;
            _otpService          = otpService;
            _otpEmailSender      = otpEmailSender;
            _pendingAdminRegStore = pendingAdminRegStore;
            _jwtTokenService     = jwtTokenService;
            _refreshTokenStore   = refreshTokenStore;
            _sessionService      = sessionService;
            _hub                 = hub;
        }

        // ── Standard Registration ─────────────────────────────────────────────

        public async Task<ServiceResult> RegisterAsync(RegisterRequest dto)
        {
            if (string.IsNullOrWhiteSpace(dto.Username) ||
                string.IsNullOrWhiteSpace(dto.Password) ||
                string.IsNullOrWhiteSpace(dto.Email)    ||
                !IsValidEmail(dto.Email))
                return ServiceResult.BadRequest("error");

            var existingByName  = await _userRepository.GetByUserNameAsync(dto.Username);
            var existingByEmail = await _userRepository.GetByEmailAsync(dto.Email);
            User? user = existingByEmail ?? existingByName;

            // Anti-enumeration: pretend we sent an OTP for already-active accounts
            if (user != null && user.Status == "ACTIVE")
                return ServiceResult.OkWithPending(
                    new { message = "next_step" },
                    new Dictionary<string, string> { ["pending_registration_email"] = dto.Email });

            if (user == null)
            {
                user = new User
                {
                    UserName  = dto.Username,
                    UserPass  = PasswordHasher.Hash(dto.Password),
                    UserEmail = dto.Email,
                    AccessId  = AppRoles.User,
                    Status    = "PENDING"
                };
                await _userRepository.AddAsync(user);
            }
            else
            {
                user.UserPass = PasswordHasher.Hash(dto.Password);
                await _userRepository.UpdateAsync(user);
            }

            var (rateLimited, otp) = await _otpService.GenerateAsync(user.UserId, "register");
            if (rateLimited) return ServiceResult.TooManyRequests();

            await TrySendOtpAsync(dto.Email, otp!, "register");

            return ServiceResult.OkWithPending(
                new { message = "next_step" },
                new Dictionary<string, string> { ["pending_registration_email"] = dto.Email });
        }

        public async Task<ServiceResult> VerifyRegisterOtpAsync(
            string  otpCode,
            string? pendingEmail,
            string? deviceId,
            string? ip)
        {
            if (string.IsNullOrWhiteSpace(pendingEmail))
                return ServiceResult.BadRequest(
                    "Registration session expired. Please register again.", "SESSION_EXPIRED");

            var user = await _userRepository.GetByEmailAsync(pendingEmail);
            if (user == null || user.Status != "PENDING")
                return ServiceResult.Unauthorized(null, "error");

            var result = await _otpService.VerifyAsync(user.UserId, otpCode, "register");
            if (result != OtpVerifyResult.Valid)
                return OtpFailResult(result);

            user.Status = "ACTIVE";
            user.EmailVerified = true;
            await _userRepository.UpdateAsync(user);

            deviceId ??= Guid.NewGuid().ToString();
            string token        = _jwtTokenService.GenerateToken(user);
            string refreshToken = _refreshTokenStore.GenerateRefreshToken(
                user.PublicId, _jwtTokenService.RefreshTokenLifetime);

            _sessionService.MarkUserLoggedIn(user.UserId, user.RoleId, token, ip, deviceId);

            return ServiceResult.OkWithTokens(token, refreshToken, deviceId,
                new { message = "success" },
                clearCookies: ["pending_registration_email"]);
        }

        // ── Admin-Created Registration ─────────────────────────────────────────

        public async Task<ServiceResult> RegisterAdminAsync(RegisterAdminRequest dto, Guid adminPublicId)
        {
            if (string.IsNullOrWhiteSpace(dto.Username) ||
                string.IsNullOrWhiteSpace(dto.Password) ||
                string.IsNullOrWhiteSpace(dto.Email))
                return ServiceResult.BadRequest("Username, email, and password are required.");

            if (dto.RoleId < 1 || dto.RoleId > 3)
                return ServiceResult.BadRequest(
                    "Invalid role. Allowed: 1=Admin, 2=Staff, 3=User.");

            var existingUsername = await _userRepository.GetByUserNameIncludingDeletedAsync(dto.Username);
            if (existingUsername != null)
            {
                if (existingUsername.IsDeleted)
                    return ServiceResult.Conflict("ACCOUNT_DELETED", "A deleted account with this username exists. You can restore it from the Account Restoration panel.");
                return ServiceResult.Conflict("DUPLICATE_USERNAME", "Username is already taken.");
            }

            var existingEmail = await _userRepository.GetByEmailIncludingDeletedAsync(dto.Email);
            if (existingEmail != null)
            {
                if (existingEmail.IsDeleted)
                    return ServiceResult.Conflict("ACCOUNT_DELETED", "A deleted account with this email exists. You can restore it from the Account Restoration panel.");
                return ServiceResult.Conflict("DUPLICATE_EMAIL", "An account with that email already exists.");
            }

            if (adminPublicId == Guid.Empty)
                return ServiceResult.Unauthorized("UNAUTHENTICATED", "Cannot identify the requesting admin.");

            var adminUser = await _userRepository.GetByIdAsync(adminPublicId);
            if (adminUser == null)
                return ServiceResult.Unauthorized("USER_NOT_FOUND", "Admin user not found.");

            _pendingAdminRegStore.Save(adminPublicId, new PendingAdminReg(
                Username:       dto.Username,
                HashedPassword: PasswordHasher.Hash(dto.Password),
                Email:          dto.Email,
                RoleId:         dto.RoleId,
                ExpiresAt:      DateTime.UtcNow.AddMinutes(15)));

            var (rateLimited, otp) = await _otpService.GenerateAsync(adminUser.UserId, "register-admin");
            if (rateLimited) return ServiceResult.TooManyRequests("RATE_LIMITED",
                "Too many OTP requests. Please wait.");

            await TrySendOtpAsync(adminUser.UserEmail, otp!, "register-admin");

            return ServiceResult.Ok("OTP has been sent to your email. Verify to complete registration.",
                new { code = "OTP_REQUIRED",
                      message = "An OTP has been sent to your email. Verify to complete registration." });
        }

        public async Task<ServiceResult> VerifyRegisterAdminOtpAsync(string otpCode, Guid adminPublicId)
        {
            if (adminPublicId == Guid.Empty)
                return ServiceResult.Unauthorized("UNAUTHENTICATED", "Not authenticated.");

            var pending = _pendingAdminRegStore.Get(adminPublicId);
            if (pending == null)
                return ServiceResult.BadRequest(
                    "Registration session expired. Please start again.", "SESSION_EXPIRED");

            var adminUser = await _userRepository.GetByIdAsync(adminPublicId);
            if (adminUser == null)
                return ServiceResult.Unauthorized("USER_NOT_FOUND", "Admin user not found.");

            var result = await _otpService.VerifyAsync(adminUser.UserId, otpCode, "register-admin");
            if (result != OtpVerifyResult.Valid)
                return OtpFailResult(result);

            var existingUser = await _userRepository.GetByEmailIncludingDeletedAsync(pending.Email)
                ?? await _userRepository.GetByUserNameIncludingDeletedAsync(pending.Username);

            if (existingUser != null)
            {
                existingUser.UserName  = pending.Username;
                existingUser.UserEmail = pending.Email;
                existingUser.UserPass  = pending.HashedPassword;
                existingUser.AccessId  = pending.RoleId;
                existingUser.Status    = "ACTIVE";
                existingUser.IsDeleted = false;
                await _userRepository.RestoreAsync(existingUser.PublicId);
                await _userRepository.UpdateAsync(existingUser);
            }
            else
            {
                var newUser = new User
                {
                    UserName      = pending.Username,
                    UserPass      = pending.HashedPassword,
                    UserEmail     = pending.Email,
                    AccessId      = pending.RoleId,
                    Status        = "ACTIVE",
                    EmailVerified = true
                };
                await _userRepository.AddAsync(newUser);
            }
            _pendingAdminRegStore.Remove(adminPublicId);

            if (pending.RoleId == AppRoles.Admin)
            {
                await _userRepository.RetireDefaultAdminAsync();
                await _hub.Clients.Group("AdminContent")
                    .SendAsync("ReceiveSecurityAlert",
                        "⚠️ Default admin account has been automatically retired. A permanent admin has been created.");
                Console.WriteLine("[SECURITY] Default admin retired — permanent admin account created.");
            }

            var created = await _userRepository.GetByUserNameAsync(pending.Username);

            await _hub.Clients.Group("AdminContent")
                .SendAsync("ReceiveSecurityAlert",
                    $"New staff account registered: {pending.Username} (role {pending.RoleId})");

            return ServiceResult.Ok("User created successfully.",
                new
                {
                    message  = "User created successfully.",
                    userId   = created?.PublicId,
                    username = created?.UserName,
                    email    = created?.UserEmail,
                    roleId   = created?.RoleId,
                    accessId = created?.AccessId
                });
        }

        public async Task<ServiceResult> ResendOtpAsync(string context, string? pendingEmail, Guid adminPublicId)
        {
            if (context == "register-admin")
            {
                if (adminPublicId == Guid.Empty)
                    return ServiceResult.Unauthorized("UNAUTHENTICATED", "Cannot identify the requesting admin.");

                var adminUser = await _userRepository.GetByIdAsync(adminPublicId);
                if (adminUser == null)
                    return ServiceResult.Unauthorized("USER_NOT_FOUND", "Admin user not found.");

                var (rateLimited, otp) = await _otpService.GenerateAsync(adminUser.UserId, "register-admin");
                if (rateLimited) return ServiceResult.TooManyRequests("RATE_LIMITED",
                    "Too many OTP requests. Please wait.");

                await TrySendOtpAsync(adminUser.UserEmail, otp!, "register-admin");
                return ServiceResult.Ok("OTP has been resent to your email.");
            }
            else
            {
                if (string.IsNullOrWhiteSpace(pendingEmail))
                    return ServiceResult.BadRequest("Session expired. Please request a new OTP by starting again.", "SESSION_EXPIRED");

                var user = await _userRepository.GetByEmailAsync(pendingEmail);
                if (user == null)
                    return ServiceResult.Unauthorized("USER_NOT_FOUND", "User account not found.");

                string purpose = context switch
                {
                    "login" => "login",
                    "reset" => "reset",
                    "profile-completion" => "profile-completion",
                    "register" => "register",
                    _ => "login"
                };

                var (rateLimited, otp) = await _otpService.GenerateAsync(user.UserId, purpose);
                if (rateLimited) return ServiceResult.TooManyRequests("RATE_LIMITED",
                    "Too many OTP requests. Please wait.");

                await TrySendOtpAsync(user.UserEmail, otp!, purpose);
                return ServiceResult.Ok("OTP has been resent to your email.");
            }
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private static ServiceResult OtpFailResult(OtpVerifyResult result) => result switch
        {
            OtpVerifyResult.Expired            => ServiceResult.Unauthorized("OTP_EXPIRED",  "OTP has expired. Please start again."),
            OtpVerifyResult.MaxAttemptsReached => ServiceResult.Unauthorized("OTP_LOCKED",   "Too many failed attempts."),
            OtpVerifyResult.RateLimited        => ServiceResult.TooManyRequests("RATE_LIMITED", "Rate limited."),
            _                                  => ServiceResult.Unauthorized("OTP_INVALID",  "Invalid OTP code.")
        };

        private async Task TrySendOtpAsync(string email, string code, string purpose)
        {
            try   { await _otpEmailSender.SendOtpAsync(email, code, purpose); }
            catch (Exception ex)
            {
                Console.WriteLine($"[REGISTRATION] SMTP failed ({purpose}) → {email}: {ex.Message}");
                Console.WriteLine($"[DEVELOPER FALLBACK] OTP code: {code}");
            }
        }

        private static bool IsValidEmail(string email)
        {
            try
            {
                var addr = new System.Net.Mail.MailAddress(email);
                return addr.Address == email;
            }
            catch { return false; }
        }
    }
}

