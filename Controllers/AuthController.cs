using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;
using Api.Modules.AuthorizationModule;
using Api.Modules.RegisterModule;
using Api.Modules.LoginModule;
using Api.Modules.AccountModule;
using Api.DTOs;
using Api.Security;
using Api.HTTP;

namespace Api.Controllers
{
    /// <summary>
    /// Authentication and account management endpoints.
    ///
    /// This controller is intentionally thin — it only handles HTTP concerns:
    ///   • Reading cookies, headers, and identity claims  (via <see cref="IRequestsContext"/>).
    ///   • Delegating all business logic to the services in Authorization/Services/.
    ///   • Applying cookie writes/clears and HTTP status codes (via <see cref="IHttpResponse"/>).
    ///
    /// To add or change logic, edit the relevant service:
    ///   • <see cref="IRegistrationService"/> — register, OTP, admin accounts
    ///   • <see cref="ILoginService"/>         — login, Google OAuth, token refresh
    ///   • <see cref="IAccountService"/>       — passwords, email, profile, logout
    /// </summary>
    [ApiController]
    [Route("api/auth")]
    [EnableCors("AllowAll")]
    [Authorize(Policy = AppPolicies.AdminOnly)]
    public class AuthController : ControllerBase
    {
        private readonly IRegistrationService _registration;
        private readonly ILoginService        _login;
        private readonly IAccountService      _account;
        private readonly IHttpResponse        _http;
        private readonly IRequestContext     _req;

        public AuthController(
            IRegistrationService registration,
            ILoginService        login,
            IAccountService      account,
            IHttpResponse        http,
            IRequestContext     req)
        {
            _registration = registration;
            _login        = login;
            _account      = account;
            _http         = http;
            _req          = req;
        }

        [AllowAnonymous]
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest dto)
            => _http.ApplyAndRespond(await _registration.RegisterAsync(dto));

        [AllowAnonymous]
        [HttpPost("register/verify-otp")]
        public async Task<IActionResult> VerifyRegisterOtp([FromBody] VerifyOtpRequest dto)
            => _http.ApplyAndRespond(await _registration.VerifyRegisterOtpAsync(
                dto.OtpCode,
                _req.Cookie("pending_registration_email"),
                _req.Cookie("device_id"),
                _req.ClientIp()));

        [HttpPost("register-admin")]
        [Authorize(Policy = AppPolicies.AdminOnly)]
        public async Task<IActionResult> RegisterAdmin([FromBody] RegisterAdminRequest dto)
            => _http.ApplyAndRespond(await _registration.RegisterAdminAsync(dto, _req.CurrentUserId));

        [HttpPost("register-admin/verify-otp")]
        [Authorize(Policy = AppPolicies.AdminOnly)]
        public async Task<IActionResult> VerifyRegisterAdminOtp([FromBody] VerifyOtpRequest dto)
            => _http.ApplyAndRespond(await _registration.VerifyRegisterAdminOtpAsync(
                dto.OtpCode, _req.CurrentUserId));

        [AllowAnonymous]
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest dto)
            => _http.ApplyAndRespond(await _login.LoginAsync(
                dto, _req.ClientIp(), _req.Cookie("device_id")));

        [AllowAnonymous]
        [HttpPost("login/verify-otp")]
        public async Task<IActionResult> VerifyLoginOtp([FromBody] VerifyOtpRequest dto)
        {
            // Accept either the login cookie or the registration cookie
            var pendingEmail = _req.Cookie("pending_login_email")
                            ?? _req.Cookie("pending_registration_email");

            return _http.ApplyAndRespond(await _login.VerifyLoginOtpAsync(
                dto.OtpCode,
                pendingEmail,
                _req.Cookie("pending_device_id"),
                _req.ClientIp(),
                dto.TrustDevice));
        }

        [AllowAnonymous]
        [HttpPost("resend-otp")]
        public async Task<IActionResult> ResendOtp([FromBody] ResendOtpRequest dto)
        {
            string? pendingEmail = dto.Context switch
            {
                "login" => _req.Cookie("pending_login_email"),
                "profile-completion" => _req.Cookie("pending_login_email"),
                "register" => _req.Cookie("pending_registration_email"),
                "reset" => _req.Cookie("pending_reset_email"),
                _ => null
            };

            return _http.ApplyAndRespond(await _registration.ResendOtpAsync(
                dto.Context, pendingEmail, _req.CurrentUserId));
        }

        [AllowAnonymous]
        [HttpPost("google")]
        public async Task<IActionResult> GoogleLogin([FromBody] GoogleLoginRequest dto)
            => _http.ApplyAndRespond(await _login.GoogleLoginAsync(
                dto, _req.ClientIp(), _req.Cookie("device_id")));

        [AllowAnonymous]
        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh()
            => _http.ApplyAndRespond(await _login.RefreshAsync(
                _req.BearerToken(), _req.Cookie("refresh_token")));

        [HttpGet("token-status")]
        [Authorize]
        public IActionResult TokenStatus()
        {
            var expClaim = User.FindFirst("exp")?.Value;
            if (expClaim == null || !long.TryParse(expClaim, out long expUnix))
                return Ok(new { valid = false, secondsRemaining = 0 });

            var expiresAt   = DateTimeOffset.FromUnixTimeSeconds(expUnix).UtcDateTime;
            var secondsLeft = (int)(expiresAt - DateTime.UtcNow).TotalSeconds;
            bool hasRefresh = !string.IsNullOrEmpty(_req.Cookie("refresh_token"));

            return Ok(new
            {
                valid            = secondsLeft > 0,
                secondsRemaining = Math.Max(secondsLeft, 0),
                expiresAt,
                canRefresh       = hasRefresh
            });
        }

        [AllowAnonymous]
        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest dto)
            => _http.ApplyAndRespond(await _account.ForgotPasswordAsync(dto));

        [AllowAnonymous]
        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest dto)
            => _http.ApplyAndRespond(await _account.ResetPasswordAsync(
                dto, _req.Cookie("pending_reset_email")));

        [AllowAnonymous]
        [HttpPost("complete-profile")]
        public async Task<IActionResult> CompleteProfile([FromBody] CompleteProfileRequest dto)
            => _http.ApplyAndRespond(await _account.CompleteProfileAsync(
                dto,
                _req.Cookie("pending_login_email"),
                _req.ClientIp(),
                _req.Cookie("device_id"),
                _req.Cookie("profile_otp_verified") == "true"));

        [AllowAnonymous]
        [HttpPost("complete-profile/verify-otp")]
        public async Task<IActionResult> VerifyProfileOtp([FromBody] VerifyOtpRequest dto)
            => _http.ApplyAndRespond(await _account.VerifyProfileOtpAsync(dto, _req.Cookie("pending_login_email")));

        [HttpPost("change-password")]
        [Authorize]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest dto)
            => _http.ApplyAndRespond(await _account.ChangePasswordAsync(
                dto, _req.CurrentUserId, _req.InternalUserId));

        [HttpPost("request-change-email")]
        [Authorize]
        public async Task<IActionResult> RequestChangeEmail([FromBody] RequestChangeEmailRequest dto)
            => _http.ApplyAndRespond(await _account.RequestChangeEmailAsync(dto, _req.CurrentUserId));

        [HttpPost("change-email")]
        [Authorize]
        public async Task<IActionResult> ChangeEmail([FromBody] VerifyOtpRequest dto)
            => _http.ApplyAndRespond(await _account.ChangeEmailAsync(
                dto, _req.CurrentUserId, _req.Cookie("pending_new_email")));

        [HttpPost("update-profile")]
        [Authorize]
        public async Task<IActionResult> UpdateProfile([FromBody] UpdateProfileRequest dto)
            => _http.ApplyAndRespond(await _account.UpdateProfileAsync(dto, _req.CurrentUserId));

        [HttpGet("me")]
        [Authorize]
        public async Task<IActionResult> GetCurrentUser()
            => _http.ApplyAndRespond(await _account.GetCurrentUserAsync(_req.CurrentUserId));

        [HttpPost("logout")]
        [AllowAnonymous]
        public IActionResult Logout()
            => _http.ApplyAndRespond(_account.Logout(
                _req.InternalUserId,
                _req.CurrentUserId,
                _req.Cookie("device_id")));
    }
}