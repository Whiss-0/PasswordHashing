namespace Api.Modules.AuthorizationModule
{
    /// <summary>
    /// Unified result returned by every auth service method.
    /// The controller reads this and handles all HTTP concerns:
    /// cookies, status codes, and JSON responses.
    /// </summary>
    public sealed class ServiceResult
    {
        // ── Response metadata ──────────────────────────────────────────────────
        public bool    IsSuccess  { get; init; }
        public int     StatusCode { get; init; } = 200;
        public string? Code       { get; init; }
        public string? Message    { get; init; }

        /// <summary>
        /// The exact JSON body to return on success.
        /// When null, the controller falls back to <c>{ message }</c>.
        /// </summary>
        public object? Payload { get; init; }

        // ── Auth cookie data ───────────────────────────────────────────────────

        /// <summary>JWT access token to write to the <c>access_token</c> cookie.</summary>
        public string? AccessToken  { get; init; }

        /// <summary>Refresh token to write to the <c>refresh_token</c> cookie.</summary>
        public string? RefreshToken { get; init; }

        /// <summary>Device ID to write to the <c>device_id</c> cookie (7-day expiry).</summary>
        public string? DeviceId { get; init; }

        // ── Short-lived pending cookies ────────────────────────────────────────

        /// <summary>
        /// Key-value pairs of pending state cookies to set with a 15-minute expiry
        /// (e.g. <c>pending_login_email</c>, <c>pending_device_id</c>).
        /// </summary>
        public Dictionary<string, string>? PendingCookies { get; init; }

        // ── Cookie cleanup ─────────────────────────────────────────────────────

        /// <summary>Names of pending cookies to clear (set to expired).</summary>
        public string[]? ClearCookies { get; init; }

        /// <summary>
        /// When true the controller calls <c>ClearAuthCookies()</c>
        /// to remove access_token and refresh_token cookies.
        /// </summary>
        public bool ShouldClearAuth { get; init; }

        // ── Factory helpers ────────────────────────────────────────────────────

        public static ServiceResult Ok(string message = "success", object? payload = null)
            => new() { IsSuccess = true, StatusCode = 200, Message = message, Payload = payload };

        /// <summary>Success with auth tokens — triggers cookie + device_id writes.</summary>
        public static ServiceResult OkWithTokens(
            string accessToken, string refreshToken, string deviceId,
            object payload, string[]? clearCookies = null)
            => new()
            {
                IsSuccess   = true,
                StatusCode  = 200,
                AccessToken  = accessToken,
                RefreshToken = refreshToken,
                DeviceId     = deviceId,
                Payload      = payload,
                ClearCookies = clearCookies
            };

        /// <summary>
        /// Success that requires short-lived state cookies
        /// (e.g. OTP sent — store pending email in cookie).
        /// </summary>
        public static ServiceResult OkWithPending(
            object payload, Dictionary<string, string> pendingCookies)
            => new()
            {
                IsSuccess     = true,
                StatusCode    = 200,
                Payload       = payload,
                PendingCookies = pendingCookies
            };

        public static ServiceResult Fail(int statusCode, string? code, string message)
            => new() { IsSuccess = false, StatusCode = statusCode, Code = code, Message = message };

        public static ServiceResult BadRequest(string message, string? code = null)
            => Fail(400, code, message);

        public static ServiceResult Unauthorized(string? code, string message)
            => Fail(401, code, message);

        public static ServiceResult Conflict(string code, string message)
            => Fail(409, code, message);

        public static ServiceResult TooManyRequests(string? code = "RATE_LIMITED",
            string message = "Too many requests. Please wait before trying again.")
            => Fail(429, code, message);

        public static ServiceResult ServerError(string message = "An unexpected error occurred.")
            => Fail(500, "SERVER_ERROR", message);
    }
}
