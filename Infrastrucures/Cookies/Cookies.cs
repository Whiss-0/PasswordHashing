using Microsoft.AspNetCore.Http;
using Api.Security;
namespace Api.Infrastrucures.Cookies
{
    /// <summary>
    /// Encapsulates all cookie read/write/clear operations for the auth flow.
    /// Depends on <see cref="IHttpContextAccessor"/> (registered as scoped) and
    /// <see cref="IJwtTokenService"/> for token lifetime values.
    /// </summary>
    public class AuthCookies : ICookies
    {
        private readonly IHttpContextAccessor _http;
        private readonly IJwtTokenService     _jwt;
        private HttpRequest  Req => _http.HttpContext!.Request;
        private HttpResponse Res => _http.HttpContext!.Response;
        public AuthCookies(IHttpContextAccessor http, IJwtTokenService jwt)
        {
            _http = http;
            _jwt  = jwt;
        }
        // ── Readers ────────────────────────────────────────────────────────────
        public string? GetCookie(string name) => Req.Cookies[name];
        // ── Writers ────────────────────────────────────────────────────────────
        public void SetAuthCookie(string token) =>
            Res.Cookies.Append("access_token", token, new CookieOptions
            {
                HttpOnly = true,
                Secure   = Req.IsHttps,
                SameSite = SameSiteMode.Lax,
                Path     = "/",
                Expires  = DateTimeOffset.UtcNow.Add(_jwt.AccessTokenLifetime)
            });
        public void SetRefreshCookie(string refreshToken) =>
            Res.Cookies.Append("refresh_token", refreshToken, new CookieOptions
            {
                HttpOnly = true,
                Secure   = Req.IsHttps,
                SameSite = SameSiteMode.Strict,
                Path     = "/api/auth/refresh",
                Expires  = DateTimeOffset.UtcNow.Add(_jwt.RefreshTokenLifetime)
            });
        public void SetDeviceIdCookie(string deviceId) =>
            Res.Cookies.Append("device_id", deviceId, new CookieOptions
            {
                HttpOnly = true,
                Secure   = Req.IsHttps,
                SameSite = Req.IsHttps ? SameSiteMode.None : SameSiteMode.Lax,
                Path     = "/",
                Expires  = DateTimeOffset.UtcNow.AddDays(7)
            });
        public void SetPendingCookie(string name, string value, int minutes = 15) =>
            Res.Cookies.Append(name, value, PendingOptions(minutes));
        // ── Clearers ───────────────────────────────────────────────────────────
        public void ClearAuthCookies()
        {
            Res.Cookies.Append("access_token", string.Empty, new CookieOptions
            {
                HttpOnly = true, Secure = Req.IsHttps,
                SameSite = SameSiteMode.Lax, Path = "/",
                Expires  = DateTimeOffset.UtcNow.AddDays(-1)
            });
            Res.Cookies.Append("refresh_token", string.Empty, new CookieOptions
            {
                HttpOnly = true, Secure = Req.IsHttps,
                SameSite = SameSiteMode.Strict, Path = "/api/auth/refresh",
                Expires  = DateTimeOffset.UtcNow.AddDays(-1)
            });
        }
        public void ClearCookie(string name) =>
            Res.Cookies.Append(name, string.Empty, ClearOptions());
        // ── Private option factories ───────────────────────────────────────────
        private CookieOptions PendingOptions(int minutes) => new()
        {
            HttpOnly = true,
            Secure   = Req.IsHttps,
            SameSite = Req.IsHttps ? SameSiteMode.None : SameSiteMode.Lax,
            Path     = "/",
            Expires  = DateTimeOffset.UtcNow.AddMinutes(minutes)
        };
        private CookieOptions ClearOptions() => new()
        {
            HttpOnly = true,
            Secure   = Req.IsHttps,
            SameSite = Req.IsHttps ? SameSiteMode.None : SameSiteMode.Lax,
            Path     = "/",
            Expires  = DateTimeOffset.UtcNow.AddDays(-1)
        };
    }
}