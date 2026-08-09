using Microsoft.AspNetCore.Mvc;
using Api.Infrastrucures.Cookies;
using Api.Modules.AuthorizationModule;

namespace Api.HTTP
{
    /// <summary>
    /// Applies cookie instructions from a <see cref="ServiceResult"/> and
    /// returns the matching <see cref="IActionResult"/>.
    ///
    /// This is the single place in the HTTP layer that orchestrates cookies
    /// and HTTP status codes — no controller needs to do it manually.
    /// </summary>
    public class HttpResponseHandler : IHttpResponse
    {
        private readonly ICookies _cookies;

        public HttpResponseHandler(ICookies cookies) => _cookies = cookies;

        /// <summary>
        /// Applies all cookie instructions carried by <paramref name="result"/>
        /// and returns the appropriate HTTP status-code + JSON body.
        /// </summary>
        public IActionResult ApplyAndRespond(ServiceResult result)
        {
            // 1. Write short-lived pending-state cookies
            if (result.PendingCookies != null)
                foreach (var (name, value) in result.PendingCookies)
                    if (!string.IsNullOrEmpty(value))
                        _cookies.SetPendingCookie(name, value);

            // 2. Write auth tokens
            if (result.AccessToken  != null) _cookies.SetAuthCookie(result.AccessToken);
            if (result.RefreshToken != null) _cookies.SetRefreshCookie(result.RefreshToken);

            // 3. Write device ID (empty = skip, e.g. token-refresh with no device change)
            if (!string.IsNullOrEmpty(result.DeviceId))
                _cookies.SetDeviceIdCookie(result.DeviceId);

            // 4. Clear individual pending cookies
            if (result.ClearCookies != null)
                foreach (var name in result.ClearCookies)
                    _cookies.ClearCookie(name);

            // 5. Clear auth cookies (logout / password change / reset)
            if (result.ShouldClearAuth)
                _cookies.ClearAuthCookies();

            // 6. Build and return the HTTP response
            object body = result.IsSuccess
                ? (result.Payload ?? (object)new { message = result.Message })
                : new { code = result.Code, message = result.Message };

            return new ObjectResult(body) { StatusCode = result.StatusCode };
        }
    }
}
