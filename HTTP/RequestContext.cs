using Microsoft.AspNetCore.Http;
using System.Security.Claims;

namespace Api.HTTP
{
    /// <summary>
    /// Reads cookies, headers, connection metadata and identity claims
    /// from the current HTTP context.
    /// Implements <see cref="IRequestsContext"/> via <see cref="IHttpContextAccessor"/>.
    /// </summary>
    public class RequestContext : IRequestContext
    {
        private readonly IHttpContextAccessor _http;

        public RequestContext(IHttpContextAccessor http) => _http = http;

        private HttpContext HttpContext => _http.HttpContext!;

        // ── Request data ───────────────────────────────────────────────────────

        /// <inheritdoc/>
        public string? Cookie(string name)
            => HttpContext.Request.Cookies[name];

        /// <inheritdoc/>
        public string? ClientIp()
        {
            var forwarded = HttpContext.Request.Headers["X-Forwarded-For"].FirstOrDefault();

            if (!string.IsNullOrWhiteSpace(forwarded))
                return forwarded.Split(',')[0].Trim();

            return HttpContext.Connection.RemoteIpAddress?.ToString();
        }

        /// <inheritdoc/>
        public string? BearerToken()
        {
            var token = HttpContext.Request.Headers["Authorization"]
                .ToString()
                .Replace("Bearer ", "")
                .Trim();

            if (string.IsNullOrEmpty(token))
                token = HttpContext.Request.Cookies["access_token"];

            return token;
        }

        // ── Identity ───────────────────────────────────────────────────────────

        /// <inheritdoc/>
        public Guid CurrentUserId
        {
            get
            {
                var claim = HttpContext.User
                    .FindFirst(ClaimTypes.NameIdentifier)
                    ?.Value;

                return Guid.TryParse(claim, out var id)
                    ? id
                    : Guid.Empty;
            }
        }

        /// <inheritdoc/>
        public int InternalUserId
        {
            get
            {
                var claim = HttpContext.User
                    .FindFirst("internal_user_id")
                    ?.Value;

                return int.TryParse(claim, out var id)
                    ? id
                    : 0;
            }
        }

        /// <inheritdoc/>
        public string? Claim(string claimType)
            => HttpContext.User.FindFirst(claimType)?.Value;
    }
}