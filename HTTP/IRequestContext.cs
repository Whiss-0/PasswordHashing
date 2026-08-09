namespace Api.HTTP
{
    /// <summary>
    /// Abstracts reading of HTTP request data (cookies, headers, connection info,
    /// and the current user's identity claims) so controllers never touch
    /// <see cref="Microsoft.AspNetCore.Http.HttpRequest"/> or
    /// <see cref="System.Security.Claims.ClaimsPrincipal"/> directly.
    /// </summary>
    public interface IRequestContext
    {
        // ── Request data ───────────────────────────────────────────────────────

        /// <summary>Returns the value of the named request cookie, or null.</summary>
        string? Cookie(string name);

        /// <summary>
        /// Returns the client's real IP address, honouring the
        /// <c>X-Forwarded-For</c> proxy header when present.
        /// </summary>
        string? ClientIp();

        /// <summary>
        /// Extracts the raw Bearer token from the <c>Authorization</c> header,
        /// falling back to the <c>access_token</c> cookie.
        /// </summary>
        string? BearerToken();

        // ── Identity ───────────────────────────────────────────────────────────

        /// <summary>The authenticated user's public GUID, or <see cref="Guid.Empty"/>.</summary>
        Guid CurrentUserId { get; }

        /// <summary>The authenticated user's internal integer ID, or 0.</summary>
        int InternalUserId { get; }

        /// <summary>Returns the value of an arbitrary claim, or null.</summary>
        string? Claim(string claimType);
    }
}
