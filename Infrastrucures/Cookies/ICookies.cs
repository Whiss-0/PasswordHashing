namespace Api.Infrastrucures.Cookies
{
    /// <summary>
    /// Abstracts all cookie read/write operations so the controller
    /// never touches <see cref="Microsoft.AspNetCore.Http.CookieOptions"/> directly.
    /// </summary>
    public interface ICookies
    {
        // ── Readers ────────────────────────────────────────────────────────────
        string? GetCookie(string name);

        // ── Writers ────────────────────────────────────────────────────────────
        void SetAuthCookie(string token);
        void SetRefreshCookie(string refreshToken);
        void SetDeviceIdCookie(string deviceId);
        void SetPendingCookie(string name, string value, int minutes = 15);

        // ── Clearers ───────────────────────────────────────────────────────────
        void ClearAuthCookies();
        void ClearCookie(string name);
    }
}
