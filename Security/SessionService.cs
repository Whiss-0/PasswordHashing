using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;

namespace Api.Security
{
    public interface ISessionService
    {
        bool   IsUserLoggedIn(int userId);
        bool   IsDeviceTrustedForUser(int userId, string deviceId);

        void   MarkUserLoggedIn(int userId, string token);
        void   MarkUserLoggedIn(int userId, int roleId, string token,
                                string? ipAddress, string? deviceId, bool trustDevice = true);

        void   MarkUserLoggedOut(int userId);
        string? GetUserToken(int userId);
        bool   IsTokenValid(int userId, string token);

        bool   IsDeviceLoggedIn(string deviceId);
        void   MarkDeviceLoggedIn(string deviceId, int userId);
        void   MarkDeviceLoggedOut(string deviceId);

        Task<int> PurgeExpiredSessionsAsync(CancellationToken ct = default);
    }

    /// <summary>
    /// In-memory fallback — used during development or if the DB session table is not available.
    /// </summary>
    public class InMemorySessionService : ISessionService
    {
        private record SessionEntry(string Token, DateTime ExpiresAt, int RoleId, string? DeviceId);

        private readonly ConcurrentDictionary<int, SessionEntry> _activeSessions = new();
        private readonly ConcurrentDictionary<string, int>       _deviceToUser   = new();

        // ── User checks ──────────────────────────────────────────────────────

        public bool IsUserLoggedIn(int userId)
        {
            if (!_activeSessions.TryGetValue(userId, out var entry)) return false;
            if (entry.ExpiresAt <= DateTime.UtcNow)
            {
                _activeSessions.TryRemove(userId, out _);
                return false;
            }
            return true;
        }

        public bool IsDeviceTrustedForUser(int userId, string deviceId)
        {
            if (!_deviceToUser.TryGetValue(deviceId, out var storedUserId)) return false;
            if (storedUserId != userId) return false;
            return IsUserLoggedIn(userId);
        }

        // ── Login / logout ───────────────────────────────────────────────────

        public void MarkUserLoggedIn(int userId, string token)
        {
            var expiry = ExtractExpiry(token);
            _activeSessions[userId] = new SessionEntry(token, expiry, 0, null);
        }

        public void MarkUserLoggedIn(int userId, int roleId, string token,
                                     string? ipAddress, string? deviceId, bool trustDevice = true)
        {
            var expiry = ExtractExpiry(token);
            _activeSessions[userId] = new SessionEntry(token, expiry, roleId, deviceId);
            if (trustDevice && !string.IsNullOrEmpty(deviceId))
                _deviceToUser[deviceId] = userId;
            else if (!trustDevice && !string.IsNullOrEmpty(deviceId))
                _deviceToUser.TryRemove(deviceId, out _);
        }

        public void MarkUserLoggedOut(int userId)
        {
            if (_activeSessions.TryRemove(userId, out var entry) &&
                entry.DeviceId != null)
                _deviceToUser.TryRemove(entry.DeviceId, out _);
        }

        // ── Token helpers ────────────────────────────────────────────────────

        public string? GetUserToken(int userId)
            => _activeSessions.TryGetValue(userId, out var e) ? e.Token : null;

        public bool IsTokenValid(int userId, string token)
        {
            if (!_activeSessions.TryGetValue(userId, out var entry)) return false;
            if (entry.Token != token || entry.ExpiresAt <= DateTime.UtcNow)
            {
                _activeSessions.TryRemove(userId, out _);
                return false;
            }
            return true;
        }

        // ── Device helpers ───────────────────────────────────────────────────

        public bool IsDeviceLoggedIn(string deviceId)
            => _deviceToUser.ContainsKey(deviceId);

        public void MarkDeviceLoggedIn(string deviceId, int userId)
            => _deviceToUser[deviceId] = userId;

        public void MarkDeviceLoggedOut(string deviceId)
            => _deviceToUser.TryRemove(deviceId, out _);

        // ── Cleanup ──────────────────────────────────────────────────────────

        public Task<int> PurgeExpiredSessionsAsync(CancellationToken ct = default)
        {
            var now = DateTime.UtcNow;
            var expired = _activeSessions
                .Where(kv => kv.Value.ExpiresAt <= now)
                .Select(kv => kv.Key).ToList();

            foreach (var id in expired) _activeSessions.TryRemove(id, out _);

            var activeIds = _activeSessions.Keys.ToHashSet();
            var orphans   = _deviceToUser
                .Where(kv => !activeIds.Contains(kv.Value))
                .Select(kv => kv.Key).ToList();

            foreach (var d in orphans) _deviceToUser.TryRemove(d, out _);

            return Task.FromResult(expired.Count);
        }

        // ── Private ──────────────────────────────────────────────────────────

        private static DateTime ExtractExpiry(string token)
        {
            try
            {
                var handler = new JwtSecurityTokenHandler();
                return handler.ReadJwtToken(token).ValidTo;
            }
            catch { return DateTime.UtcNow; }
        }
    }
}