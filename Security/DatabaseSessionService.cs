using System;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Threading;
using System.Threading.Tasks;
using Api.Main;

namespace Api.Security
{
    public class DatabaseSessionService : ISessionService
    {
        private readonly MyCon _db;

        private static readonly TimeZoneInfo _localZone =
            TimeZoneInfo.FindSystemTimeZoneById("Singapore Standard Time");

        public DatabaseSessionService(MyCon db) => _db = db;

        private static DateTime LocalNow()
            => TimeZoneInfo.ConvertTimeFromUtc(DateTime.UtcNow, _localZone);

        // ── Interface ─────────────────────────────────────────────────────────

        public bool IsUserLoggedIn(int userId)
        {
            const string sql = """
                SELECT COUNT(1) FROM login_logs
                WHERE user_id     = @userId
                  AND logout_time IS NULL
                """;
            return Scalar<int>(sql, cmd =>
            {
                cmd.Parameters.Add(P(cmd, "@userId", userId));
            }) > 0;
        }

        public bool IsDeviceTrustedForUser(int userId, string deviceId)
        {
            const string sql = """
                SELECT COUNT(1) FROM TrustedDevices
                WHERE user_id     = @userId
                  AND device_name = @deviceId
                  AND revoked     = 0
                  AND expires_at  > @now
                """;
            return Scalar<int>(sql, cmd =>
            {
                cmd.Parameters.Add(P(cmd, "@userId",   userId));
                cmd.Parameters.Add(P(cmd, "@deviceId", deviceId));
                cmd.Parameters.Add(P(cmd, "@now",      LocalNow()));
            }) > 0;
        }

        public void MarkUserLoggedIn(int userId, string token)
        {
            MarkUserLoggedIn(userId, 0, token, null, null);
        }

        public void MarkUserLoggedIn(int userId, int roleId, string token,
                                     string? ipAddress, string? deviceId, bool trustDevice = true)
        {
            InvalidateExisting(userId);

            const string logSql = """
                INSERT INTO login_logs (user_id, login_time, logout_time)
                VALUES (@userId, @loginTime, NULL)
                """;

            NonQuery(logSql, cmd =>
            {
                cmd.Parameters.Add(P(cmd, "@userId",    userId));
                cmd.Parameters.Add(P(cmd, "@loginTime", LocalNow()));
            });

            if (trustDevice && !string.IsNullOrWhiteSpace(deviceId))
            {
                string tokenHash = GenerateDeviceTokenHash();

                const string deviceSql = """
                    IF EXISTS (SELECT 1 FROM TrustedDevices WHERE user_id = @userId AND device_name = @deviceId)
                    BEGIN
                        UPDATE TrustedDevices
                        SET device_token_hash = @tokenHash,
                            last_ip           = @ip,
                            last_used_at      = @now,
                            revoked           = 0
                        WHERE user_id = @userId AND device_name = @deviceId;
                    END
                    ELSE
                    BEGIN
                        INSERT INTO TrustedDevices (user_id, device_token_hash, device_name, last_ip, trusted_at, expires_at, last_used_at, revoked)
                        VALUES (@userId, @tokenHash, @deviceId, @ip, @now, DATEADD(day, 7, @now), @now, 0);
                    END
                    """;

                NonQuery(deviceSql, cmd =>
                {
                    cmd.Parameters.Add(P(cmd, "@userId",    userId));
                    cmd.Parameters.Add(P(cmd, "@deviceId",  deviceId));
                    cmd.Parameters.Add(P(cmd, "@ip",        (object?)ipAddress ?? DBNull.Value));
                    cmd.Parameters.Add(P(cmd, "@now",       LocalNow()));
                    cmd.Parameters.Add(P(cmd, "@tokenHash", tokenHash));
                });
            }
            else if (!trustDevice && !string.IsNullOrWhiteSpace(deviceId))
            {
                const string revokeSql = """
                    UPDATE TrustedDevices
                    SET revoked = 1, last_used_at = @now
                    WHERE user_id = @userId AND device_name = @deviceId;
                    """;

                NonQuery(revokeSql, cmd =>
                {
                    cmd.Parameters.Add(P(cmd, "@userId",   userId));
                    cmd.Parameters.Add(P(cmd, "@deviceId", deviceId));
                    cmd.Parameters.Add(P(cmd, "@now",      LocalNow()));
                });
            }
        }

        public void MarkUserLoggedOut(int userId)
        {
            const string sql = """
                UPDATE login_logs
                SET logout_time = @now
                WHERE user_id     = @userId
                  AND logout_time IS NULL
                """;
            NonQuery(sql, cmd =>
            {
                cmd.Parameters.Add(P(cmd, "@now",    LocalNow()));
                cmd.Parameters.Add(P(cmd, "@userId", userId));
            });
        }

        public string? GetUserToken(int userId)
        {
            return IsUserLoggedIn(userId) ? "active_session" : null;
        }

        public bool IsTokenValid(int userId, string token)
        {
            return IsUserLoggedIn(userId);
        }

        public bool IsDeviceLoggedIn(string deviceId)
        {
            const string sql = """
                SELECT COUNT(1) FROM TrustedDevices td
                INNER JOIN login_logs ll ON td.user_id = ll.user_id
                WHERE td.device_name  = @deviceId
                  AND ll.logout_time IS NULL
                  AND td.revoked      = 0
                """;
            return Scalar<int>(sql, cmd =>
            {
                cmd.Parameters.Add(P(cmd, "@deviceId", deviceId));
            }) > 0;
        }

        public void MarkDeviceLoggedIn(string deviceId, int userId) { }

        public void MarkDeviceLoggedOut(string deviceId)
        {
            const string sql = """
                UPDATE login_logs
                SET logout_time = @now
                WHERE user_id IN (SELECT user_id FROM TrustedDevices WHERE device_name = @deviceId)
                  AND logout_time IS NULL
                """;
            NonQuery(sql, cmd =>
            {
                cmd.Parameters.Add(P(cmd, "@now",      LocalNow()));
                cmd.Parameters.Add(P(cmd, "@deviceId", deviceId));
            });
        }

        public async Task<int> PurgeExpiredSessionsAsync(CancellationToken ct = default)
        {
            // Auto close stale sessions open longer than 24 hours
            const string sql = """
                UPDATE login_logs
                SET logout_time = @now
                WHERE logout_time IS NULL
                  AND login_time  < DATEADD(hour, -24, @now)
                """;
            await using var conn = _db.GetConnection();
            await conn.OpenAsync(ct);
            await using var cmd = _db.CreateCommand(conn, sql);
            cmd.Parameters.Add(P(cmd, "@now", LocalNow()));
            return await cmd.ExecuteNonQueryAsync(ct);
        }

        // ── Private helpers ───────────────────────────────────────────────────

        public static string GenerateDeviceTokenHash()
        {
            byte[] randomBytes = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
            byte[] hashBytes   = System.Security.Cryptography.SHA256.HashData(randomBytes);
            return Convert.ToHexString(hashBytes).ToLowerInvariant();
        }

        private void InvalidateExisting(int userId)
        {
            const string sql = """
                UPDATE login_logs
                SET logout_time = @now
                WHERE user_id     = @userId
                  AND logout_time IS NULL
                """;
            NonQuery(sql, cmd =>
            {
                cmd.Parameters.Add(P(cmd, "@now",    LocalNow()));
                cmd.Parameters.Add(P(cmd, "@userId", userId));
            });
        }

        private void NonQuery(string sql, Action<System.Data.Common.DbCommand> prm)
        {
            using var conn = _db.GetConnection();
            conn.Open();
            using var cmd = _db.CreateCommand(conn, sql);
            prm(cmd);
            cmd.ExecuteNonQuery();
        }

        private T Scalar<T>(string sql, Action<System.Data.Common.DbCommand> prm)
        {
            using var conn = _db.GetConnection();
            conn.Open();
            using var cmd = _db.CreateCommand(conn, sql);
            prm(cmd);
            var result = cmd.ExecuteScalar();
            if (result == null || result == DBNull.Value) return default!;
            return (T)Convert.ChangeType(result, typeof(T));
        }

        private static System.Data.Common.DbParameter P(
            System.Data.Common.DbCommand cmd, string name, object? value)
        {
            var p = cmd.CreateParameter();
            p.ParameterName = name;
            p.Value = value ?? DBNull.Value;
            return p;
        }
    }
}

