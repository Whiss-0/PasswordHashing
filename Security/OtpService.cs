using Api.Main;
using System.Security.Cryptography;
using System.Text;

namespace Api.Security
{
    // ─── Result types ─────────────────────────────────────────────────────────

    public enum OtpVerifyResult
    {
        Valid,
        Invalid,
        Expired,
        MaxAttemptsReached,
        AlreadyUsed,
        RateLimited
    }

    // ─── Interface ────────────────────────────────────────────────────────────

    public interface IOtpService
    {
        Task<(bool IsRateLimited, string? Code)> GenerateAsync(
            int userId, string purpose = "login", CancellationToken ct = default);

        Task<OtpVerifyResult> VerifyAsync(
            int userId, string? code, string purpose = "login", CancellationToken ct = default);

        Task InvalidateAllAsync(
            int userId, CancellationToken ct = default);
    }

    // ─── Implementation ───────────────────────────────────────────────────────

    public class DatabaseOtpService : IOtpService
    {
        private readonly MyCon _db;

        // ── Security constants ─────────────────────────────────────────────────

        /// OTP valid for 10 minutes.
        private static readonly TimeSpan _expiry = TimeSpan.FromMinutes(10);

        /// How long the OTP row stays locked after hitting MaxAttempts.
        private static readonly TimeSpan _lockDuration = TimeSpan.FromMinutes(5);

        /// Max wrong attempts before the OTP row is locked.
        private const int MaxAttempts = 5;

        // ── Rate-limit constants ───────────────────────────────────────────────

        private const int  MaxGeneratePer60s  = 20;
        private const int  GenerateWindowSecs = 60;
        private const int  MaxVerifyPerHour   = 20;

        // ── Timezone ───────────────────────────────────────────────────────────

        private static readonly TimeZoneInfo _localZone =
            TimeZoneInfo.FindSystemTimeZoneById("Singapore Standard Time");

        public DatabaseOtpService(MyCon db) => _db = db;

        private static DateTime LocalNow()
            => TimeZoneInfo.ConvertTimeFromUtc(DateTime.UtcNow, _localZone);

        // ── SHA-256 hashing ────────────────────────────────────────────────────

        private static string HashOtp(string plainCode)
        {
            var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(plainCode));
            return Convert.ToHexString(bytes).ToLowerInvariant(); // 64 chars
        }

        // ─── Generate ─────────────────────────────────────────────────────────

        public async Task<(bool IsRateLimited, string? Code)> GenerateAsync(
            int userId, string purpose = "login", CancellationToken ct = default)
        {
            var now         = LocalNow();
            var windowStart = now.AddSeconds(-GenerateWindowSecs);

            await using var conn = _db.GetConnection();
            await conn.OpenAsync(ct);

            // ── Rate limit check ─────────────────────────────────────────────
            const string rateSql = """
                SELECT COUNT(*)
                FROM   otp
                WHERE  user_id    = @userId
                  AND  created_at >= @window
                """;

            await using (var rateCmd = _db.CreateCommand(conn, rateSql))
            {
                rateCmd.Parameters.Add(Param(rateCmd, "@userId", userId));
                rateCmd.Parameters.Add(Param(rateCmd, "@window", windowStart));
                var count = Convert.ToInt32(await rateCmd.ExecuteScalarAsync(ct));
                if (count >= MaxGeneratePer60s)
                    return (IsRateLimited: true, Code: null);
            }

            // ── Invalidate existing unused OTPs for this purpose ───────────────
            const string invalidateSql = """
                UPDATE otp SET verified = 1
                WHERE  user_id  = @userId
                  AND  verified = 0
                  AND  purpose  = @purpose
                """;
            await using (var invCmd = _db.CreateCommand(conn, invalidateSql))
            {
                invCmd.Parameters.Add(Param(invCmd, "@userId",  userId));
                invCmd.Parameters.Add(Param(invCmd, "@purpose", purpose));
                await invCmd.ExecuteNonQueryAsync(ct);
            }

            // ── Generate 6-digit code ──────────────────────────────────────────
            string plainCode = RandomNumberGenerator.GetInt32(100_000, 999_999).ToString();
            string otpHash   = HashOtp(plainCode);
            var    expires   = now.Add(_expiry);

            // ── Persist OTP ───────────────────────────────────────────────────
            const string insertSql = """
                INSERT INTO otp
                    (user_id, otp_hash, purpose, expires_at, verified, attempt_count, locked_until, created_at)
                VALUES
                    (@userId, @hash, @purpose, @expiresAt, 0, 0, NULL, @createdAt)
                """;

            await using (var insCmd = _db.CreateCommand(conn, insertSql))
            {
                insCmd.Parameters.Add(Param(insCmd, "@userId",    userId));
                insCmd.Parameters.Add(Param(insCmd, "@hash",      otpHash));
                insCmd.Parameters.Add(Param(insCmd, "@purpose",   purpose));
                insCmd.Parameters.Add(Param(insCmd, "@expiresAt", expires));
                insCmd.Parameters.Add(Param(insCmd, "@createdAt", now));
                await insCmd.ExecuteNonQueryAsync(ct);
            }

            return (IsRateLimited: false, Code: plainCode);
        }

        // ─── Verify ──────────────────────────────────────────────────────────

        public async Task<OtpVerifyResult> VerifyAsync(int userId, string? code,
                                                       string purpose = "login",
                                                       CancellationToken ct = default)
        {
            if (string.IsNullOrWhiteSpace(code))
                return OtpVerifyResult.Invalid;

            code = code.Trim();

            var now               = LocalNow();
            var verifyWindowStart = now.AddHours(-1);

            await using var conn = _db.GetConnection();
            await conn.OpenAsync(ct);

            // ── Rate limit verify ────────────────────────────────────────────
            const string attemptSql = """
                SELECT ISNULL(SUM(attempt_count), 0)
                FROM   otp
                WHERE  user_id    = @userId
                  AND  created_at >= @window
                """;
            await using (var attCmd = _db.CreateCommand(conn, attemptSql))
            {
                attCmd.Parameters.Add(Param(attCmd, "@userId", userId));
                attCmd.Parameters.Add(Param(attCmd, "@window", verifyWindowStart));
                var total = Convert.ToInt32(await attCmd.ExecuteScalarAsync(ct));
                if (total >= MaxVerifyPerHour)
                    return OtpVerifyResult.RateLimited;
            }

            // ── Fetch latest unverified OTP row ──────────────────────────────
            const string selectSql = """
                SELECT TOP 1 otp_id, otp_hash, expires_at, attempt_count, locked_until
                FROM   otp
                WHERE  user_id  = @userId
                  AND  verified = 0
                  AND  purpose  = @purpose
                ORDER BY created_at DESC, otp_id DESC
                """;

            int       otpId;
            string    storedHash;
            DateTime  expiresAt;
            int       attempts;
            DateTime? lockedUntil;

            await using (var selCmd = _db.CreateCommand(conn, selectSql))
            {
                selCmd.Parameters.Add(Param(selCmd, "@userId",  userId));
                selCmd.Parameters.Add(Param(selCmd, "@purpose", purpose));
                await using (var reader = await selCmd.ExecuteReaderAsync(ct))
                {
                    if (!await reader.ReadAsync(ct))
                        return OtpVerifyResult.Invalid;

                    otpId       = reader.GetInt32(0);
                    storedHash  = reader.GetString(1);
                    expiresAt   = reader.GetDateTime(2);
                    attempts    = reader.GetInt32(3);
                    lockedUntil = reader.IsDBNull(4) ? null : reader.GetDateTime(4);
                }
            }

            if (lockedUntil.HasValue && now < lockedUntil.Value)
                return OtpVerifyResult.MaxAttemptsReached;

            if (now > expiresAt)
                return OtpVerifyResult.Expired;

            if (attempts >= MaxAttempts)
                return OtpVerifyResult.MaxAttemptsReached;

            attempts++;
            var lockUntilValue = (attempts >= MaxAttempts) ? (object)now.Add(_lockDuration) : DBNull.Value;

            const string incrSql = """
                UPDATE otp
                SET    attempt_count = @att,
                       locked_until  = @lockUntil
                WHERE  otp_id        = @id
                """;
            await using (var incrCmd = _db.CreateCommand(conn, incrSql))
            {
                incrCmd.Parameters.Add(Param(incrCmd, "@att",       attempts));
                incrCmd.Parameters.Add(Param(incrCmd, "@id",        otpId));
                incrCmd.Parameters.Add(Param(incrCmd, "@lockUntil", lockUntilValue));
                await incrCmd.ExecuteNonQueryAsync(ct);
            }

            string submittedHash = HashOtp(code!);
            if (!string.Equals(storedHash, submittedHash, StringComparison.OrdinalIgnoreCase))
                return OtpVerifyResult.Invalid;

            const string useSql = "UPDATE otp SET verified = 1 WHERE otp_id = @id";
            await using (var useCmd = _db.CreateCommand(conn, useSql))
            {
                useCmd.Parameters.Add(Param(useCmd, "@id", otpId));
                await useCmd.ExecuteNonQueryAsync(ct);
            }

            return OtpVerifyResult.Valid;
        }

        // ─── Invalidate ──────────────────────────────────────────────────────

        public async Task InvalidateAllAsync(int userId, CancellationToken ct = default)
        {
            const string sql = """
                UPDATE otp SET verified = 1
                WHERE  user_id  = @userId
                  AND  verified = 0
                """;

            await using var conn = _db.GetConnection();
            await conn.OpenAsync(ct);
            await using var cmd = _db.CreateCommand(conn, sql);
            cmd.Parameters.Add(Param(cmd, "@userId", userId));
            await cmd.ExecuteNonQueryAsync(ct);
        }

        private static System.Data.Common.DbParameter Param(
            System.Data.Common.DbCommand cmd, string name, object? value)
        {
            var p = cmd.CreateParameter();
            p.ParameterName = name;
            p.Value = value ?? DBNull.Value;
            return p;
        }
    }
}

