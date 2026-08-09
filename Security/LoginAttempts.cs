using Api.Main;

namespace Api.Security
{
    public interface ILoginAttemptService
    {
        Task LogAsync(
            int?    userId,
            string  attemptedIdentifier,
            bool    success,
            string? ipAddress,
            string? userAgent,
            CancellationToken ct = default);
    }

    /// <summary>
    /// No-op fallback — swapped out in Program.cs with DatabaseLoginAttemptService.
    /// </summary>
    public class NullLoginAttemptService : ILoginAttemptService
    {
        public Task LogAsync(int? userId, string attemptedIdentifier, bool success,
                             string? ipAddress, string? userAgent,
                             CancellationToken ct = default)
            => Task.CompletedTask;
    }

    /// <summary>
    /// Persists every login attempt (success or failure) to the LoginAttempts table.
    /// </summary>
    public class DatabaseLoginAttemptService : ILoginAttemptService
    {
        private readonly MyCon _db;

        private static readonly TimeZoneInfo _localZone =
            TimeZoneInfo.FindSystemTimeZoneById("Singapore Standard Time");

        public DatabaseLoginAttemptService(MyCon db) => _db = db;

        private static DateTime LocalNow()
            => TimeZoneInfo.ConvertTimeFromUtc(DateTime.UtcNow, _localZone);

        public async Task LogAsync(
            int?    userId,
            string  attemptedIdentifier,
            bool    success,
            string? ipAddress,
            string? userAgent,
            CancellationToken ct = default)
        {
            const string sql = """
                INSERT INTO LoginAttempts
                    (user_id, attempted_identifier, ip_address, user_agent, success, attempted_at)
                VALUES
                    (@userId, @identifier, @ip, @userAgent, @success, @now)
                """;

            try
            {
                await using var conn = _db.GetConnection();
                await conn.OpenAsync(ct);
                await using var cmd = _db.CreateCommand(conn, sql);

                cmd.Parameters.Add(P(cmd, "@userId",     (object?)userId ?? DBNull.Value));
                cmd.Parameters.Add(P(cmd, "@identifier", attemptedIdentifier));
                cmd.Parameters.Add(P(cmd, "@ip",         (object?)ipAddress ?? DBNull.Value));
                cmd.Parameters.Add(P(cmd, "@userAgent",  (object?)userAgent ?? DBNull.Value));
                cmd.Parameters.Add(P(cmd, "@success",    success ? 1 : 0));
                cmd.Parameters.Add(P(cmd, "@now",        LocalNow()));

                await cmd.ExecuteNonQueryAsync(ct);
            }
            catch (Exception ex)
            {
                // Never crash the login flow because of an audit log failure
                Console.WriteLine($"[AUDIT] LoginAttempts write failed: {ex.Message}");
            }
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

