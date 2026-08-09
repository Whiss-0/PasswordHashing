using System;
using Api.Main;
using System.Security.Cryptography;

namespace Api.Security
{
    public class DatabaseRefreshTokenStore : IRefreshTokenStore
    {
        private readonly MyCon _db;

        public DatabaseRefreshTokenStore(MyCon db) => _db = db;

        public string GenerateRefreshToken(Guid publicUserId, TimeSpan expiry)
        {
            var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
            var expiresAt = DateTime.UtcNow.Add(expiry);

            const string sql = @"
                INSERT INTO refresh_tokens (user_id, token, expires_at, created_at, revoked)
                SELECT user_id, @token, @expiresAt, SYSUTCDATETIME(), 0
                FROM users WHERE guid = @publicUserId AND is_deleted = 0;";

            using var conn = _db.GetConnection();
            conn.Open();
            using var cmd = _db.CreateCommand(conn, sql);
            cmd.Parameters.Add(P(cmd, "@publicUserId", publicUserId.ToString()));
            cmd.Parameters.Add(P(cmd, "@token",        token));
            cmd.Parameters.Add(P(cmd, "@expiresAt",    expiresAt));

            cmd.ExecuteNonQuery();
            return token;
        }

        public bool ValidateRefreshToken(Guid publicUserId, string refreshToken, out DateTime expiry)
        {
            expiry = DateTime.MinValue;
            const string sql = @"
                SELECT expires_at 
                FROM refresh_tokens
                WHERE user_id = (SELECT user_id FROM users WHERE guid = @publicUserId AND is_deleted = 0)
                  AND token = @token
                  AND revoked = 0
                  AND expires_at > SYSUTCDATETIME();";

            using var conn = _db.GetConnection();
            conn.Open();
            using var cmd = _db.CreateCommand(conn, sql);
            cmd.Parameters.Add(P(cmd, "@publicUserId", publicUserId.ToString()));
            cmd.Parameters.Add(P(cmd, "@token",        refreshToken));

            var result = cmd.ExecuteScalar();
            if (result != null && result != DBNull.Value)
            {
                expiry = (DateTime)result;
                return true;
            }

            return false;
        }

        public void RevokeRefreshToken(Guid publicUserId)
        {
            const string sql = @"
                UPDATE refresh_tokens
                SET revoked = 1
                WHERE user_id = (SELECT user_id FROM users WHERE guid = @publicUserId);";

            using var conn = _db.GetConnection();
            conn.Open();
            using var cmd = _db.CreateCommand(conn, sql);
            cmd.Parameters.Add(P(cmd, "@publicUserId", publicUserId.ToString()));
            cmd.ExecuteNonQuery();
        }

        public void RevokeAll()
        {
            const string sql = "UPDATE refresh_tokens SET revoked = 1;";
            using var conn = _db.GetConnection();
            conn.Open();
            using var cmd = _db.CreateCommand(conn, sql);
            cmd.ExecuteNonQuery();
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
