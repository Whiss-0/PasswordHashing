using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Common;
using System.Linq;
using System.Threading.Tasks;
using Api.Main;

namespace Api.Modules.UserModule
{
    public class UserRepository : BaseRepository, IUserRepository
    {
        public UserRepository(MyCon dbConnection) : base(dbConnection) { }

        // ── Mapper ────────────────────────────────────────────────────────────

        private User MapReaderToUser(DbDataReader reader)
        {
            try
            {
                var user = new User
                {
                    UserId        = reader.IsDBNull(reader.GetOrdinal("user_id"))       ? 0          : reader.GetInt32(reader.GetOrdinal("user_id")),
                    AccessId      = reader.IsDBNull(reader.GetOrdinal("access_id"))     ? 0          : reader.GetInt32(reader.GetOrdinal("access_id")),
                    UserEmail     = reader.IsDBNull(reader.GetOrdinal("email"))         ? string.Empty : reader.GetString(reader.GetOrdinal("email")),
                    UserName      = reader.IsDBNull(reader.GetOrdinal("username"))      ? string.Empty : reader.GetString(reader.GetOrdinal("username")),
                    UserPass      = reader.IsDBNull(reader.GetOrdinal("password_hash")) ? string.Empty : reader.GetString(reader.GetOrdinal("password_hash")),
                    EmailVerified = !reader.IsDBNull(reader.GetOrdinal("email_verified")) && reader.GetBoolean(reader.GetOrdinal("email_verified")),
                    Status        = reader.IsDBNull(reader.GetOrdinal("status"))        ? string.Empty : reader.GetString(reader.GetOrdinal("status")),
                    IsDeleted     = !reader.IsDBNull(reader.GetOrdinal("is_deleted"))   && reader.GetBoolean(reader.GetOrdinal("is_deleted")),
                    UserRole      = reader.IsDBNull(reader.GetOrdinal("user_role"))     ? string.Empty : reader.GetString(reader.GetOrdinal("user_role"))
                };

                if (!reader.IsDBNull(reader.GetOrdinal("guid")))
                {
                    var gVal = reader.GetValue(reader.GetOrdinal("guid"));
                    if (gVal is Guid g)
                        user.PublicId = g;
                    else if (Guid.TryParse(gVal.ToString(), out var parsedGuid))
                        user.PublicId = parsedGuid;
                }

                if (!reader.IsDBNull(reader.GetOrdinal("deleted_at")))
                    user.DeletedAt = reader.GetDateTime(reader.GetOrdinal("deleted_at"));

                if (!reader.IsDBNull(reader.GetOrdinal("created_at")))
                    user.CreatedAt = reader.GetDateTime(reader.GetOrdinal("created_at"));

                if (!reader.IsDBNull(reader.GetOrdinal("updated_at")))
                    user.UpdatedAt = reader.GetDateTime(reader.GetOrdinal("updated_at"));

                return user;
            }
            catch
            {
                return new User();
            }
        }

        // ── Base SELECT (joins Access_Roles) ───────────────────

        private const string SelectSql = @"
            SELECT u.user_id, u.guid, u.access_id, u.email, u.username, u.password_hash, u.email_verified, u.status, u.is_deleted, u.deleted_at, u.created_at, u.updated_at, r.role_name AS user_role
            FROM users u
            LEFT JOIN Access_Roles r ON u.access_id = r.access_id
            WHERE u.is_deleted = 0";

        // ── Reads ─────────────────────────────────────────────────────────────

        public async Task<IEnumerable<User>> GetAllAsync()
            => await ExecuteReaderToListAsync(SelectSql, MapReaderToUser);

        public async Task<User?> GetByIdAsync(Guid publicId)
        {
            var sql = SelectSql + " AND u.guid = @guid";
            var results = await ExecuteReaderToListAsync(sql, MapReaderToUser,
                new[] { CreateParameter("guid", publicId.ToString()) });
            return results.FirstOrDefault();
        }

        public async Task<User?> GetByUserNameAsync(string userName)
        {
            var sql = SelectSql + " AND u.username = @username";
            var results = await ExecuteReaderToListAsync(sql, MapReaderToUser,
                new[] { CreateParameter("username", userName) });
            return results.FirstOrDefault();
        }

        public async Task<User?> GetByEmailAsync(string email)
        {
            var sql = SelectSql + " AND u.email = @email";
            var results = await ExecuteReaderToListAsync(sql, MapReaderToUser,
                new[] { CreateParameter("email", email) });
            return results.FirstOrDefault();
        }

        public async Task<IEnumerable<User>> GetByRoleIdAsync(int roleId)
        {
            var sql = SelectSql + " AND u.access_id = @access_id";
            return await ExecuteReaderToListAsync(sql, MapReaderToUser,
                new[] { CreateParameter("access_id", roleId) });
        }

        public async Task<User?> GetByGoogleIdAsync(string googleId)
        {
            const string sql = @"
                SELECT u.user_id, u.guid, u.access_id, u.email, u.username, u.password_hash, u.email_verified, u.status, u.is_deleted, u.deleted_at, u.created_at, u.updated_at, r.role_name AS user_role
                FROM users u
                INNER JOIN authProvider ap ON u.user_id = ap.user_id
                LEFT JOIN Access_Roles r ON u.access_id = r.access_id
                WHERE ap.provider = 'google' AND ap.provider_user_id = @google_id AND u.is_deleted = 0";

            var results = await ExecuteReaderToListAsync(sql, MapReaderToUser,
                new[] { CreateParameter("google_id", googleId) });
            return results.FirstOrDefault();
        }

        public async Task LinkGoogleIdAsync(int userId, string googleId, string? providerEmail = null)
        {
            const string sql = @"
                IF EXISTS (SELECT 1 FROM authProvider WHERE user_id = @user_id AND provider = 'google')
                BEGIN
                    UPDATE authProvider 
                    SET provider_user_id = @google_id, 
                        provider_email = @email, 
                        last_login_at = SYSUTCDATETIME()
                    WHERE user_id = @user_id AND provider = 'google';
                END
                ELSE
                BEGIN
                    INSERT INTO authProvider (user_id, provider, provider_user_id, provider_email, created_at, last_login_at)
                    VALUES (@user_id, 'google', @google_id, @email, SYSUTCDATETIME(), SYSUTCDATETIME());
                END";

            await ExecuteNonQueryAsync(sql, new[]
            {
                CreateParameter("user_id",   userId),
                CreateParameter("google_id", googleId),
                CreateParameter("email",     (object?)providerEmail ?? DBNull.Value)
            });
        }

        // ── Write ─────────────────────────────────────────────────────────────

        public async Task AddAsync(User entity)
        {
            if (entity.PublicId == Guid.Empty)
                entity.PublicId = Guid.NewGuid();

            const string sql = @"
                INSERT INTO users (guid, access_id, email, username, password_hash, email_verified, status, is_deleted, created_at)
                OUTPUT INSERTED.user_id
                VALUES (@guid, @access_id, @email, @username, @password_hash, @email_verified, @status, 0, SYSUTCDATETIME())";

            var results = await ExecuteReaderToListAsync(sql, r => r.GetInt32(0),
                new[]
                {
                    CreateParameter("guid",           entity.PublicId.ToString()),
                    CreateParameter("access_id",      entity.AccessId),
                    CreateParameter("email",          entity.UserEmail),
                    CreateParameter("username",       entity.UserName),
                    CreateParameter("password_hash",  entity.UserPass),
                    CreateParameter("email_verified", entity.EmailVerified, DbType.Boolean),
                    CreateParameter("status",         entity.Status)
                });

            entity.UserId = results.FirstOrDefault();
            if (entity.UserId == 0)
                throw new InvalidOperationException("Insert did not return a user_id.");

            await EnsureAdminSafetyAsync();
        }

        public async Task UpdateAsync(User entity)
        {
            const string sql = @"
                UPDATE users
                SET access_id      = @access_id,
                    email          = @email,
                    username       = @username,
                    password_hash  = @password_hash,
                    email_verified = @email_verified,
                    status         = @status,
                    updated_at     = SYSUTCDATETIME()
                WHERE guid = @guid AND is_deleted = 0";

            await ExecuteNonQueryAsync(sql, new[]
            {
                CreateParameter("guid",           entity.PublicId.ToString()),
                CreateParameter("access_id",      entity.AccessId),
                CreateParameter("email",          entity.UserEmail),
                CreateParameter("username",       entity.UserName),
                CreateParameter("password_hash",  entity.UserPass),
                CreateParameter("email_verified", entity.EmailVerified, DbType.Boolean),
                CreateParameter("status",         entity.Status)
            });

            await EnsureAdminSafetyAsync();
        }

        public async Task DeleteAsync(Guid publicId)
        {
            // Soft delete
            const string sql = @"
                UPDATE users
                SET is_deleted = 1,
                    deleted_at = SYSUTCDATETIME()
                WHERE guid = @guid";

            await ExecuteNonQueryAsync(sql, new[] { CreateParameter("guid", publicId.ToString()) });
            await EnsureAdminSafetyAsync();
        }

        // ── Restoration ───────────────────────────────────────────────────────

        private const string SelectSqlIncludingDeleted = @"
            SELECT u.user_id, u.guid, u.access_id, u.email, u.username, u.password_hash, u.email_verified, u.status, u.is_deleted, u.deleted_at, u.created_at, u.updated_at, r.role_name AS user_role
            FROM users u
            LEFT JOIN Access_Roles r ON u.access_id = r.access_id
            WHERE 1=1";

        public async Task<IEnumerable<User>> GetDeletedAsync()
        {
            var sql = SelectSqlIncludingDeleted + " AND u.is_deleted = 1";
            return await ExecuteReaderToListAsync(sql, MapReaderToUser);
        }

        public async Task<User?> GetByIdIncludingDeletedAsync(Guid publicId)
        {
            var sql = SelectSqlIncludingDeleted + " AND u.guid = @guid";
            var results = await ExecuteReaderToListAsync(sql, MapReaderToUser,
                new[] { CreateParameter("guid", publicId.ToString()) });
            return results.FirstOrDefault();
        }

        public async Task<User?> GetByEmailIncludingDeletedAsync(string email)
        {
            var sql = SelectSqlIncludingDeleted + " AND u.email = @email";
            var results = await ExecuteReaderToListAsync(sql, MapReaderToUser,
                new[] { CreateParameter("email", email) });
            return results.FirstOrDefault();
        }

        public async Task<User?> GetByUserNameIncludingDeletedAsync(string userName)
        {
            var sql = SelectSqlIncludingDeleted + " AND u.username = @username";
            var results = await ExecuteReaderToListAsync(sql, MapReaderToUser,
                new[] { CreateParameter("username", userName) });
            return results.FirstOrDefault();
        }

        public async Task RestoreAsync(Guid publicId)
        {
            const string sql = @"
                UPDATE users
                SET is_deleted = 0,
                    deleted_at = NULL,
                    status = 'ACTIVE',
                    updated_at = SYSUTCDATETIME()
                WHERE guid = @guid";

            await ExecuteNonQueryAsync(sql, new[] { CreateParameter("guid", publicId.ToString()) });
            await EnsureAdminSafetyAsync();
        }

        // ── Default Admin ──────────────────────────────────────────────────────

        public async Task<User?> GetDefaultAdminAsync()
        {
            var sql = SelectSql + " AND u.username = 'admin' AND u.access_id = 1";
            var results = await ExecuteReaderToListAsync(sql, MapReaderToUser);
            return results.FirstOrDefault();
        }

        public async Task<bool> HasOtherActiveAdminAsync()
        {
            const string sql = @"
                SELECT COUNT(1) 
                FROM users 
                WHERE access_id = 1 
                  AND username != 'admin' 
                  AND is_deleted = 0 
                  AND status = 'ACTIVE'";

            var results = await ExecuteReaderToListAsync(sql, r => r.GetInt32(0));
            return results.FirstOrDefault() > 0;
        }

        public async Task RetireDefaultAdminAsync()
        {
            const string sql = @"
                UPDATE users
                SET    status = 'RETIRED',
                       updated_at = SYSUTCDATETIME()
                WHERE  username = 'admin'
                  AND  access_id = 1
                  AND  status != 'RETIRED'";

            await ExecuteNonQueryAsync(sql);
        }

        public async Task ReactivateDefaultAdminAsync()
        {
            const string sql = @"
                UPDATE users
                SET    status = 'ACTIVE',
                       is_deleted = 0,
                       updated_at = SYSUTCDATETIME()
                WHERE  username = 'admin'
                  AND  access_id = 1";

            await ExecuteNonQueryAsync(sql);
        }

        public async Task EnsureAdminSafetyAsync()
        {
            if (await HasOtherActiveAdminAsync())
            {
                await RetireDefaultAdminAsync();
            }
            else
            {
                await ReactivateDefaultAdminAsync();
            }
        }
    }
}