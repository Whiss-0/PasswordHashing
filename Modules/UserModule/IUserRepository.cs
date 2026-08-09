using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Api.Modules.UserModule
{
    public interface IUserRepository
    {
        Task<IEnumerable<User>> GetAllAsync();
        Task AddAsync(User entity);
        Task UpdateAsync(User entity);
        Task DeleteAsync(Guid publicId);
        Task<User?> GetByIdAsync(Guid publicId);
        Task<User?> GetByUserNameAsync(string userName);
        Task<User?> GetByEmailAsync(string email);
        Task<IEnumerable<User>> GetByRoleIdAsync(int roleId);

        // ── Account Restoration ───────────────────────────────────────────────
        Task<IEnumerable<User>> GetDeletedAsync();
        Task<User?> GetByIdIncludingDeletedAsync(Guid publicId);
        Task<User?> GetByEmailIncludingDeletedAsync(string email);
        Task<User?> GetByUserNameIncludingDeletedAsync(string userName);
        Task RestoreAsync(Guid publicId);

        /// <summary>Finds a user by their Google OAuth provider user ID in authProvider table.</summary>
        Task<User?> GetByGoogleIdAsync(string googleId);

        /// <summary>
        /// Links (or updates) a Google OAuth record in authProvider table.
        /// </summary>
        Task LinkGoogleIdAsync(int userId, string googleId, string? providerEmail = null);

        /// <summary>Returns the default admin account (username = 'admin'), or null if retired/deleted.</summary>
        Task<User?> GetDefaultAdminAsync();

        /// <summary>Checks if any active admin user exists other than the default admin ('admin').</summary>
        Task<bool> HasOtherActiveAdminAsync();

        /// <summary>
        /// Sets status = 'RETIRED' on the default admin account. Safe to call multiple times.
        /// </summary>
        Task RetireDefaultAdminAsync();

        /// <summary>Reactivates the default admin account (status = 'ACTIVE').</summary>
        Task ReactivateDefaultAdminAsync();

        /// <summary>
        /// Ensures admin access is never lost. If no other active admin exists, reactivates default admin.
        /// If other active admins exist, retires default admin.
        /// </summary>
        Task EnsureAdminSafetyAsync();
    }
}