using Microsoft.AspNetCore.Authorization;

namespace Api.Modules.AuthorizationModule
{
    /// <summary>
    /// Centralized policy name constants and policy registration extension.
    /// </summary>
    public static class AppPolicies
    {
        // ── Single-role policies ───────────────────────────────────────────────

        /// <summary>Only access_id = 1 (Admin). Full system access.</summary>
        public const string AdminOnly = "AdminOnly";

        /// <summary>Only access_id = 2 (Staff). Staff-level access.</summary>
        public const string StaffOnly = "StaffOnly";

        /// <summary>Only access_id = 3 (User). Regular user access.</summary>
        public const string UserOnly  = "UserOnly";

        // ── Combined / multi-role policies ─────────────────────────────────────

        /// <summary>All staff roles (Admin, Staff).</summary>
        public const string StaffAndAbove = "StaffAndAbove";

        /// <summary>Any authenticated user regardless of role (Admin, Staff, User).</summary>
        public const string AllAuthenticatedUsers = "AllUsers";

        // ── Registration extension ─────────────────────────────────────────────

        public static void AddAppPolicies(this AuthorizationOptions options)
        {
            options.AddPolicy(AdminOnly,             p => p.AddRequirements(new RoleRequirement(AppRoles.Admin)));
            options.AddPolicy(StaffOnly,             p => p.AddRequirements(new RoleRequirement(AppRoles.Staff)));
            options.AddPolicy(UserOnly,              p => p.AddRequirements(new RoleRequirement(AppRoles.User)));
            options.AddPolicy(StaffAndAbove,         p => p.AddRequirements(new RoleRequirement(AppRoles.StaffRoles)));
            options.AddPolicy(AllAuthenticatedUsers, p => p.AddRequirements(new RoleRequirement(AppRoles.AllRoles)));
        }
    }
}
