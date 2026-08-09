using Microsoft.AspNetCore.Authorization;

namespace Api.Modules.AuthorizationModule
{
    /// <summary>
    /// Represents a requirement that the current user must have at least one of the
    /// specified role IDs (read from the <c>user_role_id</c> JWT claim).
    /// </summary>
    public sealed class RoleRequirement : IAuthorizationRequirement
    {
        /// <summary>
        /// The set of role IDs that satisfy this requirement.
        /// The user must have ANY ONE of these roles (OR logic).
        /// </summary>
        public IReadOnlyList<int> AllowedRoleIds { get; }

        public RoleRequirement(params int[] allowedRoleIds)
        {
            if (allowedRoleIds == null || allowedRoleIds.Length == 0)
                throw new ArgumentException("At least one role ID must be specified.", nameof(allowedRoleIds));

            AllowedRoleIds = allowedRoleIds;
        }
    }

    /// <summary>
    /// Handles <see cref="RoleRequirement"/> by checking the <c>user_role_id</c>
    /// claim in the current user's JWT against the allowed role IDs.
    /// </summary>
    public sealed class RoleRequirementHandler : AuthorizationHandler<RoleRequirement>
    {
        protected override Task HandleRequirementAsync(
            AuthorizationHandlerContext context,
            RoleRequirement requirement)
        {
            var roleIdClaim = context.User.FindFirst("user_role_id")?.Value;

            if (!string.IsNullOrEmpty(roleIdClaim) &&
                int.TryParse(roleIdClaim, out int userRoleId) &&
                requirement.AllowedRoleIds.Contains(userRoleId))
            {
                context.Succeed(requirement);
            }

            return Task.CompletedTask;
        }
    }
}
