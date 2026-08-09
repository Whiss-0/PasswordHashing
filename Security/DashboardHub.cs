using Microsoft.AspNetCore.SignalR;

namespace Api.Security
{
    /// <summary>
    /// SignalR hub for real-time dashboard updates (e.g. security alerts).
    /// Clients join named groups (e.g. "AdminContent", "User_{userId}")
    /// to receive targeted notifications.
    /// </summary>
    public class DashboardHub : Hub
    {
        public async Task JoinGroup(string groupName)
            => await Groups.AddToGroupAsync(Context.ConnectionId, groupName);

        public async Task LeaveGroup(string groupName)
            => await Groups.RemoveFromGroupAsync(Context.ConnectionId, groupName);
    }
}
