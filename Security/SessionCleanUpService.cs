namespace Api.Security
{
    public class SessionCleanupService : BackgroundService
    {
        private readonly IServiceScopeFactory           _scopeFactory;
        private readonly ILogger<SessionCleanupService> _logger;
        private readonly TimeSpan _interval = TimeSpan.FromMinutes(15);

        public SessionCleanupService(
            IServiceScopeFactory           scopeFactory,
            ILogger<SessionCleanupService> logger)
        {
            _scopeFactory = scopeFactory;
            _logger       = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("SessionCleanupService started. Interval: {Interval}", _interval);

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(_interval, stoppingToken);

                    using var scope  = _scopeFactory.CreateScope();
                    var sessionSvc   = scope.ServiceProvider.GetRequiredService<ISessionService>();
                    int purged       = await sessionSvc.PurgeExpiredSessionsAsync(stoppingToken);

                    if (purged > 0)
                        _logger.LogInformation("Purged {Count} expired session(s).", purged);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error during session cleanup.");
                }
            }

            _logger.LogInformation("SessionCleanupService stopped.");
        }
    }
}
