using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using kdyf.Authorization.Administration.Abstractions;
using kdyf.Authorization.Administration.AspNetCore;
using kdyf.Authorization.Administration.EntraId;

namespace kdyf.Authorization.EntraId.Migration
{
    /// <summary>
    /// Runs the migration (<see cref="GateMigration"/>) when the host starts and every
    /// <c>Directory:MigrationSyncInterval</c>, while <c>Directory:Gate</c> is <c>Migrating</c>. With any other gate it does
    /// nothing.
    /// </summary>
    /// <remarks>
    /// It never holds the host back: a pass that fails is logged and the next one tries again. The gate is read on every
    /// pass, so switching it in the configuration stops or starts the sync without a restart where the configuration
    /// reloads.
    /// </remarks>
    internal sealed class GateMigrationService : BackgroundService
    {
        private readonly IServiceScopeFactory _scopes;
        private readonly IOptionsMonitor<EntraIdAuthorizationOptions> _options;
        private readonly ILogger<GateMigrationService> _logger;

        public GateMigrationService(IServiceScopeFactory scopes, IOptionsMonitor<EntraIdAuthorizationOptions> options, ILogger<GateMigrationService> logger)
        {
            _scopes = scopes;
            _options = options;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            // Let the host finish starting: the first pass is not part of the startup.
            await Task.Yield();

            while (!stoppingToken.IsCancellationRequested)
            {
                var directory = _options.CurrentValue.Directory;
                if (directory.Gate == AccessGate.Migrating)
                {
                    try
                    {
                        await using var scope = _scopes.CreateAsyncScope();
                        var services = scope.ServiceProvider;
                        var db = services.GetRequiredService<AdministrationDbContext>();
                        await new GateMigration(
                                services.GetRequiredService<GraphAccessGroupDirectory>(),
                                services.GetRequiredService<IAccessAssignments>(),
                                services.GetRequiredService<IAuditLog>(),
                                ct => db.SaveChangesAsync(ct),
                                _logger)
                            .RunAsync(stoppingToken);
                    }
                    catch (Exception ex) when (ex is not OperationCanceledException)
                    {
                        _logger.LogError(ex, "Access gate migration: the pass failed; the next one tries again.");
                    }
                }

                try
                {
                    await Task.Delay(directory.MigrationSyncInterval, stoppingToken);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
            }
        }
    }
}
