using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace kdyf.Authorization.Roles
{
    /// <summary>
    /// At startup, reports configured role permissions whose code the application no longer declares.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The moment a permission class is removed, or its namespace changes, is a deployment: this puts the
    /// consequence in that deployment's log instead of leaving it to be discovered as "somebody lost access".
    /// Such codes grant nothing — they are ignored — and <c>DELETE /auth/roles/orphans</c> removes them.
    /// </para>
    /// <para>
    /// It only warns. A database that is not reachable yet is logged and startup goes on: authorization fails
    /// closed on its own, and refusing to start over a report would turn a warning into an outage.
    /// </para>
    /// </remarks>
    internal sealed class RolePermissionStartupCheck : IHostedService
    {
        private readonly RolePermissionMapProvider _roles;
        private readonly ILogger<RolePermissionStartupCheck> _logger;

        public RolePermissionStartupCheck(RolePermissionMapProvider roles, ILogger<RolePermissionStartupCheck> logger)
        {
            _roles = roles;
            _logger = logger;
        }

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            try
            {
                var undeclared = (await _roles.GetAsync(cancellationToken)).Undeclared;
                if (undeclared.Count == 0)
                    return;

                _logger.LogWarning(
                    "The role configuration grants permissions this version of the application does not declare; they "
                    + "grant nothing. A permission class was removed or its namespace changed. Reconfigure the roles, or "
                    + "remove them with DELETE /auth/roles/orphans: {Undeclared}.",
                    string.Join("; ", undeclared.Select(u => $"{u.Key}: {string.Join(", ", u.Value)}")));
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogError(ex, "The role configuration could not be checked at startup.");
            }
        }

        public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
