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
        private readonly DeclaredPermissions _declared;
        private readonly ILogger<RolePermissionStartupCheck> _logger;

        public RolePermissionStartupCheck(
            RolePermissionMapProvider roles, DeclaredPermissions declared, ILogger<RolePermissionStartupCheck> logger)
        {
            _roles = roles;
            _declared = declared;
            _logger = logger;
        }

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            // Wildcard classes left over from before 1.2.0: harmless (a node covers its area), but dead code that
            // reads as if it granted something.
            if (_declared.IgnoredWildcards.Count > 0)
                _logger.LogWarning(
                    "These permission classes declare a wildcard, which the permission tree has replaced: grant the node "
                    + "instead ('' for everything, 'area' for an area). They were left out of the catalog; delete them: {Wildcards}.",
                    string.Join(", ", _declared.IgnoredWildcards));

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
