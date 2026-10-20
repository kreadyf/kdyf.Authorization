using kdyf.Authorization.Abstractions;
using kdyf.Authorization.Authorization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace kdyf.Authorization.Startup
{
    /// <summary>
    /// On startup, walks all endpoints, extracts the policy names from their [Authorize]
    /// attributes and checks that each one is either a REGISTERED policy or a permission code
    /// that exists in the catalog.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Turns a typo (which would only produce mysterious, silent 403s) into an obvious
    /// failure. Outside Production it aborts startup; in Production it logs a critical event
    /// but keeps the application up: tearing down the whole service over this would be worse.
    /// </para>
    /// <para>
    /// Both forms are accepted because both are legitimate, and the provider resolves them in
    /// that order: a registered policy wins, and only an unknown name is read as a permission
    /// code. Checking the catalog alone would condemn every declared policy the moment its name
    /// stopped being a code — which is exactly what declaring policies is for.
    /// </para>
    /// </remarks>
    public sealed class PolicyValidationHostedService : IHostedService
    {
        private readonly IServiceProvider _services;
        private readonly PermissionAuthorizationOptions _options;
        private readonly IHostEnvironment _environment;
        private readonly ILogger<PolicyValidationHostedService> _logger;

        /// <summary>For the container.</summary>
        public PolicyValidationHostedService(
            IServiceProvider services,
            PermissionAuthorizationOptions options,
            IHostEnvironment environment,
            ILogger<PolicyValidationHostedService> logger)
        {
            _services = services;
            _options = options;
            _environment = environment;
            _logger = logger;
        }

        /// <summary>
        /// Runs the check. An unknown name throws <see cref="InvalidOperationException"/> in any environment other than
        /// Production, and is logged as critical in Production.
        /// </summary>
        /// <remarks>
        /// Skipped, with a log entry, when no <see cref="IPermissionCatalog"/> is registered or the catalog cannot be
        /// read; skipped silently when there is no <see cref="EndpointDataSource"/>.
        /// </remarks>
        public async Task StartAsync(CancellationToken cancellationToken)
        {
            using var scope = _services.CreateScope();

            var catalog = scope.ServiceProvider.GetService<IPermissionCatalog>();
            if (catalog is null)
            {
                _logger.LogWarning(
                    "ValidatePoliciesOnStartup is enabled but no IPermissionCatalog is registered: policy names will not be validated.");
                return;
            }

            var endpointSource = scope.ServiceProvider.GetService<EndpointDataSource>();
            if (endpointSource is null)
                return;

            IReadOnlySet<string> known;
            try
            {
                known = await catalog.GetAllAsync(cancellationToken);
            }
            catch (Exception ex)
            {
                // Don't block startup because the DB isn't available yet.
                _logger.LogError(ex, "Could not read the permission catalog: policy validation is skipped.");
                return;
            }

            // Registered policies answer for themselves: their name is a name, not a code.
            // OrdinalIgnoreCase because that is how AuthorizationOptions keys them.
            var registered = scope.ServiceProvider.GetService<PolicyCatalog>() is { } policies
                ? policies.Policies.Select(p => p.Name).ToHashSet(StringComparer.OrdinalIgnoreCase)
                : new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            var names = endpointSource.Endpoints
                .SelectMany(e => e.Metadata.GetOrderedMetadata<IAuthorizeData>())
                .Select(a => a.Policy)
                .Where(p => !string.IsNullOrWhiteSpace(p))
                .Select(p => p!)
                .Distinct(StringComparer.Ordinal)
                .ToList();

            // Only a name nobody registered is read as a permission code, and only then does the
            // catalog have anything to say. A policy can still enumerate several codes in OR
            // ("A|B"), so each part is checked on its own.
            var used = names
                .Where(name => !registered.Contains(name))
                .SelectMany(name => name.Split(
                    _options.AnyOfSeparator,
                    StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                .Distinct(StringComparer.Ordinal)
                .ToList();

            var unknown = used
                .Where(p => !known.Contains(p) && !_options.IgnoredPolicyNames.Contains(p))
                .OrderBy(p => p, StringComparer.Ordinal)
                .ToList();

            if (unknown.Count == 0)
            {
                _logger.LogInformation(
                    "Policy validation passed: {Registered} declared policies and {Codes} permissions "
                    + "read as codes, all present in the catalog.",
                    names.Count - used.Count, used.Count);
                return;
            }

            var message =
                $"There are {unknown.Count} policy(ies) used in [Authorize] that do not exist in the permission catalog: " +
                $"{string.Join(", ", unknown)}. They would always deny, silently.";

            if (_environment.IsProduction())
                _logger.LogCritical(message);
            else
                throw new InvalidOperationException(message);
        }

        /// <summary>Nothing to stop.</summary>
        public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
