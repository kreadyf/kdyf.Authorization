using kdyf.Authorization.Abstractions;
using kdyf.Authorization.EntraId;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

// Top-level namespace on purpose: the host finds it with the usings it already has.
namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>Registration of the Entra ID membership source and the Graph plumbing.</summary>
    public static class EntraIdServiceCollectionExtensions
    {
        /// <summary>
        /// Reads who may use the application from Microsoft Entra ID — the access group, or the assignments to the Enterprise
        /// application, as <see cref="EntraGraphOptions.Gate"/> says — as the <see cref="IMembershipSource"/>, plus the
        /// shared Graph plumbing.
        /// </summary>
        /// <remarks>
        /// Configure <see cref="EntraGraphOptions"/> separately (<c>UseEntraId</c> fills it from the library's
        /// section). Pair it with <c>AddPermissionAuthorization().AddAssignedRoles(assembly)</c> and a
        /// source of roles (<c>AddEfRoles</c>).
        /// </remarks>
        public static IServiceCollection AddEntraGroupMembership(this IServiceCollection services)
        {
            services.AddOptions<EntraGraphOptions>();
            services.AddHttpClient(GraphClient.HttpClientName);

            // Singletons: the token cache must outlive a request. TryAdd, because the administration package
            // calls this too, and a test may put a fake in first.
            services.TryAddSingleton<GraphTokenProvider>();
            services.TryAddSingleton<GraphClient>();

            services.TryAddSingleton<GraphAppRoleAssignments>();
            services.TryAddSingleton<IAccessAssignments>(provider => provider.GetRequiredService<GraphAppRoleAssignments>());

            // Who may use the application, by Directory:Gate: the access group (the default), the assignments to the
            // Enterprise application, or the group while both are compared. Chosen per resolution from the options, so the
            // gate changes with the configuration and nothing else.
            services.TryAddScoped<GraphMembershipSource>();
            services.TryAddScoped<GraphAppAssignmentMembershipSource>();
            services.TryAddScoped<MigratingMembershipSource>();
            services.TryAddScoped<IMembershipSource>(provider => provider.GetRequiredService<IOptions<EntraGraphOptions>>().Value.Gate switch
            {
                AccessGate.AppAssignment => provider.GetRequiredService<GraphAppAssignmentMembershipSource>(),
                AccessGate.Migrating => provider.GetRequiredService<MigratingMembershipSource>(),
                _ => provider.GetRequiredService<GraphMembershipSource>(),
            });

            return services;
        }
    }
}
