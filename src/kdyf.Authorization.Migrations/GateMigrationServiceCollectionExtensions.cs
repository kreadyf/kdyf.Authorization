using Microsoft.Extensions.Logging;
using kdyf.Authorization.Administration.AspNetCore;
using kdyf.Authorization.Administration.EntraId;
using kdyf.Authorization.EntraId;
using kdyf.Authorization.EntraId.Migration;

// Top-level namespace on purpose: the host finds it with the usings it already has.
namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>Registration of the migration of the access gate to assignments to the Enterprise application.</summary>
    public static class GateMigrationServiceCollectionExtensions
    {
        /// <summary>
        /// The migration of the access gate from the Entra group to assignments to the Enterprise application, for the
        /// host that administers access: while <c>Directory:Gate</c> is <c>Migrating</c>, the administration writes every
        /// change to both, and a background sync keeps the assignments equal to the group, audited as
        /// <c>system:migration</c>.
        /// </summary>
        /// <remarks>
        /// <para>
        /// After <c>AddKdyfAuthorizationAdministration</c>. Harmless with any other gate: the sync does nothing and the
        /// administration writes only where the gate says. Remove it, and the package, once the gate is
        /// <c>AppAssignment</c>.
        /// </para>
        /// <para>
        /// A host that only reads (a SPA host without administration) does not need it: with the gate on
        /// <c>Migrating</c> it decides by the group and logs every difference with the assignments on its own.
        /// </para>
        /// </remarks>
        public static IServiceCollection AddKdyfAuthorizationGateMigration(this IServiceCollection services)
        {
            if (!services.Any(d => d.ServiceType == typeof(AdministrationDbContext)))
                throw new InvalidOperationException(
                    "AddKdyfAuthorizationGateMigration changes access and audits it: call AddKdyfAuthorizationAdministration(...) first.");

            services.AddSingleton<GateMigrationRegistration>();
            services.AddScoped<IMigratingAccessDirectory>(provider => new DualWriteAccessDirectory(
                provider.GetRequiredService<GraphAccessGroupDirectory>(),
                provider.GetRequiredService<GraphAccessAssignmentDirectory>(),
                provider.GetRequiredService<ILogger<DualWriteAccessDirectory>>()));
            services.AddHostedService<GateMigrationService>();

            return services;
        }
    }
}
