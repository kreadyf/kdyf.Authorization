using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using kdyf.Authorization.Administration.Abstractions;
using kdyf.Authorization.Administration.EntraId;
using kdyf.Authorization.EntraId;

namespace kdyf.Authorization.Administration.EntraId
{
    /// <summary>
    /// The access directory while the gate migrates (<see cref="AccessGate.Migrating"/>): it reads the access group, which
    /// still decides, and writes every change to the group AND to the assignments. Implemented by
    /// kdyf.Authorization.Migrations.
    /// </summary>
    public interface IMigratingAccessDirectory : IAccessDirectory
    {
    }

    /// <summary>
    /// Registered, as a singleton, by the migration package next to its <see cref="IMigratingAccessDirectory"/>: what the
    /// startup check looks for, without resolving a scoped directory from the root.
    /// </summary>
    public sealed class GateMigrationRegistration
    {
    }

    /// <summary>
    /// Refuses, when the host starts, an administering host whose gate is <see cref="AccessGate.Migrating"/> without the
    /// migration package: it would change the group and leave the assignments behind.
    /// </summary>
    internal sealed class GateMigrationRegisteredValidator : IValidateOptions<EntraIdAuthorizationOptions>
    {
        private readonly IServiceProvider _services;

        public GateMigrationRegisteredValidator(IServiceProvider services) => _services = services;

        public ValidateOptionsResult Validate(string? name, EntraIdAuthorizationOptions options) =>
            options.Directory.Gate == AccessGate.Migrating && _services.GetService<GateMigrationRegistration>() is null
                ? ValidateOptionsResult.Fail(
                    "Directory:Gate is Migrating, but this host administers access without the migration: add the package "
                    + "kdyf.Authorization.Migrations and call AddKdyfAuthorizationGateMigration() after AddKdyfAuthorizationAdministration(...).")
                : ValidateOptionsResult.Success;
    }
}

// Top-level namespace on purpose: so the consumer only needs
// 'using Microsoft.Extensions.DependencyInjection;' to find this.
namespace Microsoft.Extensions.DependencyInjection
{
    public static class AzureAdAccessAdministrationExtensions
    {
        /// <summary>
        /// Administers access in Microsoft Entra ID: registers the access directory — the access group
        /// (<see cref="GraphAccessGroupDirectory"/>) or the assignments to the Enterprise application
        /// (<see cref="GraphAccessAssignmentDirectory"/>), as <c>Directory:Gate</c> says — and
        /// <see cref="GraphDirectoryService"/> (search and B2B invitations).
        /// </summary>
        /// <remarks>
        /// Also registers the shared Graph plumbing (<c>AddEntraGroupMembership</c>) if it is not there yet. Configure
        /// <c>EntraGraphOptions</c> and <see cref="GraphDirectoryOptions"/> separately; kdyf.Authorization.AspNetCore fills
        /// both from the library's section. With <see cref="AccessGate.Migrating"/> the directory is the migration
        /// package's (<see cref="IMigratingAccessDirectory"/>), and the host does not start without it.
        /// </remarks>
        public static IServiceCollection AddAzureAdAccessAdministration(this IServiceCollection services)
        {
            services.AddEntraGroupMembership();
            services.AddOptions<GraphDirectoryOptions>();

            services.AddScoped<GraphAccessGroupDirectory>();
            services.AddScoped<GraphAccessAssignmentDirectory>();
            services.AddScoped<IAccessDirectory>(provider => provider.GetRequiredService<IOptions<EntraGraphOptions>>().Value.Gate switch
            {
                AccessGate.AppAssignment => provider.GetRequiredService<GraphAccessAssignmentDirectory>(),
                AccessGate.Migrating => provider.GetService<IMigratingAccessDirectory>()
                    ?? throw new InvalidOperationException(
                        "Directory:Gate is Migrating: the access directory is kdyf.Authorization.Migrations's (AddKdyfAuthorizationGateMigration)."),
                _ => provider.GetRequiredService<GraphAccessGroupDirectory>(),
            });
            services.AddScoped<IDirectoryService, GraphDirectoryService>();

            services.AddSingleton<IValidateOptions<EntraIdAuthorizationOptions>>(provider => new GateMigrationRegisteredValidator(provider));

            return services;
        }
    }
}
