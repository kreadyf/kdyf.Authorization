using System.Reflection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace kdyf.Authorization.EntityFrameworkCore
{
    /// <summary>
    /// Registration of the catalog synchronisation.
    /// </summary>
    public static class PermissionCatalogSyncExtensions
    {
        /// <summary>
        /// Syncs <c>auth.Permission</c> with the permissions declared in
        /// <paramref name="declarations"/> when the host starts: inserts what is missing, updates a
        /// name or description that changed, deletes nothing.
        /// </summary>
        /// <remarks>
        /// Runs before every other hosted service, whatever the order of the registrations: a check
        /// that reads the catalog would otherwise fail on precisely the rows this is about to write.
        /// </remarks>
        /// <param name="declarations">
        /// The assembly holding the <c>PermissionDefinition</c> subclasses — normally the host's own.
        /// </param>
        public static IServiceCollection AddPermissionCatalogSync<TContext>(
            this IServiceCollection services,
            Assembly declarations,
            Action<PermissionCatalogSyncOptions>? configure = null)
            where TContext : DbContext
        {
            var options = new PermissionCatalogSyncOptions();
            options.Assemblies.Add(declarations);
            configure?.Invoke(options);

            services.AddSingleton(options);

            // Hosted services start in registration order. First, so nothing reads the catalog
            // before it is written — regardless of where this line sits in Program.cs.
            services.Insert(0, ServiceDescriptor.Singleton<IHostedService, PermissionCatalogSynchronizer<TContext>>());

            return services;
        }
    }
}
