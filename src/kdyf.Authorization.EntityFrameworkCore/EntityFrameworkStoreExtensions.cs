using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using kdyf.Authorization.Hosting;

namespace kdyf.Authorization.EntityFrameworkCore
{
    /// <summary>
    /// How the host's contexts reach the database: the provider it chose, applied to every context of the library —
    /// <see cref="AuthorizationDbContext"/> and the administration's, which shares the tables.
    /// </summary>
    public sealed class EntityFrameworkStore
    {
        private readonly Action<DbContextOptionsBuilder, string> _configure;

        internal EntityFrameworkStore(Action<DbContextOptionsBuilder, string> configure) => _configure = configure;

        /// <summary>Applies the host's provider with the configured connection string.</summary>
        public void Configure(DbContextOptionsBuilder options, IServiceProvider services)
        {
            ArgumentNullException.ThrowIfNull(options);
            ArgumentNullException.ThrowIfNull(services);
            _configure(options, services.GetRequiredService<IOptions<AuthorizationStoreOptions>>().Value.ConnectionString!);
        }
    }

    public static class EntityFrameworkStoreExtensions
    {
        /// <summary>
        /// Roles, what each grants, who holds which, personal access tokens and the permission catalog in the
        /// <c>auth.*</c> tables, through EF Core on the database the host chooses.
        /// </summary>
        /// <remarks>
        /// <para>Reads, from the library's section: <c>ConnectionStringName</c> (default <c>Authorization</c>) and
        /// <c>Schema</c> (default <c>auth</c>). The connection string itself is the application's,
        /// <c>ConnectionStrings:{ConnectionStringName}</c>. Both are validated when the host starts.</para>
        /// <para>Registers <see cref="AuthorizationDbContext"/>, the role sources, the PAT store and the catalog
        /// synchronizer, which brings <c>auth.Permission</c> in line with the declared classes at startup.</para>
        /// </remarks>
        /// <param name="builder">The composition.</param>
        /// <param name="configure">
        /// The database provider, given the connection string: <c>(db, connectionString) =&gt; db.UseSqlServer(connectionString)</c>.
        /// </param>
        public static TBuilder UseEntityFrameworkStore<TBuilder>(this TBuilder builder, Action<DbContextOptionsBuilder, string> configure)
            where TBuilder : IKdyfAuthorizationBuilder =>
            builder.UseEntityFrameworkStore(AuthorizationStoreOptions.DefaultConnectionStringName, configure);

        /// <summary>
        /// As above, with the host's own default for the connection string's name: a host whose configuration always
        /// named its database keeps doing so, without a <c>ConnectionStringName</c> key. The key, when present, still wins.
        /// </summary>
        /// <param name="builder">The composition.</param>
        /// <param name="connectionStringName">The name under <c>ConnectionStrings</c> used when the section does not give one.</param>
        /// <param name="configure">The database provider, given the connection string.</param>
        public static TBuilder UseEntityFrameworkStore<TBuilder>(
            this TBuilder builder, string connectionStringName, Action<DbContextOptionsBuilder, string> configure)
            where TBuilder : IKdyfAuthorizationBuilder
        {
            ArgumentNullException.ThrowIfNull(builder);
            ArgumentException.ThrowIfNullOrWhiteSpace(connectionStringName);
            ArgumentNullException.ThrowIfNull(configure);

            builder.AddProvider(nameof(UseEntityFrameworkStore), context =>
            {
                var services = context.Services;

                // The host's default first, then the section: a ConnectionStringName key overrides it.
                services.AddOptions<AuthorizationStoreOptions>()
                    .Configure(options => options.ConnectionStringName = connectionStringName)
                    .Bind(context.Section)
                    .Configure(options => options.ConnectionString = context.Configuration.GetConnectionString(options.ConnectionStringName))
                    .ValidateOnStart();
                services.AddSingleton<IValidateOptions<AuthorizationStoreOptions>>(new AuthorizationStoreOptionsValidator(context.Section.Path));

                var store = new EntityFrameworkStore(configure);
                services.AddSingleton(store);
                services.AddDbContext<AuthorizationDbContext>((provider, options) => store.Configure(options, provider));

                services.AddEfPatStore<AuthorizationDbContext>();

                // The roles, what each grants and who holds which: read here; administered where
                // AddKdyfAuthorizationAdministration is registered.
                services.AddEfRoles<AuthorizationDbContext>();

                // Suspension and the last access (auth.UserProfile, schema version 4). No row means active.
                services.AddEfUserProfiles<AuthorizationDbContext>();

                // Which permissions exist, persisted: auth.Permission is brought in line with the declared classes
                // when the host starts (inserted, names updated, never deleted). RolePermission points at it.
                var declarations = context.DeclarationAssemblies;
                services.AddPermissionCatalogSync<AuthorizationDbContext>(declarations[0], sync =>
                {
                    foreach (var assembly in declarations.Skip(1))
                        sync.Assemblies.Add(assembly);
                });

                // Before the catalog sync, which writes to the tables: the schema is the version these packages expect.
                services.Insert(0, ServiceDescriptor.Singleton<IHostedService, SchemaVersionCheck<AuthorizationDbContext>>());
            });

            return builder;
        }
    }
}
