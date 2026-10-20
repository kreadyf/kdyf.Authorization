using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using kdyf.Authorization.Administration.Persistence;
using kdyf.Authorization.EntityFrameworkCore;

namespace kdyf.Authorization.Administration.AspNetCore
{
    /// <summary>
    /// The <c>auth.*</c> tables the administration writes: the authorization tables — roles, what each grants,
    /// who holds which, tokens — AND the audit log, in the schema of <see cref="AuthorizationStoreOptions.Schema"/>.
    /// Registered by <c>AddKdyfAuthorizationAdministration</c> on the same database and provider as
    /// <see cref="AuthorizationDbContext"/>.
    /// </summary>
    /// <remarks>
    /// Both models on ONE context: a change and its audit entry are written in a single transaction. Authorization
    /// keeps reading through its own <see cref="AuthorizationDbContext"/> — same database, same tables; the caches the
    /// administration invalidates are services, not contexts, so the two never disagree for longer than a request.
    /// </remarks>
    public sealed class AdministrationDbContext : DbContext, ISchemaQualifiedContext
    {
        private readonly string _schema;

        /// <summary>Creates the context. <paramref name="store"/> gives the schema the tables live in.</summary>
        public AdministrationDbContext(DbContextOptions<AdministrationDbContext> options, IOptions<AuthorizationStoreOptions> store)
            : base(options)
        {
            _schema = store.Value.Schema;
        }

        /// <inheritdoc />
        public string Schema => _schema;

        /// <summary>One model per schema, not one per context type: see <see cref="SchemaModelCacheKeyFactory"/>.</summary>
        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder) =>
            optionsBuilder.ReplaceService<Microsoft.EntityFrameworkCore.Infrastructure.IModelCacheKeyFactory, SchemaModelCacheKeyFactory>();

        /// <summary>Applies the authorization model and the administration model (the audit log) in the configured schema.</summary>
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);
            modelBuilder.ApplyAuthorizationModel(_schema, ModelBuilderExtensions.KeyCollationFor(Database));
            modelBuilder.ApplyAdministrationModel(_schema);
        }
    }
}
