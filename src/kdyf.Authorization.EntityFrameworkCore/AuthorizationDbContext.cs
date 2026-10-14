using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace kdyf.Authorization.EntityFrameworkCore
{
    /// <summary>
    /// The <c>auth.*</c> tables authorization reads — the roles, what each grants, who holds which, the
    /// permission catalog and personal access tokens — in the schema of <see cref="AuthorizationStoreOptions.Schema"/>.
    /// Registered by <c>UseEntityFrameworkStore</c>, on the database provider the host chose.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Authorization only: no audit log. A host that administers access registers
    /// <c>AddKdyfAuthorizationAdministration</c>, whose own context maps both models so that a change and its audit
    /// entry are written in a single transaction.
    /// </para>
    /// <para>
    /// There is no user table: people live in the identity provider, and are named here by their object id.
    /// </para>
    /// <para>
    /// EF Core does not create or migrate these tables: the SQL script that ships with the host does. The model
    /// and the script must tell the same story. EF caches the model per context TYPE, so the schema is read
    /// once per process.
    /// </para>
    /// </remarks>
    public sealed class AuthorizationDbContext : DbContext
    {
        private readonly string _schema;

        public AuthorizationDbContext(DbContextOptions<AuthorizationDbContext> options, IOptions<AuthorizationStoreOptions> store)
            : base(options)
        {
            _schema = store.Value.Schema;
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);
            modelBuilder.ApplyAuthorizationModel(_schema);
        }
    }
}
