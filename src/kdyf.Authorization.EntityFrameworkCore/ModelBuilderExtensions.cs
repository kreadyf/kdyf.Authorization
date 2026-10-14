using kdyf.Authorization.EntityFrameworkCore.Entities;
using Microsoft.EntityFrameworkCore;

namespace kdyf.Authorization.EntityFrameworkCore
{
    /// <summary>
    /// Registers the authorization model (schema <c>auth</c>) in the consumer's <see cref="ModelBuilder"/>:
    /// the permission catalog, the roles, what each grants, who holds which, and the personal access tokens.
    /// </summary>
    /// <remarks>
    /// No user table: people live in Entra and are named here by their object id only. Who may use the
    /// application at all is an Entra group, read through Graph — not a row.
    /// </remarks>
    public static class ModelBuilderExtensions
    {
        public const string DefaultSchema = "auth";

        /// <summary>
        /// Configures the authorization entities. Call from <c>OnModelCreating</c>, after
        /// <c>base.OnModelCreating(...)</c>. A consumer that also administers access adds
        /// <c>ApplyAdministrationModel()</c> after this, with the same schema.
        /// </summary>
        public static ModelBuilder ApplyAuthorizationModel(this ModelBuilder modelBuilder, string schema = DefaultSchema)
        {
            modelBuilder.Entity<Role>(e =>
            {
                e.ToTable("Role", schema);
                e.HasKey(x => x.RoleValue).HasName("PK_Role");
                // Binary collation in the script: a role value is compared exactly, everywhere.
                e.Property(x => x.RoleValue).HasColumnName("roleValue").HasMaxLength(100).IsUnicode(false);
                e.Property(x => x.Name).HasColumnName("name").HasMaxLength(200).IsRequired();
                e.Property(x => x.Description).HasColumnName("description").HasMaxLength(500);
                e.Property(x => x.CreatedAt).HasColumnName("createdAt");
            });

            // The permission catalog: one row per PermissionDefinition class, written by the
            // PermissionCatalogSynchronizer at startup. Wildcards ('*', 'area.*') are rows like any other.
            modelBuilder.Entity<Permission>(e =>
            {
                e.ToTable("Permission", schema);
                e.HasKey(x => x.PermissionCode).HasName("PK_Permission");
                e.Property(x => x.PermissionCode).HasColumnName("PermissionCode").HasMaxLength(50).IsUnicode(false);
                e.Property(x => x.Name).HasColumnName("name").HasMaxLength(100);
                e.Property(x => x.Description).HasColumnName("description").HasMaxLength(200);
            });

            modelBuilder.Entity<RolePermission>(e =>
            {
                e.ToTable("RolePermission", schema);
                e.HasKey(x => new { x.RoleValue, x.PermissionCode }).HasName("PK_RolePermission");
                e.Property(x => x.RoleValue).HasColumnName("roleValue").HasMaxLength(100).IsUnicode(false);
                e.Property(x => x.PermissionCode).HasColumnName("PermissionCode").HasMaxLength(50).IsUnicode(false);

                // What a role grants goes with the role.
                e.HasOne<Role>().WithMany().HasForeignKey(x => x.RoleValue)
                    .HasConstraintName("FK_RolePermission_Role").OnDelete(DeleteBehavior.Cascade);

                // Only a permission of the catalog can be granted. NOT cascade: a catalog row granted to a
                // role cannot disappear under it — the synchronizer never deletes, and the cleanup removes
                // the grants of an undeclared code before the code itself.
                e.HasOne<Permission>().WithMany().HasForeignKey(x => x.PermissionCode)
                    .HasConstraintName("FK_RolePermission_Permission").OnDelete(DeleteBehavior.Restrict);
            });

            modelBuilder.Entity<UserRole>(e =>
            {
                e.ToTable("UserRole", schema);
                e.HasKey(x => new { x.ObjectId, x.RoleValue }).HasName("PK_UserRole");
                e.Property(x => x.ObjectId).HasColumnName("objectId").HasMaxLength(50).IsUnicode(false);
                e.Property(x => x.RoleValue).HasColumnName("roleValue").HasMaxLength(100).IsUnicode(false);

                // NOT cascade: a role somebody holds cannot be deleted. Taking it away from everyone first is a
                // decision the lockout guard and the four-eyes rule get to look at, person by person.
                e.HasOne<Role>().WithMany().HasForeignKey(x => x.RoleValue)
                    .HasConstraintName("FK_UserRole_Role").OnDelete(DeleteBehavior.Restrict);

                // "Who holds this role?" — the role's user count, and the lockout guard.
                e.HasIndex(x => x.RoleValue).HasDatabaseName("IX_UserRole_Role");
            });

            modelBuilder.Entity<PersonalAccessToken>(e =>
            {
                e.ToTable("PersonalAccessToken", schema);
                e.HasKey(x => x.PersonalAccessTokenId);
                e.Property(x => x.PersonalAccessTokenId).HasColumnName("PersonalAccessTokenId");
                e.Property(x => x.Name).HasColumnName("name").HasMaxLength(100).IsRequired();
                e.Property(x => x.TokenHash).HasColumnName("tokenHash").HasColumnType("varbinary(32)").IsRequired();
                e.Property(x => x.TokenPrefix).HasColumnName("tokenPrefix").HasMaxLength(12);
                e.Property(x => x.OwnerObjectId).HasColumnName("ownerObjectId").HasMaxLength(50).IsRequired();
                e.Property(x => x.OwnerLabel).HasColumnName("ownerLabel").HasMaxLength(256).IsRequired();
                e.Property(x => x.IsActive).HasColumnName("isActive");
                e.Property(x => x.ExpiresAt).HasColumnName("expiresAt");
                e.Property(x => x.CreatedAt).HasColumnName("createdAt");
                e.Property(x => x.LastUsedAt).HasColumnName("lastUsedAt");

                // A non-admin user's listing filters by its owner.
                e.HasIndex(x => x.OwnerObjectId).HasDatabaseName("IX_PersonalAccessToken_Owner");
                // Looked up by hash on every request with a token: two rows with the same hash would make
                // a token resolve to one owner or another depending on the execution plan. In the mapping
                // as well as in the script, so the SQLite tests have it too.
                e.HasIndex(x => x.TokenHash).IsUnique().HasDatabaseName("UQ_PersonalAccessToken_Hash");
            });

            // The audit table (auth.AuditLog) is NOT mapped here: it belongs to administration.
            // ApplyAdministrationModel(), from kdyf.Authorization.Administration, applies it.

            return modelBuilder;
        }
    }
}
