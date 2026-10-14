namespace kdyf.Authorization.EntityFrameworkCore.Entities
{
    /// <summary>
    /// A permission of the catalog, as persisted in <c>auth.Permission</c>.
    /// </summary>
    /// <remarks>
    /// Defined by CODE, never by an administrator: every row mirrors a <c>PermissionDefinition</c> class,
    /// written by <see cref="PermissionCatalogSynchronizer{TContext}"/> when the host starts. It is what
    /// <c>auth.RolePermission</c> points at, so a role can only be given a permission that exists here.
    /// A row whose class was removed stays (the synchronizer never deletes) and grants nothing.
    /// </remarks>
    public class Permission
    {
        /// <summary>The code, e.g. <c>portal.Read</c>, or a wildcard (<c>*</c>). The key.</summary>
        public string PermissionCode { get; set; } = string.Empty;

        /// <summary>Human-readable name of the permission.</summary>
        public string? Name { get; set; }

        public string? Description { get; set; }
    }
}
