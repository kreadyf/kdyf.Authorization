using kdyf.Authorization.Abstractions;

namespace kdyf.Authorization.Caching
{
    /// <summary>
    /// The name this store had before the permission hierarchy. It is <see cref="HierarchyExpandingPermissionStore"/>,
    /// which still reads the legacy <c>*</c> and <c>prefix.*</c> as the root and <c>prefix</c>.
    /// </summary>
    [Obsolete("Use HierarchyExpandingPermissionStore: wildcards are replaced by the permission hierarchy.")]
    public sealed class WildcardExpandingPermissionStore : IPermissionStore
    {
        private readonly HierarchyExpandingPermissionStore _store;

        /// <param name="inner">The store whose grants may be nodes (or legacy wildcards).</param>
        /// <param name="catalog">The codes the nodes expand to.</param>
        public WildcardExpandingPermissionStore(IPermissionStore inner, IPermissionCatalog catalog)
        {
            _store = new HierarchyExpandingPermissionStore(inner, catalog);
        }

        /// <inheritdoc cref="HierarchyExpandingPermissionStore.GetPermissionsAsync"/>
        public Task<IReadOnlySet<string>> GetPermissionsAsync(UserIdentity user, CancellationToken cancellationToken = default) =>
            _store.GetPermissionsAsync(user, cancellationToken);
    }
}
