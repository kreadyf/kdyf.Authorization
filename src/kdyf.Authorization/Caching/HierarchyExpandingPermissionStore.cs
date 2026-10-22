using kdyf.Authorization.Abstractions;
using kdyf.Authorization.Authorization;

namespace kdyf.Authorization.Caching
{
    /// <summary>
    /// Expands each granted node to the catalog codes below it (<see cref="PermissionHierarchy.Expand"/>), so that
    /// everything downstream keeps comparing exact strings.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Sits between the consumer's store and the cache — <c>Caching(HierarchyExpanding(Store))</c> — so an expanded set
    /// is cached like any other and the catalog is not re-read on every request.
    /// </para>
    /// <para>
    /// <b>It throws rather than degrades.</b> If the catalog cannot be read, the alternative would be to hand back the
    /// unexpanded set: an administrator holding only the root would silently shrink to almost nothing, that reduced set
    /// would be CACHED for the full duration, and the administration service would then count zero administrators and
    /// refuse every change. Throwing is what <see cref="IPermissionStore"/> prescribes for a real failure, and the
    /// handler turns it into a clean denial.
    /// </para>
    /// </remarks>
    public sealed class HierarchyExpandingPermissionStore : IPermissionStore
    {
        private readonly IPermissionStore _inner;
        private readonly IPermissionCatalog _catalog;

        /// <param name="inner">The store whose grants may be nodes (or legacy wildcards).</param>
        /// <param name="catalog">The codes the nodes expand to.</param>
        public HierarchyExpandingPermissionStore(IPermissionStore inner, IPermissionCatalog catalog)
        {
            _inner = inner;
            _catalog = catalog;
        }

        /// <summary>
        /// The inner store's grants, as paths, plus the catalog codes they cover. Nothing granted reads no catalog; a
        /// catalog failure throws.
        /// </summary>
        public async Task<IReadOnlySet<string>> GetPermissionsAsync(
            UserIdentity user, CancellationToken cancellationToken = default)
        {
            var granted = PermissionHierarchy.NormalizeStoredGrants(await _inner.GetPermissionsAsync(user, cancellationToken));
            if (granted.Count == 0)
                return granted;

            return PermissionHierarchy.Expand(granted, await _catalog.GetAllAsync(cancellationToken));
        }
    }
}
