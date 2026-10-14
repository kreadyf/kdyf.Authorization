using kdyf.Authorization.Abstractions;
using kdyf.Authorization.Authorization;

namespace kdyf.Authorization.Caching
{
    /// <summary>
    /// Resolves the patterns a role may grant (<c>*</c>, <c>prefix.*</c>) into real permission codes,
    /// so that everything downstream keeps comparing exact strings.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Sits between the consumer's store and the cache — <c>Caching(WildcardExpanding(Store))</c> —
    /// so an expanded set is cached like any other and the catalog is not re-read on every request.
    /// </para>
    /// <para>
    /// <b>It throws rather than degrades.</b> If the catalog cannot be read, the alternative would be
    /// to hand back the unexpanded set: an administrator holding only <c>*</c> would silently shrink
    /// to almost nothing, that reduced set would be CACHED for the full duration (it is not empty, so
    /// the short empty-result window does not apply), and the administration service would then count
    /// zero administrators and refuse every change. Throwing is what <see cref="IPermissionStore"/>
    /// prescribes for a real failure, and the handler turns it into a clean denial.
    /// </para>
    /// </remarks>
    public sealed class WildcardExpandingPermissionStore : IPermissionStore
    {
        private readonly IPermissionStore _inner;
        private readonly IPermissionCatalog _catalog;

        public WildcardExpandingPermissionStore(IPermissionStore inner, IPermissionCatalog catalog)
        {
            _inner = inner;
            _catalog = catalog;
        }

        public async Task<IReadOnlySet<string>> GetPermissionsAsync(
            UserIdentity user, CancellationToken cancellationToken = default)
        {
            var granted = await _inner.GetPermissionsAsync(user, cancellationToken);

            // The overwhelming majority of users hold no pattern at all. Checking first means they
            // never pay for the catalog read.
            if (!PermissionWildcards.ContainsPattern(granted))
                return granted;

            var catalog = await _catalog.GetAllAsync(cancellationToken);

            return PermissionWildcards.Expand(granted, catalog);
        }
    }
}
