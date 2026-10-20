using System.Collections.Concurrent;
using kdyf.Authorization.Abstractions;
using kdyf.Authorization.Roles;

namespace kdyf.Authorization.Caching
{
    /// <summary>
    /// Decorator that caches the responses of the real store. Without it, every API request would be
    /// a database query — and, with the group gate, a Graph call too.
    /// </summary>
    /// <remarks>
    /// It is a decorator precisely so the store and the handler know nothing about the cache:
    /// switching to a distributed cache touches neither of those two pieces.
    ///
    /// It also coalesces concurrent misses: several requests carrying the same token that arrive at
    /// once, just after the entry expired, share a SINGLE resolution instead of each hitting the
    /// database and Graph. Without this, a page load right after expiry fans out into as many backend
    /// lookups as it fires API calls.
    /// </remarks>
    internal sealed class CachingPermissionStore : IPermissionStore
    {
        private readonly IPermissionStore _inner;
        private readonly MemoryPermissionCache _cache;
        private readonly RolePermissionMapProvider? _roles;

        // In-flight resolutions, per user, shared by EVERY request: this store is created per request, so they
        // live in the singleton cache. Lazy<Task> guarantees that the factory —which starts the task— runs only
        // once even if several threads enter at the same time.
        private ConcurrentDictionary<string, Lazy<Task<IReadOnlySet<string>>>> InFlight => _cache.InFlight;

        /// <param name="inner">The store that resolves.</param>
        /// <param name="cache">Where the answers are kept.</param>
        /// <param name="roles">
        /// The role map the inner store resolves through, when it does (<c>AddAssignedRoles</c>): an entry then ends
        /// no later than that map, so a role change reaches this instance within one <c>CacheDuration</c>.
        /// </param>
        public CachingPermissionStore(IPermissionStore inner, MemoryPermissionCache cache, RolePermissionMapProvider? roles = null)
        {
            _inner = inner;
            _cache = cache;
            _roles = roles;
        }

        public async Task<IReadOnlySet<string>> GetPermissionsAsync(
            UserIdentity user,
            CancellationToken cancellationToken = default)
        {
            if (_cache.TryGet(user, out var cached))
                return cached;

            // The first request in creates the resolution — with its own store, which it outlives by awaiting
            // it; those arriving while it runs await the same task. N concurrent requests → 1 DB query and one
            // round of Graph calls.
            var lazy = InFlight.GetOrAdd(user.CacheKey,
                _ => new Lazy<Task<IReadOnlySet<string>>>(() => ResolveAndCacheAsync(user)));

            try
            {
                return await lazy.Value;
            }
            finally
            {
                // Removed on completion so already-resolved tasks do not pile up; a failure does not stick
                // either — the next request creates a new resolution. Only THIS resolution: a newer one that
                // started meanwhile is left alone.
                InFlight.TryRemove(new KeyValuePair<string, Lazy<Task<IReadOnlySet<string>>>>(user.CacheKey, lazy));
            }
        }

        /// <remarks>
        /// Resolved WITHOUT the request's CancellationToken on purpose: the task is shared by
        /// several requests, and one being cancelled (closing the tab) must not bring down the others'.
        /// These are short queries.
        ///
        /// If the store throws, nothing is cached and the handler turns it into a denial. Caching the failure as
        /// "no permissions" would leave the user locked out for the whole TTL even if the DB recovers a second later.
        /// The failure travels as an <see cref="AccessUnavailableException"/>: its message is fixed, the original —
        /// which can name the database server or its login — stays inside, for the log.
        /// </remarks>
        private async Task<IReadOnlySet<string>> ResolveAndCacheAsync(UserIdentity user)
        {
            IReadOnlySet<string> permissions;
            DateTimeOffset? notAfter;
            // Taken before anything is read: an invalidation during the resolution means the answer is not cached.
            var generation = _cache.GenerationOf(user);
            try
            {
                // Read BEFORE resolving: the inner store resolves from this map or from one loaded after it, never
                // an older one — so ending the entry here bounds its staleness by the map's window, not by two.
                notAfter = _roles is null ? null : await _roles.GetValidUntilAsync(CancellationToken.None);
                permissions = await _inner.GetPermissionsAsync(user, CancellationToken.None);
            }
            catch (Exception ex) when (AccessUnavailableException.Wrap(ex) is { } wrapped)
            {
                throw wrapped;
            }

            _cache.Set(user, permissions, notAfter, generation);
            return permissions;
        }
    }
}
