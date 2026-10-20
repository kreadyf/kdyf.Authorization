using kdyf.Authorization.Abstractions;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;

namespace kdyf.Authorization.Caching
{
    /// <summary>
    /// In-memory cache of a user's effective permissions.
    /// </summary>
    /// <remarks>
    /// NOT shared across instances. With several replicas, Invalidate only affects the one
    /// serving the call; on the others the permission stays alive until the TTL expires. It is a
    /// known limitation bounded by CacheDuration: replace with a distributed implementation
    /// if that window is unacceptable.
    /// </remarks>
    public sealed class MemoryPermissionCache : IPermissionCache
    {
        private const string KeyPrefix = "kdyf:permissions:";

        private readonly IMemoryCache _cache;
        private readonly PermissionAuthorizationOptions _options;
        private readonly ILogger<MemoryPermissionCache> _logger;
        private readonly TimeProvider _time;

        // Token shared by all entries: allows dropping the whole cache at once,
        // which is what's needed when the permissions of a shared role change.
        private CancellationTokenSource _resetSource = new();

        // Generations: every invalidation moves them on. A resolution that started before one does not cache its answer
        // (it may have read what the invalidation was about), so a suspension or a role change cannot be put back by a
        // lookup that was already running.
        private long _allGeneration;
        private readonly System.Collections.Concurrent.ConcurrentDictionary<string, long> _generations = new(StringComparer.Ordinal);

        /// <summary>
        /// For the container: a singleton over the application's <see cref="IMemoryCache"/>. Entry expiry is checked
        /// against the given <see cref="TimeProvider"/>.
        /// </summary>
        public MemoryPermissionCache(
            IMemoryCache cache,
            PermissionAuthorizationOptions options,
            ILogger<MemoryPermissionCache> logger,
            TimeProvider time)
        {
            _cache = cache;
            _options = options;
            _logger = logger;
            _time = time;
        }

        /// <summary>
        /// The resolutions running right now, per user — shared by every request, because this cache is a
        /// singleton and <see cref="CachingPermissionStore"/> is created per request. Kept per store instance,
        /// concurrent misses would never meet: each request would resolve on its own.
        /// </summary>
        internal System.Collections.Concurrent.ConcurrentDictionary<string, Lazy<Task<IReadOnlySet<string>>>> InFlight { get; } = new();

        internal bool TryGet(UserIdentity user, out IReadOnlySet<string> permissions)
        {
            // The expiry is checked against the injected clock, not only left to the memory cache's own: the
            // entry's end is what bounds a stale grant, and it is what the tests move.
            if (_cache.TryGetValue(KeyOf(user), out Entry? entry) && entry is not null && _time.GetUtcNow() < entry.ExpiresAt)
            {
                permissions = entry.Permissions;
                return true;
            }

            permissions = null!;
            return false;
        }

        /// <param name="user">Whose permissions.</param>
        /// <param name="permissions">What they were resolved to.</param>
        /// <param name="notAfter">
        /// The latest moment the entry may be served: the end of the role map it was resolved from. Without it the
        /// entry's own window would start again from now and stack on the map's, doubling how long another
        /// instance keeps serving a changed role.
        /// </param>
        /// <param name="generation">
        /// What <see cref="GenerationOf"/> said when the resolution started. When an invalidation came since, nothing is
        /// cached: the answer may predate it.
        /// </param>
        internal void Set(UserIdentity user, IReadOnlySet<string> permissions, DateTimeOffset? notAfter = null, (long All, long One)? generation = null)
        {
            if (generation is { } started && started != GenerationOf(user))
            {
                _logger.LogDebug("Permissions of {Subject} not cached: they were invalidated while being resolved.", user.CacheKey);
                return;
            }

            // An empty result (user with no permissions or not yet onboarded) is cached for a much
            // shorter time: otherwise onboarding a new user would take the whole TTL to take effect
            // and would look like it didn't work. Caching something, even briefly, keeps a valid
            // token with no permissions from hitting the DB on every request.
            var duration = permissions.Count == 0
                ? _options.EmptyResultCacheDuration
                : _options.CacheDuration;

            var now = _time.GetUtcNow();
            if (notAfter is { } end && end - now < duration)
                duration = end - now;

            if (duration <= TimeSpan.Zero)
                return;

            var entryOptions = new MemoryCacheEntryOptions()
                .SetAbsoluteExpiration(duration)
                .SetSize(EstimateSize(permissions))
                .AddExpirationToken(new CancellationChangeToken(Volatile.Read(ref _resetSource).Token));

            _cache.Set(KeyOf(user), new Entry(permissions, now + duration), entryOptions);

            // An invalidation between the check above and the write would find nothing to remove and leave this entry:
            // checked again now that it is there. Invalidations bump the generation before removing, so one is never missed.
            if (generation is { } before && before != GenerationOf(user))
                _cache.Remove(KeyOf(user));
        }

        /// <inheritdoc />
        /// <remarks>On this instance only.</remarks>
        public void Invalidate(UserIdentity user)
        {
            _generations.AddOrUpdate(user.CacheKey, 1, (_, current) => current + 1);
            // A request arriving now starts its own resolution instead of joining one that may have read the old state.
            InFlight.TryRemove(user.CacheKey, out _);
            _cache.Remove(KeyOf(user));
            _logger.LogInformation("Cached permissions invalidated for {Subject}.", user.CacheKey);
        }

        /// <inheritdoc />
        /// <remarks>On this instance only.</remarks>
        public void InvalidateAll()
        {
            Interlocked.Increment(ref _allGeneration);
            InFlight.Clear();
            // Cancelled, not disposed: an entry being added right now may still read its token, and a disposed source
            // would throw there — on a request whose permissions were already resolved.
            var previous = Interlocked.Exchange(ref _resetSource, new CancellationTokenSource());
            previous.Cancel();
            _logger.LogInformation("Permission cache fully invalidated.");
        }

        /// <summary>Where the invalidations of <paramref name="user"/> (and of everybody) stand now.</summary>
        internal (long All, long One) GenerationOf(UserIdentity user) =>
            (Interlocked.Read(ref _allGeneration), _generations.TryGetValue(user.CacheKey, out var one) ? one : 0);

        private static string KeyOf(UserIdentity user) => KeyPrefix + user.CacheKey;

        /// <summary>A person's permissions and the moment they stop being served.</summary>
        private sealed record Entry(IReadOnlySet<string> Permissions, DateTimeOffset ExpiresAt);

        /// <summary>
        /// Approximate footprint of the entry, in bytes.
        /// </summary>
        /// <remarks>
        /// The cache is the host's, so it plays by the host's rules: when the host configures a
        /// <c>SizeLimit</c>, EVERY entry has to declare a size or <c>Set</c> throws
        /// <see cref="InvalidOperationException"/> — and it throws while RESOLVING permissions, so a
        /// missing size does not degrade performance, it denies access.
        ///
        /// Estimated in bytes (two per character plus per-string overhead) because that is the unit of
        /// a limit expressed as memory. Against a limit meant as "number of entries" the value is only
        /// conservative, never wrong: it fills the budget sooner and evicts earlier, which for a cache
        /// backed by the database costs a query, not correctness.
        /// </remarks>
        private static long EstimateSize(IReadOnlySet<string> permissions)
        {
            long size = 64;   // key + entry overhead
            foreach (var code in permissions)
                size += 24 + (code.Length * 2);
            return size;
        }
    }
}
