using kdyf.Authorization.Abstractions;
using Microsoft.Extensions.DependencyInjection;

namespace kdyf.Authorization.Roles
{
    /// <summary>
    /// The current <see cref="RolePermissionMap"/>, read from the <see cref="IRolePermissionSource"/> and
    /// kept for <c>CacheDuration</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// One read serves every request: the map is a handful of rows, and reading it per request would put the
    /// database on the path of every authorization. The same TTL as the per-person cache, so a change made
    /// directly in the tables has the same documented propagation time as a change made in the directory. A
    /// change made through the administration service calls <see cref="Invalidate"/> and applies at once — on
    /// the instance that made it.
    /// </para>
    /// <para>
    /// On every other instance the change applies when the map expires: at most <c>CacheDuration</c> after it,
    /// because the window starts when the rows are read. The per-person cache keeps that bound by ending no later
    /// than the map it was resolved from (<see cref="GetValidUntilAsync"/>); otherwise a person resolved just
    /// before the map expires would keep the old grants for a second full window.
    /// </para>
    /// <para>A failure to read is not cached: it throws, and the next request tries again.</para>
    /// </remarks>
    public sealed class RolePermissionMapProvider
    {
        private readonly Func<CancellationToken, Task<IReadOnlyDictionary<string, IReadOnlySet<string>>>> _load;
        private readonly DeclaredPermissions _declared;
        private readonly IReadOnlySet<string> _memberGrants;
        private readonly TimeSpan _duration;
        private readonly TimeProvider _time;
        private readonly SemaphoreSlim _gate = new(1, 1);

        // The map and its end, swapped together: a reader never pairs one map with another's expiry.
        private Snapshot? _current;

        /// <summary>For the container: the source is scoped (it reads the database), so it is resolved per load.</summary>
        public RolePermissionMapProvider(
            IServiceScopeFactory scopes, DeclaredPermissions declared, PermissionAuthorizationOptions options, TimeProvider time)
            : this(async ct =>
            {
                using var scope = scopes.CreateScope();
                return await scope.ServiceProvider.GetRequiredService<IRolePermissionSource>().GetAllAsync(ct);
            }, declared, options.MemberPermissionCodes, options.CacheDuration, time)
        { }

        private RolePermissionMapProvider(
            Func<CancellationToken, Task<IReadOnlyDictionary<string, IReadOnlySet<string>>>> load,
            DeclaredPermissions declared, IReadOnlyCollection<string> memberGrants, TimeSpan duration, TimeProvider time)
        {
            _load = load;
            _declared = declared;
            _memberGrants = memberGrants.Where(declared.Codes.Contains).ToHashSet(StringComparer.Ordinal);
            _duration = duration;
            _time = time;
        }

        /// <summary>The declared codes every member of the access group holds without any role.</summary>
        public IReadOnlySet<string> MemberCodes => _memberGrants;

        /// <summary>Over a source that can be held for the provider's lifetime (tests, in-memory configurations).</summary>
        public static RolePermissionMapProvider ForSource(
            IRolePermissionSource source, DeclaredPermissions declared, TimeSpan duration, IEnumerable<string>? memberGrants = null,
            TimeProvider? time = null) =>
            new(ct => source.GetAllAsync(ct), declared, (memberGrants ?? Array.Empty<string>()).ToList(), duration, time ?? TimeProvider.System);

        public async Task<RolePermissionMap> GetAsync(CancellationToken cancellationToken = default) =>
            (await CurrentAsync(cancellationToken)).Map;

        /// <summary>
        /// Until when the map this instance holds may be used — loading it first if it has expired. Whatever is
        /// resolved from the map afterwards is at most this fresh: a cache of it must not outlive this moment.
        /// </summary>
        public async Task<DateTimeOffset> GetValidUntilAsync(CancellationToken cancellationToken = default) =>
            (await CurrentAsync(cancellationToken)).ExpiresAt;

        private async Task<Snapshot> CurrentAsync(CancellationToken cancellationToken)
        {
            var current = _current;
            if (current is not null && _time.GetUtcNow() < current.ExpiresAt)
                return current;

            await _gate.WaitAsync(cancellationToken);
            try
            {
                current = _current;
                if (current is not null && _time.GetUtcNow() < current.ExpiresAt)
                    return current;

                // The window starts BEFORE the read: a change committed while the rows are being read is then
                // still bounded by one duration.
                var readAt = _time.GetUtcNow();
                var map = new RolePermissionMap(await _load(cancellationToken), _declared.Codes, _memberGrants);
                current = new Snapshot(map, readAt + _duration);
                _current = current;
                return current;
            }
            finally
            {
                _gate.Release();
            }
        }

        /// <summary>Forgets the cached map: the next request reads it again.</summary>
        public void Invalidate() => _current = null;

        private sealed record Snapshot(RolePermissionMap Map, DateTimeOffset ExpiresAt);
    }
}
