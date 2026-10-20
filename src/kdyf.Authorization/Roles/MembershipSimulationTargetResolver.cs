using kdyf.Authorization.Abstractions;
using Microsoft.Extensions.Caching.Memory;

namespace kdyf.Authorization.Roles
{
    /// <summary>
    /// <see cref="ISimulationTargetResolver"/> of the access model: the target is somebody the directory knows by
    /// that e-mail, with an enabled account, in the access group, not suspended by the application, and holding at
    /// least something.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Somebody without access is refused as "no such user" rather than simulated: their session would hold
    /// nothing and show an empty menu, which answers no question an administrator asks.
    /// </para>
    /// <para>
    /// The answer is cached per e-mail, for the same times as permissions (<c>CacheDuration</c>, and
    /// <c>EmptyResultCacheDuration</c> for a refusal): it is asked on EVERY simulated request, and resolving it
    /// costs a directory search and two Graph calls. What the simulated session may open is not cached here:
    /// it is read from the permission store on each request, so revoking the person still takes effect as fast
    /// as for anybody else.
    /// </para>
    /// </remarks>
    public sealed class MembershipSimulationTargetResolver : ISimulationTargetResolver
    {
        private const string KeyPrefix = "kdyf:simulation-target:";

        private readonly IMembershipSource _membership;
        private readonly IUserRoleSource _userRoles;
        private readonly RolePermissionMapProvider _roles;
        private readonly IMemoryCache? _cache;
        private readonly PermissionAuthorizationOptions? _options;
        private readonly IUserSuspensionSource? _suspensions;

        /// <param name="membership">The directory.</param>
        /// <param name="userRoles">Who holds which role.</param>
        /// <param name="roles">What each role grants.</param>
        /// <param name="cache">Where answers are kept; without it every call resolves again.</param>
        /// <param name="options">The cache durations.</param>
        /// <param name="suspensions">Who the application suspended: nobody simulates them.</param>
        public MembershipSimulationTargetResolver(
            IMembershipSource membership,
            IUserRoleSource userRoles,
            RolePermissionMapProvider roles,
            IMemoryCache? cache = null,
            PermissionAuthorizationOptions? options = null,
            IUserSuspensionSource? suspensions = null)
        {
            _suspensions = suspensions;
            _membership = membership;
            _userRoles = userRoles;
            _roles = roles;
            _cache = cache;
            _options = options;
        }

        /// <inheritdoc />
        /// <exception cref="AccessUnavailableException">The directory or the database failed.</exception>
        public async Task<SimulationTarget?> ResolveAsync(string email, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(email))
                return null;

            var normalized = email.Trim().ToLowerInvariant();
            var key = KeyPrefix + normalized;

            if (_cache is not null && _cache.TryGetValue(key, out Answer? cached))
                return cached!.Target;

            SimulationTarget? target;
            try
            {
                target = await ResolveNowAsync(normalized, cancellationToken);
            }
            catch (Exception ex) when (AccessUnavailableException.Wrap(ex) is { } wrapped)
            {
                // The directory or the database failed: a fixed message out, the original inside for the log.
                throw wrapped;
            }

            if (_cache is not null && _options is not null)
            {
                var duration = target is null ? _options.EmptyResultCacheDuration : _options.CacheDuration;
                if (duration > TimeSpan.Zero)
                    _cache.Set(key, new Answer(target), new MemoryCacheEntryOptions()
                        .SetAbsoluteExpiration(duration)
                        .SetSize(1));
            }

            return target;
        }

        private async Task<SimulationTarget?> ResolveNowAsync(string email, CancellationToken cancellationToken)
        {
            var person = await _membership.FindByEmailAsync(email, cancellationToken);
            if (person is null)
                return null;

            var membership = await _membership.GetMembershipAsync(person.SubjectId, cancellationToken);
            if (membership is not { HasAccess: true })
                return null;

            if (_suspensions is not null && await _suspensions.IsSuspendedAsync(person.SubjectId, cancellationToken))
                return null;

            var held = await _userRoles.GetRolesAsync(person.SubjectId, cancellationToken);
            if ((await _roles.GetAsync(cancellationToken)).ForMember(held).Count == 0)
                return null;

            return new SimulationTarget(person.Email, person.SubjectId, person.DisplayName);
        }

        /// <summary>
        /// Forgets the cached answer for <paramref name="email"/>: after suspending or reactivating somebody, so the
        /// next simulation of them is decided again.
        /// </summary>
        public static void Forget(IMemoryCache cache, string? email)
        {
            ArgumentNullException.ThrowIfNull(cache);
            if (!string.IsNullOrWhiteSpace(email))
                cache.Remove(KeyPrefix + email.Trim().ToLowerInvariant());
        }

        /// <summary>A cached answer — a refusal included, which is why it is wrapped.</summary>
        private sealed record Answer(SimulationTarget? Target);
    }
}
