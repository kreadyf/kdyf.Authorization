using kdyf.Authorization.Abstractions;
using Microsoft.Extensions.Logging;

namespace kdyf.Authorization.Roles
{
    /// <summary>
    /// <see cref="IPermissionStore"/> of the access model: a person's permissions are what every member of the
    /// access group holds, plus what their roles grant — and nothing at all outside the group.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The group is read on the server, not from the token.</b> A token can carry group ids, but it lives for
    /// an hour or more: somebody removed from the group, or whose account was disabled, would keep their
    /// access until it expires. Resolving here, with a short cache in front (<c>CacheDuration</c>), bounds that
    /// window to minutes. The same goes for the token's <c>roles</c> claim, which is never used for people.
    /// </para>
    /// <para>
    /// <b>Keyed by the subject id only.</b> A person without an 'oid' in the token is not resolved by e-mail:
    /// that fallback is exactly what let a guest's <c>#EXT#</c> sign-in name, or a recycled address, land on
    /// somebody else's access.
    /// </para>
    /// <para>
    /// <b>Nobody is created on sign-in.</b> Being in the group is what lets a person in; a row appears only when
    /// an administrator gives them a role. Deleting a person therefore takes them out of the group as well —
    /// otherwise their next sign-in would find them still a member.
    /// </para>
    /// <para>
    /// <b>Suspension.</b> With an <see cref="IUserSuspensionSource"/>, a person the application suspended holds
    /// nothing, whatever the directory and their roles say. Checked here, under the cache: suspending somebody and
    /// invalidating their entry takes effect at their next request, for their tokens too (a token resolves its owner
    /// through this store).
    /// </para>
    /// <para>A directory or database failure propagates (the handler denies, nothing is cached). Fail-closed.</para>
    /// </remarks>
    public sealed class MembershipPermissionStore : IPermissionStore
    {
        private static readonly IReadOnlySet<string> None = new HashSet<string>(StringComparer.Ordinal);

        private readonly IMembershipSource _membership;
        private readonly IUserRoleSource _userRoles;
        private readonly RolePermissionMapProvider _roles;
        private readonly ILogger<MembershipPermissionStore> _logger;
        private readonly IUserSuspensionSource? _suspensions;
        private readonly IUserActivityRecorder? _activity;

        /// <param name="membership">The access group.</param>
        /// <param name="userRoles">Who holds which role.</param>
        /// <param name="roles">What each role grants.</param>
        /// <param name="logger">The log.</param>
        /// <param name="suspensions">Who the application suspended. Optional: without it nobody is.</param>
        /// <param name="activity">Where the last access is recorded. Optional.</param>
        public MembershipPermissionStore(
            IMembershipSource membership,
            IUserRoleSource userRoles,
            RolePermissionMapProvider roles,
            ILogger<MembershipPermissionStore> logger,
            IUserSuspensionSource? suspensions = null,
            IUserActivityRecorder? activity = null)
        {
            _membership = membership;
            _userRoles = userRoles;
            _roles = roles;
            _logger = logger;
            _suspensions = suspensions;
            _activity = activity;
        }

        public async Task<IReadOnlySet<string>> GetPermissionsAsync(UserIdentity user, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(user.SubjectId))
            {
                _logger.LogWarning("No permissions for {Email}: the token carries no subject id ('oid').", user.Email);
                return None;
            }

            // The database answers before Graph: a suspended person costs no directory call.
            if (_suspensions is not null && await _suspensions.IsSuspendedAsync(user.SubjectId, cancellationToken))
            {
                _logger.LogInformation("No permissions for {Subject}: suspended by the application.", user.SubjectId);
                return None;
            }

            var membership = await _membership.GetMembershipAsync(user.SubjectId, cancellationToken);

            if (membership is null)
                return None;

            if (!membership.AccountEnabled)
            {
                _logger.LogInformation("No permissions for {Subject}: the account is disabled in the directory.", user.SubjectId);
                return None;
            }

            if (!membership.IsMember)
            {
                _logger.LogInformation("No permissions for {Subject}: not a member of the access group.", user.SubjectId);
                return None;
            }

            var held = await _userRoles.GetRolesAsync(user.SubjectId, cancellationToken);
            var permissions = (await _roles.GetAsync(cancellationToken)).ForMember(held);

            await RecordActivityAsync(user);
            return permissions;
        }

        /// <summary>Somebody with access was seen. A failure to write it never denies them.</summary>
        private async Task RecordActivityAsync(UserIdentity user)
        {
            if (_activity is null)
                return;
            try
            {
                await _activity.RecordAsync(user, CancellationToken.None);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "The last access of {Subject} could not be recorded.", user.SubjectId);
            }
        }
    }
}
