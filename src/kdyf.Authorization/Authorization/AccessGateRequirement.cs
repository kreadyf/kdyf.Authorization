using kdyf.Authorization.Abstractions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Logging;

namespace kdyf.Authorization.Authorization
{
    /// <summary>
    /// Passing the access gate, on top of being signed in: what the fallback and default policies demand, so that an
    /// endpoint without a permission of its own is still closed to an account of the tenant that is not let in.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A person passes it when they hold at least one permission — which needs the access gate (the group or the
    /// assignment), an account not suspended, and either a role or what every member holds
    /// (<c>EveryMemberHolds</c>). A member with no role and no base access holds nothing, and does not pass.
    /// </para>
    /// <para>
    /// A client that is not a person (a personal access token, an application token) passes it when it carries at least
    /// one permission as a role claim: a token is only valid while its owner holds something, and an application token
    /// with no role is any application of the tenant.
    /// </para>
    /// </remarks>
    public sealed class AccessGateRequirement : IAuthorizationRequirement
    {
        /// <summary>The requirement; it has no state.</summary>
        public static AccessGateRequirement Instance { get; } = new();

        private AccessGateRequirement() { }
    }

    /// <summary>Decides <see cref="AccessGateRequirement"/>. Fail-closed, as the permission handler.</summary>
    internal sealed class AccessGateAuthorizationHandler : AuthorizationHandler<AccessGateRequirement>
    {
        private readonly IPermissionStore _store;
        private readonly IUserIdentityResolver _resolver;
        private readonly PermissionAuthorizationOptions _options;
        private readonly ILogger<AccessGateAuthorizationHandler> _logger;

        public AccessGateAuthorizationHandler(
            IPermissionStore store, IUserIdentityResolver resolver, PermissionAuthorizationOptions options, ILogger<AccessGateAuthorizationHandler> logger)
        {
            _store = store;
            _resolver = resolver;
            _options = options;
            _logger = logger;
        }

        protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, AccessGateRequirement requirement)
        {
            var principal = context.User;
            if (principal?.Identity?.IsAuthenticated != true)
                return;

            // The same two paths the permission handler grants by, asking for any permission instead of a given one.
            var identity = _resolver.Resolve(principal);
            var roleClaimsApply = _options.AcceptRoleClaims &&
                                  (!PrincipalKind.IsPerson(principal, identity) || _options.AcceptRoleClaimsForUserPrincipals);

            if (roleClaimsApply && principal.Identities.Any(i => i.FindAll(i.RoleClaimType).Any(c => !string.IsNullOrWhiteSpace(c.Value))))
            {
                context.Succeed(requirement);
                return;
            }

            if (identity is null)
            {
                _logger.LogInformation("Access refused: the token carries no permission and no identity to look one up by.");
                return;
            }

            IReadOnlySet<string> permissions;
            try
            {
                permissions = await _store.GetPermissionsAsync(identity, CancellationToken.None);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Access refused for {Subject}: the permission store could not be read.", identity.CacheKey);
                return;
            }

            if (permissions.Count > 0)
                context.Succeed(requirement);
            else
                _logger.LogInformation("Access refused for {Subject}: outside the access gate, suspended, or holding nothing.", identity.CacheKey);
        }
    }
}
