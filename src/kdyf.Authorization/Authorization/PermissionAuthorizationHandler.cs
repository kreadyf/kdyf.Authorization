using kdyf.Authorization.Abstractions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Logging;

namespace kdyf.Authorization.Authorization
{
    /// <summary>
    /// Decides whether the user has the required permission.
    /// </summary>
    /// <remarks>
    /// Fail-closed: a grant only happens by explicitly calling Succeed. Any other path
    /// —anonymous user, unresolvable claims, store that throws— ends without granting, and ASP.NET
    /// translates it into a 403. There is no branch that grants on a failure.
    /// </remarks>
    internal sealed class PermissionAuthorizationHandler : AuthorizationHandler<PermissionRequirement>
    {
        private readonly IPermissionStore _store;
        private readonly IUserIdentityResolver _resolver;
        private readonly PermissionAuthorizationOptions _options;
        private readonly ILogger<PermissionAuthorizationHandler> _logger;

        public PermissionAuthorizationHandler(
            IPermissionStore store,
            IUserIdentityResolver resolver,
            PermissionAuthorizationOptions options,
            ILogger<PermissionAuthorizationHandler> logger)
        {
            _store = store;
            _resolver = resolver;
            _options = options;
            _logger = logger;
        }

        protected override async Task HandleRequirementAsync(
            AuthorizationHandlerContext context,
            PermissionRequirement requirement)
        {
            var principal = context.User;
            var required = requirement.ToString();

            if (principal?.Identity?.IsAuthenticated != true)
            {
                _logger.LogDebug("{Permission} denied: unauthenticated request.", required);
                return;
            }

            var identity = _resolver.Resolve(principal);

            // Path 1: non-person clients (application tokens, PATs). They have no email nor
            // entry in the user store; their role claim is the only thing that identifies them.
            //
            // The shortcut does NOT apply to people unless explicitly requested: if a role claim
            // were enough, anyone holding a directory app role named after a permission would get
            // in without touching the DB, bypassing IsActive and role revocation.
            var isPerson = PrincipalKind.IsPerson(principal, identity);
            var roleClaimsApply = _options.AcceptRoleClaims &&
                                  (!isPerson || _options.AcceptRoleClaimsForUserPrincipals);

            if (roleClaimsApply && requirement.Codes.Any(principal.IsInRole))
            {
                context.Succeed(requirement);
                return;
            }

            // Path 2: people. The identity comes from the token; the permissions, from the store.
            if (identity is null)
            {
                _logger.LogWarning(
                    "{Permission} denied: the token is authenticated but carries none of the configured identity claims ({SubjectClaims} / {EmailClaims}).",
                    required,
                    string.Join(", ", _options.SubjectClaimTypes),
                    string.Join(", ", _options.EmailClaimTypes));
                return;
            }

            IReadOnlySet<string> permissions;
            try
            {
                permissions = await _store.GetPermissionsAsync(identity, CancellationToken.None);
            }
            catch (Exception ex)
            {
                // A store failure does NOT grant. It is logged as a security event because
                // a down store denies everyone and it must be noticed immediately.
                _logger.LogError(ex,
                    "{Permission} denied for {Subject}: failed to query the permission store.",
                    required, identity.CacheKey);
                return;
            }

            // Having any one of the required codes is enough.
            if (requirement.Codes.Any(permissions.Contains))
            {
                context.Succeed(requirement);
                return;
            }

            _logger.LogWarning(
                "{Permission} denied for {Subject}. Effective permissions: {Count}.",
                required, identity.CacheKey, permissions.Count);
        }
    }
}
