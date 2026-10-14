using System.Security.Claims;
using kdyf.Authorization.Abstractions;

namespace kdyf.Authorization.Authorization
{
    /// <summary>
    /// Default implementation of <see cref="IPrincipalPermissionResolver"/>. Mirrors the logic of
    /// <see cref="PermissionAuthorizationHandler"/>: for non-person clients the permissions are
    /// their role claims; for people, those from the store.
    /// </summary>
    public sealed class PrincipalPermissionResolver : IPrincipalPermissionResolver
    {
        private static readonly IReadOnlySet<string> None = new HashSet<string>(StringComparer.Ordinal);

        private readonly IPermissionStore _store;
        private readonly IUserIdentityResolver _identityResolver;
        private readonly PermissionAuthorizationOptions _options;

        public PrincipalPermissionResolver(
            IPermissionStore store,
            IUserIdentityResolver identityResolver,
            PermissionAuthorizationOptions options)
        {
            _store = store;
            _identityResolver = identityResolver;
            _options = options;
        }

        public async Task<IReadOnlySet<string>> ResolveAsync(
            ClaimsPrincipal principal, CancellationToken cancellationToken = default)
        {
            if (principal?.Identity?.IsAuthenticated != true)
                return None;

            var identity = _identityResolver.Resolve(principal);
            var isPerson = !string.IsNullOrWhiteSpace(identity?.Email);

            var codes = new HashSet<string>(StringComparer.Ordinal);

            // Path 1: non-person clients (PAT / application token). Their permissions are their
            // role claims — same rule the PermissionAuthorizationHandler grants by.
            var roleClaimsApply = _options.AcceptRoleClaims &&
                                  (!isPerson || _options.AcceptRoleClaimsForUserPrincipals);
            if (roleClaimsApply)
            {
                foreach (var id in principal.Identities)
                    foreach (var role in id.FindAll(id.RoleClaimType))
                        codes.Add(role.Value);
            }

            // Path 2: people. Permissions from the store (DB), by identity.
            if (isPerson && identity is not null)
                codes.UnionWith(await _store.GetPermissionsAsync(identity, cancellationToken));

            return codes;
        }
    }
}
