using System.Security.Claims;
using kdyf.Authorization.Abstractions;

namespace kdyf.Authorization.Authorization
{
    /// <summary>
    /// Default resolver: walks the configured claims in order and keeps the first
    /// one that has a value.
    /// </summary>
    public sealed class ClaimsUserIdentityResolver : IUserIdentityResolver
    {
        private readonly PermissionAuthorizationOptions _options;

        public ClaimsUserIdentityResolver(PermissionAuthorizationOptions options) => _options = options;

        public UserIdentity? Resolve(ClaimsPrincipal principal)
        {
            var subjectId = FirstClaimValue(principal, _options.SubjectClaimTypes);
            var email = FirstClaimValue(principal, _options.EmailClaimTypes);

            // Email is normalized because the store compares it as text: if the token carries
            // 'Dev@Example.com' and the DB stores 'dev@example.com', without this there would be no match.
            if (email is not null)
                email = email.Trim().ToLowerInvariant();

            var identity = new UserIdentity(subjectId, email);

            // Without subject or email no one is identified: the caller must deny.
            return identity.IsEmpty ? null : identity;
        }

        private static string? FirstClaimValue(ClaimsPrincipal principal, string[] claimTypes)
        {
            foreach (var claimType in claimTypes)
            {
                var value = principal.FindFirst(claimType)?.Value;
                if (!string.IsNullOrWhiteSpace(value))
                    return value;
            }

            return null;
        }
    }
}
