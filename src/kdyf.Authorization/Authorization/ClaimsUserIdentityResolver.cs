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

        /// <param name="options">Supplies the claim types to read, in order (<c>SubjectClaimTypes</c>, <c>EmailClaimTypes</c>).</param>
        public ClaimsUserIdentityResolver(PermissionAuthorizationOptions options) => _options = options;

        /// <inheritdoc />
        /// <remarks>The e-mail is trimmed and lower-cased, the way the store compares it.</remarks>
        public UserIdentity? Resolve(ClaimsPrincipal principal)
        {
            var subjectId = FirstClaimValue(principal, _options.SubjectClaimTypes);
            var email = FirstClaimValue(principal, _options.EmailClaimTypes);

            // Email is normalized because the store compares it as text: if the token carries
            // 'Dev@Example.com' and the DB stores 'dev@example.com', without this there would be no match.
            if (email is not null)
                email = email.Trim().ToLowerInvariant();

            // An object id the way the store keys it, so the cache and the roles see one person, whatever case the token carries.
            if (subjectId is not null)
                subjectId = Guid.TryParse(subjectId, out var objectId) ? objectId.ToString() : subjectId.Trim();

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
