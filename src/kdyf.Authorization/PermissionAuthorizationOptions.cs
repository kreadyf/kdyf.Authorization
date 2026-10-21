using System.Security.Claims;

namespace kdyf.Authorization
{
    /// <summary>
    /// Configuration of the permission-based authorization system. Everything that varies between
    /// consumers lives here; none of it is hardcoded.
    /// </summary>
    public sealed class PermissionAuthorizationOptions
    {
        /// <summary>
        /// Claims from which the user's immutable identifier is extracted, in order.
        /// Azure AD emits 'oid' in both v1 and v2 tokens.
        /// </summary>
        public string[] SubjectClaimTypes { get; set; } =
        {
            "oid",
            "http://schemas.microsoft.com/identity/claims/objectidentifier",
            ClaimTypes.NameIdentifier
        };

        /// <summary>
        /// Claims from which the email is extracted, in order. Varies by issuer:
        /// Azure AD v1 uses 'upn'/'unique_name', v2 uses 'preferred_username', and 'email' only
        /// appears if the user has the 'mail' field populated in the directory. With the JWT handler's default inbound
        /// mapping, 'upn' arrives as <see cref="ClaimTypes.Upn"/>.
        /// </summary>
        /// <remarks>
        /// Whether a request is a person's does not depend on finding an e-mail: a token issued for a user (delegated
        /// scopes, or <c>idtyp = user</c>) is a person's either way, and goes through the store, never its role claims.
        /// </remarks>
        public string[] EmailClaimTypes { get; set; } =
        {
            "email",
            ClaimTypes.Email,
            "preferred_username",
            "upn",
            ClaimTypes.Upn,
            "unique_name"
        };

        /// <summary>
        /// Authentication schemes applied to the generated policies. Must include ALL
        /// schemes a client may arrive with: if one is missing, its tokens are ignored
        /// and the user appears as anonymous (permanent 403).
        /// </summary>
        public string[] AuthenticationSchemes { get; set; } = Array.Empty<string>();

        /// <summary>
        /// If a token carries a role claim that exactly matches the permission code,
        /// it is granted without querying the store. Covers non-person clients:
        /// application tokens (client credentials) and Personal Access Tokens.
        /// </summary>
        public bool AcceptRoleClaims { get; set; } = true;

        /// <summary>
        /// Whether the shortcut above also applies to people (principals with an email).
        /// </summary>
        /// <remarks>
        /// Off by default, and deliberately so: for a person, the store is the single source of
        /// truth. If a role claim were enough, someone assigned an app role in the
        /// directory named after a permission would get in without touching the DB, bypassing
        /// IsActive and role revocation — exactly what this system exists to guarantee.
        /// </remarks>
        public bool AcceptRoleClaimsForUserPrincipals { get; set; } = false;

        /// <summary>
        /// How long a user's effective permissions are cached. It is the maximum time a
        /// revocation can take to take effect if explicit invalidation fails.
        /// </summary>
        public TimeSpan CacheDuration { get; set; } = TimeSpan.FromMinutes(5);

        /// <summary>
        /// How long an EMPTY result is cached (user with no permissions or not onboarded).
        /// </summary>
        /// <remarks>
        /// Much shorter than CacheDuration: if they were cached the same, a just-onboarded user
        /// would keep seeing 403 for the whole TTL and it would look like onboarding failed. Even so,
        /// something is cached so that a valid token with no permissions doesn't hit the DB on every request.
        /// </remarks>
        public TimeSpan EmptyResultCacheDuration { get; set; } = TimeSpan.FromSeconds(30);

        /// <summary>
        /// Separator with which a policy name can enumerate several permissions in OR:
        /// [Authorize(Policy = "Compliance.List|Compliance.Cases")] grants if the user has
        /// either of the two. Used for endpoints shared by several screens.
        /// </summary>
        public char AnyOfSeparator { get; set; } = '|';

        /// <summary>
        /// On startup, checks the policy names of all the project's [Authorize] attributes
        /// against IPermissionCatalog. Requires a registered catalog.
        /// </summary>
        public bool ValidatePoliciesOnStartup { get; set; } = true;

        /// <summary>
        /// Policy names the startup validation must ignore (policies with their own
        /// semantics registered separately, that are not permissions).
        /// </summary>
        public HashSet<string> IgnoredPolicyNames { get; set; } = new(StringComparer.Ordinal);

        /// <summary>
        /// The permission code that means "may administer users, roles and tokens".
        /// </summary>
        /// <remarks>
        /// <para>
        /// The administration package counts the holders of this code before accepting a change, so
        /// that no edit can leave the system with nobody able to manage access. Configurable because
        /// a consumer names that capability whatever fits its scheme.
        /// </para>
        /// <para>
        /// Set it to the SAME code the host's administration policy demands (the one it passes to
        /// <c>AddKdyfAuthorizationAdministration(...).AdministeredBy</c>, which sets this). If the two differ, the service counts holders of a
        /// code that does not open the door, and the lockout guard protects the wrong thing.
        /// </para>
        /// </remarks>
        public string AdministrationPermissionCode { get; set; } = "DataAdministration";

        /// <summary>
        /// The permission codes every member of the access group holds without any role — normally just the
        /// base access, the one that means "may use the application".
        /// </summary>
        /// <remarks>
        /// Exact declared codes only, checked by <c>AddAssignedRoles</c> at registration: a pattern here would
        /// hand everything it covers to everybody in the group.
        /// </remarks>
        public HashSet<string> MemberPermissionCodes { get; set; } = new(StringComparer.Ordinal);

        /// <summary>
        /// Whether <c>AddAssignedRoles</c> adds the wildcard of every area to the declared permissions — <c>fabrikam.*</c>
        /// for an area with at least two permissions — so that nobody has to write its class. See
        /// <see cref="Authorization.AreaWildcards"/>.
        /// </summary>
        /// <remarks>
        /// Off by default: a wildcard grants more than it looks like on a roles screen, so a host decides to have them.
        /// </remarks>
        public bool AreaWildcards { get; set; }

        /// <summary>
        /// The areas that get no wildcard when <see cref="AreaWildcards"/> is on: those holding a permission that must
        /// never come through a wildcard. Each must be an area the host declares permissions in — checked at
        /// registration, because a misspelt one would derive the very wildcard it meant to prevent.
        /// </summary>
        public HashSet<string> AreaWildcardExceptions { get; set; } = new(StringComparer.Ordinal);

        internal void Validate()
        {
            if (SubjectClaimTypes.Length == 0 && EmailClaimTypes.Length == 0)
                throw new InvalidOperationException(
                    "At least one subject or email claim must be configured: without them the user cannot be identified and every request would be denied.");

            if (CacheDuration < TimeSpan.Zero)
                throw new InvalidOperationException("CacheDuration cannot be negative.");

            if (!AreaWildcards && AreaWildcardExceptions.Count > 0)
                throw new InvalidOperationException(
                    "AreaWildcardExceptions are set but AreaWildcards is off: no area gets a wildcard, so there is nothing to except.");
        }
    }
}
