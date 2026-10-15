using kdyf.Authorization.AspNetCore;
using kdyf.Authorization.Authorization;

namespace kdyf.Authorization.Administration.AspNetCore
{
    /// <summary>
    /// The decisions of <c>AddKdyfAuthorizationAdministration</c> that belong to the host's CODE: which policies guard the
    /// administration and the personal access tokens.
    /// </summary>
    public sealed class KdyfAuthorizationAdministrationBuilder
    {
        internal Policy? AdministrationPolicy { get; private set; }
        internal string? AdministrationPermissionCode { get; private set; }
        internal Policy? TokensPolicy { get; private set; }

        /// <summary>
        /// The policy that guards the administration, registered as <c>AccessPolicyNames.Administration</c>.
        /// Its permission is also the code the lockout guard counts, so no change can leave the application
        /// without an administrator.
        /// </summary>
        /// <remarks>
        /// One policy for both jobs, on purpose: they used to be two values that had to match by hand, and
        /// nothing failed when they did not. The policy must demand exactly one permission.
        /// </remarks>
        public KdyfAuthorizationAdministrationBuilder AdministeredBy(Policy policy)
        {
            AdministrationPermissionCode = KdyfAuthorizationBuilder.SinglePermission(policy, "administration");
            AdministrationPolicy = policy;
            return this;
        }

        /// <summary>
        /// The policy that guards the personal access tokens, registered as
        /// <c>AccessPolicyNames.PersonalAccessTokens</c>: every person manages their own. Not the
        /// administration one: a plain user manages theirs.
        /// </summary>
        public KdyfAuthorizationAdministrationBuilder TokensManagedBy(Policy policy)
        {
            ArgumentNullException.ThrowIfNull(policy);
            TokensPolicy = policy;
            return this;
        }

        /// <summary>Refuses an incomplete setup at registration, with the call that is missing.</summary>
        internal void EnsureComplete()
        {
            if (AdministrationPolicy is null)
                throw new InvalidOperationException("AddKdyfAuthorizationAdministration: call .AdministeredBy(policy) — it guards the administration (AccessPolicyNames.Administration) and names the code the lockout guard counts.");
            if (TokensPolicy is null)
                throw new InvalidOperationException("AddKdyfAuthorizationAdministration: call .TokensManagedBy(policy) — it guards the personal access tokens (AccessPolicyNames.PersonalAccessTokens).");
        }
    }
}
