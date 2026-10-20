using System.Security.Claims;
using kdyf.Authorization.Abstractions;

namespace kdyf.Authorization.Authorization
{
    /// <summary>Whether a request comes from a person or from a client that is not one (an application token, a PAT).</summary>
    /// <remarks>
    /// <para>
    /// It decides which door a request goes through: a person's permissions come from the store (the gate, the suspension,
    /// their roles); a non-person's from its role claims. Getting a person wrong is the dangerous side: their token's
    /// <c>roles</c> would authorize them with no gate, no suspension and no revocation.
    /// </para>
    /// <para>
    /// So a person is not only "a token with an e-mail": it is also a token issued FOR a user — delegated scopes
    /// (<c>scp</c>, or its mapped name) or <c>idtyp = user</c>. A v1 token whose <c>upn</c> was mapped to another claim name,
    /// or a user without a mail, is still a person. An application token (client credentials) has no scopes and no e-mail;
    /// a personal access token has neither.
    /// </para>
    /// </remarks>
    internal static class PrincipalKind
    {
        private static readonly string[] ScopeClaimTypes = { "scp", "http://schemas.microsoft.com/identity/claims/scope" };

        public static bool IsPerson(ClaimsPrincipal principal, UserIdentity? identity)
        {
            if (identity is null)
                return false;
            if (!string.IsNullOrWhiteSpace(identity.Email))
                return true;

            return !string.IsNullOrWhiteSpace(identity.SubjectId)
                   && (principal.HasClaim(c => ScopeClaimTypes.Contains(c.Type, StringComparer.Ordinal) && !string.IsNullOrWhiteSpace(c.Value))
                       || principal.HasClaim(c => c.Type == "idtyp" && string.Equals(c.Value, "user", StringComparison.OrdinalIgnoreCase)));
        }
    }
}
