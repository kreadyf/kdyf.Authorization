using System.Security.Claims;

namespace kdyf.Authorization.Abstractions
{
    /// <summary>
    /// Extracts the user identity from the token claims. Can be replaced when the
    /// issuer does not follow the usual conventions (Azure AD v1/v2, B2C, IdentityServer...).
    /// </summary>
    public interface IUserIdentityResolver
    {
        /// <summary>
        /// Returns the identity, or null if the claims cannot identify anyone
        /// (in which case authorization must deny).
        /// </summary>
        UserIdentity? Resolve(ClaimsPrincipal principal);
    }
}
