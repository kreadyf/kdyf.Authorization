using System.Security.Claims;

namespace kdyf.Authorization.Abstractions
{
    /// <summary>
    /// Returns the effective permissions of the current principal, unifying two sources:
    /// people (permissions from the <see cref="IPermissionStore"/>, by identity) and non-person
    /// clients —PATs, application tokens— (permissions from their role claims). It is the SAME
    /// rule the authorization handler applies, exposed for code that needs the set of
    /// permissions (e.g. building the navigation menu).
    /// </summary>
    public interface IPrincipalPermissionResolver
    {
        /// <summary>
        /// The permission codes <paramref name="principal"/> holds: its role claims when role claims apply to it, plus the
        /// store's permissions when it is a person. Empty for an unauthenticated principal.
        /// </summary>
        /// <remarks>A store failure propagates; it is never turned into an empty set here.</remarks>
        Task<IReadOnlySet<string>> ResolveAsync(ClaimsPrincipal principal, CancellationToken cancellationToken = default);
    }
}
