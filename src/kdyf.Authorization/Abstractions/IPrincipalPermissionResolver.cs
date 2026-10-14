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
        Task<IReadOnlySet<string>> ResolveAsync(ClaimsPrincipal principal, CancellationToken cancellationToken = default);
    }
}
