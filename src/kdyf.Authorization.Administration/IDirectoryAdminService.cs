using kdyf.Authorization.Administration.Models;
using kdyf.Authorization.Administration.Validation;

namespace kdyf.Authorization.Administration
{
    /// <summary>
    /// Finding the person to give access to, and bringing a person into the access group.
    /// </summary>
    /// <remarks>
    /// Searching grants nothing. Bringing somebody in (an invitation) puts them in the access group: they can
    /// sign in, with the base access, until a role is given with <see cref="IAccessAdminService.SetRolesAsync"/>
    /// — which also brings somebody found by the search into the group.
    /// </remarks>
    public interface IDirectoryAdminService
    {
        /// <summary>People in the tenant matching <paramref name="search"/>, with whether they are in the group and their roles.</summary>
        Task<ValidationResult<List<DirectoryUserResponse>>> SearchAsync(string? search, CancellationToken ct);

        /// <summary>
        /// Brings the person with this e-mail into the access group, inviting them as a B2B guest first when
        /// nobody with that e-mail is in the directory.
        /// </summary>
        Task<ValidationResult<InviteResponse>> InviteAsync(InviteRequest request, AdminActor actor, CancellationToken ct);
    }
}
