using kdyf.Authorization.Administration.Models;
using kdyf.Authorization.Administration.Validation;

namespace kdyf.Authorization.Administration
{
    /// <summary>
    /// Personal Access Token management. A person manages their own tokens; an administrator (with the
    /// administration permission) sees and manages everyone's, and may create one for an owner who holds
    /// nothing beyond them.
    /// </summary>
    /// <remarks>
    /// Every operation needs an interactive sign-in that is not simulating: a token cannot mint or manage
    /// tokens, and the audit log has to name a person.
    /// </remarks>
    public interface IPatAdminService
    {
        /// <summary>
        /// Creates a token for the caller or, for an administrator, for another owner. The plaintext comes back
        /// only in this response. Refused when the owner holds no access (the token would grant nothing) or,
        /// for another owner, holds permissions the administrator does not.
        /// </summary>
        Task<ValidationResult<CreatePatResponse>> CreateAsync(CreatePatRequest request, AdminActor actor, CancellationToken ct);

        /// <summary>
        /// The caller's tokens, or everyone's for an administrator, newest first, each with what its owner holds
        /// now. A read: allowed while simulating.
        /// </summary>
        Task<ValidationResult<List<PatResponse>>> ListAsync(AdminActor actor, CancellationToken ct);

        /// <summary>
        /// Switches a token on or off. An administrator may switch anybody's off; switching one back on is refused
        /// when its owner holds permissions the administrator does not. Somebody else's token, for a
        /// non-administrator, answers as not found.
        /// </summary>
        Task<ValidationResult<bool>> SetActiveAsync(int patId, bool active, AdminActor actor, CancellationToken ct);

        /// <summary>
        /// Deletes a token. Same visibility as <see cref="SetActiveAsync"/>; for somebody else's token, refused when
        /// its owner holds permissions the administrator does not.
        /// </summary>
        Task<ValidationResult<bool>> DeleteAsync(int patId, AdminActor actor, CancellationToken ct);
    }
}
