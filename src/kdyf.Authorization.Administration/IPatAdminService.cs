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
        Task<ValidationResult<CreatePatResponse>> CreateAsync(CreatePatRequest request, AdminActor actor, CancellationToken ct);
        Task<ValidationResult<List<PatResponse>>> ListAsync(AdminActor actor, CancellationToken ct);
        Task<ValidationResult<bool>> SetActiveAsync(int patId, bool active, AdminActor actor, CancellationToken ct);
        Task<ValidationResult<bool>> DeleteAsync(int patId, AdminActor actor, CancellationToken ct);
    }
}
