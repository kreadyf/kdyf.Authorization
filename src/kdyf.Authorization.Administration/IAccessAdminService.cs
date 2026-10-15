using kdyf.Authorization.Administration.Models;
using kdyf.Authorization.Administration.Validation;

namespace kdyf.Authorization.Administration
{
    /// <summary>
    /// Administration of who may use the application, which roles exist and what each role allows.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Access has two halves, in two places. Being in the access group — an Entra security group — lets a
    /// person in, with the base access; it is changed through Graph. The roles, what each grants and who holds
    /// which are the application's own, in its database (<c>auth.Role</c>, <c>auth.RolePermission</c>,
    /// <c>auth.UserRole</c>). People themselves are not stored: they live in Entra.
    /// </para>
    /// <para>The rules every change passes:</para>
    /// <list type="number">
    /// <item>The caller is a person signed in interactively, and not simulating anybody: the audit log must name
    /// the real administrator by their Entra id.</item>
    /// <item>Four eyes: nobody changes their own access, nor what a role they hold grants.</item>
    /// <item>Nobody grants, removes or configures more than they hold.</item>
    /// <item>No change leaves the application without an enabled administrator in the group.</item>
    /// </list>
    /// <para>
    /// After a change: an audit entry with the delta, the cached permissions invalidated (at once on this
    /// instance), and — for a person — an <c>IAccessChangeNotifier</c> event.
    /// </para>
    /// </remarks>
    public interface IAccessAdminService
    {
        /// <summary>Everybody in the access group, plus anybody outside it who still holds roles (flagged).</summary>
        Task<ValidationResult<List<AccessUserResponse>>> ListUsersAsync(AdminActor actor, CancellationToken ct);

        /// <summary>One person, with or without access. Error when neither Entra nor the roles know them.</summary>
        Task<ValidationResult<AccessUserResponse>> GetUserAsync(string objectId, AdminActor actor, CancellationToken ct);

        /// <summary>
        /// Replaces the person's roles with <paramref name="request"/>, adding them to the access group first if
        /// they are not in it. An empty list leaves them with the base access only.
        /// </summary>
        Task<ValidationResult<AccessUserResponse>> SetRolesAsync(string objectId, SetRolesRequest request, AdminActor actor, CancellationToken ct);

        /// <summary>
        /// Takes the person out of the application: their roles, then their membership of the access group.
        /// Their Entra account is untouched.
        /// </summary>
        Task<ValidationResult<bool>> RevokeAsync(string objectId, AdminActor actor, CancellationToken ct);

        /// <summary>
        /// Suspends the person: they hold nothing from their next request on (sessions, tokens, simulation), with their
        /// roles and their membership left as they are. The rules of removing their roles apply: four eyes, nothing
        /// beyond what the caller holds, and never the last administrator.
        /// </summary>
        Task<ValidationResult<AccessUserResponse>> SuspendAsync(string objectId, AdminActor actor, CancellationToken ct);

        /// <summary>Lifts a suspension: the person holds again what their membership and roles give them.</summary>
        Task<ValidationResult<AccessUserResponse>> ReactivateAsync(string objectId, AdminActor actor, CancellationToken ct);

        /// <summary>
        /// Whether the caller could give these roles to somebody else: they exist and grant nothing beyond what the
        /// caller holds. Changes nothing; for checking a request before acting on it (an invitation with roles).
        /// </summary>
        Task<ValidationResult<bool>> CheckGrantableAsync(IReadOnlyCollection<string> roles, AdminActor actor, CancellationToken ct);

        /// <summary>Every role, with what it grants.</summary>
        Task<ValidationResult<List<RoleResponse>>> ListRolesAsync(AdminActor actor, CancellationToken ct);

        /// <summary>One role. Error when it does not exist.</summary>
        Task<ValidationResult<RoleResponse>> GetRoleAsync(string roleValue, AdminActor actor, CancellationToken ct);

        /// <summary>Creates a role, optionally with what it grants.</summary>
        Task<ValidationResult<RoleResponse>> CreateRoleAsync(CreateRoleRequest request, AdminActor actor, CancellationToken ct);

        /// <summary>
        /// Renames a role or changes its description and, when the request carries permissions, what it grants: in one
        /// transaction, refused as a whole when <see cref="UpdateRoleRequest.Version"/> is stale. Its value stays.
        /// </summary>
        Task<ValidationResult<RoleResponse>> UpdateRoleAsync(string roleValue, UpdateRoleRequest request, AdminActor actor, CancellationToken ct);

        /// <summary>Deletes a role nobody holds, with what it grants.</summary>
        Task<ValidationResult<bool>> DeleteRoleAsync(string roleValue, AdminActor actor, CancellationToken ct);

        /// <summary>Replaces what the role grants. Affects everybody who holds it.</summary>
        Task<ValidationResult<RoleResponse>> SetRolePermissionsAsync(string roleValue, SetRolePermissionsRequest request, AdminActor actor, CancellationToken ct);

        /// <summary>What is left behind or still missing: see <see cref="RoleConsistencyResponse"/>. Read-only.</summary>
        Task<ValidationResult<RoleConsistencyResponse>> CheckRoleConsistencyAsync(AdminActor actor, CancellationToken ct);

        /// <summary>
        /// Removes what is left behind: configured codes the application no longer declares, and the roles of
        /// people no longer in the access group. Nothing removed granted anything. Returns what was removed.
        /// </summary>
        Task<ValidationResult<OrphanCleanupResponse>> DeleteOrphansAsync(AdminActor actor, CancellationToken ct);

        /// <summary>The permissions the application declares: what a role can be configured to grant.</summary>
        Task<ValidationResult<List<PermissionResponse>>> ListPermissionsAsync(CancellationToken ct);
    }
}
