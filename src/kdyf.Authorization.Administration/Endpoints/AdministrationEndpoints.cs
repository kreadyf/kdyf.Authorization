using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using kdyf.Authorization.Administration;
using kdyf.Authorization.Administration.Endpoints.Contracts;
using kdyf.Authorization.Administration.Validation;
using kdyf.Authorization.AspNetCore.Endpoints;
using kdyf.Authorization.Simulation;

// ASP.NET namespace on purpose: the host finds it with the usings it already has.
namespace Microsoft.AspNetCore.Builder
{
    /// <summary>Maps the endpoints of the administration of access.</summary>
    public static class KdyfAuthorizationAdministrationEndpoints
    {
        /// <summary>
        /// The administration of access under <paramref name="prefix"/>: people, roles, the permission catalog, the
        /// directory, the audit log and personal access tokens.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Every endpoint demands its door — <see cref="AccessPolicyNames.Administration"/>, or
        /// <see cref="AccessPolicyNames.PersonalAccessTokens"/> for the tokens — with the requirements the host gave
        /// <c>AddKdyfAuthorizationAdministration</c>. The host may add conventions to the returned group (tags, rate
        /// limiting); it cannot take a door away.
        /// </para>
        /// <para>
        /// The rules live in the services, not here: nobody changes their own access, nobody grants or removes more
        /// than they hold, no change leaves the application without an administrator, changes need an interactive
        /// sign-in that is not simulating. The actor they are decided on comes from <see cref="IAdminActorAccessor"/>.
        /// </para>
        /// <para>
        /// Answers, through <see cref="IKdyfAuthorizationResultWriter"/>: 200 with the data; 422 when a rule refuses;
        /// 404 on a read by id that finds nothing; 204 on deletions and activations; and a fixed message when the
        /// database or the directory fails. People are addressed by their object id, never by e-mail.
        /// </para>
        /// </remarks>
        public static RouteGroupBuilder MapKdyfAuthorizationAdministration(this IEndpointRouteBuilder routes, string prefix = "/auth")
        {
            ArgumentNullException.ThrowIfNull(routes);

            var group = routes.MapGroup(prefix).AddEndpointFilter<HideFailuresFilter>();
            const string Administration = AccessPolicyNames.Administration;
            const string Tokens = AccessPolicyNames.PersonalAccessTokens;

            // ── People and their access ──────────────────────────────────────

            // Everybody with access, plus anybody without it who still holds roles (flagged).
            group.MapGet("users", async (HttpContext http, [FromServices] IAdminActorAccessor actors, [FromServices] IAccessAdminService access, CancellationToken ct) =>
                    Accept(http, await access.ListUsersAsync(await actors.GetAsync(ct), ct), users => users.Select(AdministrationMapper.ToDto).ToList()))
                .RequireAuthorization(Administration);

            // Anybody in the directory, with or without access.
            group.MapGet("users/{objectId:guid}", async (Guid objectId, HttpContext http, [FromServices] IAdminActorAccessor actors, [FromServices] IAccessAdminService access, CancellationToken ct) =>
                    Found(http, await access.GetUserAsync(objectId.ToString(), await actors.GetAsync(ct), ct), "The user", AdministrationMapper.ToDto))
                .RequireAuthorization(Administration);

            // The COMPLETE set of roles: it replaces the current ones. Giving access to somebody new is this same call.
            group.MapPut("users/{objectId:guid}/roles", async (Guid objectId, SetRolesRequestDto request, HttpContext http, [FromServices] IAdminActorAccessor actors, [FromServices] IAccessAdminService access, CancellationToken ct) =>
                    Accept(http, await access.SetRolesAsync(objectId.ToString(), AdministrationMapper.ToRequest(request), await actors.GetAsync(ct), ct), AdministrationMapper.ToDto))
                .RequireAuthorization(Administration);

            // Takes the person out of the application: their roles, then their access. Their account stays.
            group.MapDelete("users/{objectId:guid}", async (Guid objectId, HttpContext http, [FromServices] IAdminActorAccessor actors, [FromServices] IAccessAdminService access, CancellationToken ct) =>
                    Done(http, await access.RevokeAsync(objectId.ToString(), await actors.GetAsync(ct), ct)))
                .RequireAuthorization(Administration);

            // Suspends the person: nothing from their next request on, roles and membership kept. And lifts it.
            group.MapPost("users/{objectId:guid}/suspension", async (Guid objectId, HttpContext http, [FromServices] IAdminActorAccessor actors, [FromServices] IAccessAdminService access, CancellationToken ct) =>
                    Accept(http, await access.SuspendAsync(objectId.ToString(), await actors.GetAsync(ct), ct), AdministrationMapper.ToDto))
                .RequireAuthorization(Administration);

            group.MapDelete("users/{objectId:guid}/suspension", async (Guid objectId, HttpContext http, [FromServices] IAdminActorAccessor actors, [FromServices] IAccessAdminService access, CancellationToken ct) =>
                    Accept(http, await access.ReactivateAsync(objectId.ToString(), await actors.GetAsync(ct), ct), AdministrationMapper.ToDto))
                .RequireAuthorization(Administration);

            // ── Roles and catalog ────────────────────────────────────────────

            group.MapGet("roles", async (HttpContext http, [FromServices] IAdminActorAccessor actors, [FromServices] IAccessAdminService access, CancellationToken ct) =>
                    Accept(http, await access.ListRolesAsync(await actors.GetAsync(ct), ct), roles => roles.Select(AdministrationMapper.ToDto).ToList()))
                .RequireAuthorization(Administration);

            group.MapPost("roles", async (CreateRoleRequestDto request, HttpContext http, [FromServices] IAdminActorAccessor actors, [FromServices] IAccessAdminService access, CancellationToken ct) =>
                    Accept(http, await access.CreateRoleAsync(AdministrationMapper.ToRequest(request), await actors.GetAsync(ct), ct), AdministrationMapper.ToDto))
                .RequireAuthorization(Administration);

            // What is left behind. A literal segment: it wins over roles/{roleValue}.
            group.MapGet("roles/orphans", async (HttpContext http, [FromServices] IAdminActorAccessor actors, [FromServices] IAccessAdminService access, CancellationToken ct) =>
                    Accept(http, await access.CheckRoleConsistencyAsync(await actors.GetAsync(ct), ct), AdministrationMapper.ToDto))
                .RequireAuthorization(Administration);

            group.MapDelete("roles/orphans", async (HttpContext http, [FromServices] IAdminActorAccessor actors, [FromServices] IAccessAdminService access, CancellationToken ct) =>
                    Accept(http, await access.DeleteOrphansAsync(await actors.GetAsync(ct), ct), AdministrationMapper.ToDto))
                .RequireAuthorization(Administration);

            group.MapGet("roles/{roleValue}", async (string roleValue, HttpContext http, [FromServices] IAdminActorAccessor actors, [FromServices] IAccessAdminService access, CancellationToken ct) =>
                    Found(http, await access.GetRoleAsync(roleValue, await actors.GetAsync(ct), ct), "The role", AdministrationMapper.ToDto))
                .RequireAuthorization(Administration);

            // Name and description, and optionally what it grants, in one transaction. The value never changes.
            group.MapPut("roles/{roleValue}", async (string roleValue, UpdateRoleRequestDto request, HttpContext http, [FromServices] IAdminActorAccessor actors, [FromServices] IAccessAdminService access, CancellationToken ct) =>
                    Accept(http, await access.UpdateRoleAsync(roleValue, AdministrationMapper.ToRequest(request), await actors.GetAsync(ct), ct), AdministrationMapper.ToDto))
                .RequireAuthorization(Administration);

            // Only a role nobody holds.
            group.MapDelete("roles/{roleValue}", async (string roleValue, HttpContext http, [FromServices] IAdminActorAccessor actors, [FromServices] IAccessAdminService access, CancellationToken ct) =>
                    Done(http, await access.DeleteRoleAsync(roleValue, await actors.GetAsync(ct), ct)))
                .RequireAuthorization(Administration);

            // The COMPLETE set of permissions, for everybody holding the role; the version refuses a stale overwrite.
            group.MapPut("roles/{roleValue}/permissions", async (string roleValue, SetRolePermissionsRequestDto request, HttpContext http, [FromServices] IAdminActorAccessor actors, [FromServices] IAccessAdminService access, CancellationToken ct) =>
                    Accept(http, await access.SetRolePermissionsAsync(roleValue, AdministrationMapper.ToRequest(request), await actors.GetAsync(ct), ct), AdministrationMapper.ToDto))
                .RequireAuthorization(Administration);

            // Read-only: permissions are declared in code, because the doors that demand them are code.
            group.MapGet("permissions", async (HttpContext http, [FromServices] IAccessAdminService access, CancellationToken ct) =>
                    Accept(http, await access.ListPermissionsAsync(ct), permissions => permissions.Select(AdministrationMapper.ToDto).ToList()))
                .RequireAuthorization(Administration);

            // ── Directory ────────────────────────────────────────────────────

            // Who to give access to: people in the tenant, with whether they have access and their roles.
            group.MapGet("directory/users", async (string? search, HttpContext http, [FromServices] IDirectoryAdminService directory, CancellationToken ct) =>
                    Accept(http, await directory.SearchAsync(search, ct), people => people.Select(AdministrationMapper.ToDto).ToList()))
                .RequireAuthorization(Administration);

            // Gives a person access by e-mail — invited as a guest first when they are not in the tenant.
            group.MapPost("directory/invitations", async (InviteRequestDto request, HttpContext http, [FromServices] IAdminActorAccessor actors, [FromServices] IDirectoryAdminService directory, CancellationToken ct) =>
                    Accept(http, await directory.InviteAsync(AdministrationMapper.ToRequest(request), await actors.GetAsync(ct), ct), AdministrationMapper.ToDto))
                .RequireAuthorization(Administration);

            // ── Audit log ────────────────────────────────────────────────────

            // Paginated; POST because the filter goes in the body. Marked as a read: it answers during a simulation.
            group.MapPost("audit/{skip:int}/{take:int}", async (int skip, int take, [FromBody] AuditFilterDto? filter, HttpContext http, [FromServices] IAuditAdminService audit, CancellationToken ct) =>
                    Accept(http, await audit.ListAsync(AdministrationMapper.ToFilter(filter), skip, take, ct), AdministrationMapper.ToDto))
                .WithMetadata(new ReadOnlyOperationAttribute())
                .RequireAuthorization(Administration);

            // ── Personal access tokens ───────────────────────────────────────

            // One's own, or everyone's for an administrator. Never the secret: only its prefix.
            group.MapGet("pat", async (HttpContext http, [FromServices] IAdminActorAccessor actors, [FromServices] IPatAdminService tokens, CancellationToken ct) =>
                    Accept(http, await tokens.ListAsync(await actors.GetAsync(ct), ct), list => list.Select(AdministrationMapper.ToDto).ToList()))
                .RequireAuthorization(Tokens);

            // The response carries the token IN PLAINTEXT, and it is the only time.
            group.MapPost("pat", async (CreateTokenRequestDto request, HttpContext http, [FromServices] IAdminActorAccessor actors, [FromServices] IPatAdminService tokens, CancellationToken ct) =>
                    Accept(http, await tokens.CreateAsync(AdministrationMapper.ToRequest(request), await actors.GetAsync(ct), ct), AdministrationMapper.ToDto))
                .RequireAuthorization(Tokens);

            // Deactivate instead of deleting: use is cut off without losing the trail.
            group.MapPost("pat/{id:int}/deactivate", async (int id, HttpContext http, [FromServices] IAdminActorAccessor actors, [FromServices] IPatAdminService tokens, CancellationToken ct) =>
                    Done(http, await tokens.SetActiveAsync(id, false, await actors.GetAsync(ct), ct)))
                .RequireAuthorization(Tokens);

            group.MapPost("pat/{id:int}/activate", async (int id, HttpContext http, [FromServices] IAdminActorAccessor actors, [FromServices] IPatAdminService tokens, CancellationToken ct) =>
                    Done(http, await tokens.SetActiveAsync(id, true, await actors.GetAsync(ct), ct)))
                .RequireAuthorization(Tokens);

            group.MapDelete("pat/{id:int}", async (int id, HttpContext http, [FromServices] IAdminActorAccessor actors, [FromServices] IPatAdminService tokens, CancellationToken ct) =>
                    Done(http, await tokens.DeleteAsync(id, await actors.GetAsync(ct), ct)))
                .RequireAuthorization(Tokens);

            return group;
        }

        // ── How a service's answer becomes a response ────────────────────────────

        /// <summary>The data, or 422 with the service's validation.</summary>
        private static IResult Accept<T, TDto>(HttpContext http, ValidationResult<T> result, Func<T, TDto> map)
        {
            var writer = ResultWriter.For(http);
            return result.Validation.IsValid ? writer.Ok(http, map(result.Data)) : writer.Rejected(http, Rejection(result));
        }

        /// <summary>204, or 422 with the service's validation.</summary>
        private static IResult Done(HttpContext http, ValidationResult<bool> result)
        {
            var writer = ResultWriter.For(http);
            return result.Validation.IsValid ? writer.NoContent(http) : writer.Rejected(http, Rejection(result));
        }

        /// <summary>The data, or 404: for reads by id, where a refusal means "nothing the caller may see".</summary>
        private static IResult Found<T, TDto>(HttpContext http, ValidationResult<T> result, string what, Func<T, TDto> map)
        {
            var writer = ResultWriter.For(http);
            return result.Validation.IsValid ? writer.Ok(http, map(result.Data)) : writer.NotFound(http, $"{what} was not found.");
        }

        private static AuthorizationRejection Rejection(ValidationResult result) => new(
            result.Validation.Errors.ToList(),
            result.Validation.Fields.ToDictionary(f => f.Key, f => (IReadOnlyList<string>)f.Value.Errors.ToList()));
    }
}
