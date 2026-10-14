using System.Net;
using Microsoft.Extensions.Options;

namespace kdyf.Authorization.EntraId
{
    /// <summary>One assignment of the access app role: who holds it, and the assignment's own id (what removing it takes).</summary>
    /// <param name="AssignmentId">The id of the appRoleAssignment object.</param>
    /// <param name="PrincipalId">The object id of the user it is assigned to.</param>
    public sealed record AppRoleAssignment(string AssignmentId, string PrincipalId);

    /// <summary>
    /// The assignments of the <c>Access</c> app role on the application's Enterprise application: who holds it, and giving
    /// or taking it. The application and the role are configuration, never a parameter.
    /// </summary>
    public interface IAccessAssignments
    {
        /// <summary>Whether the user holds the access app role. False for an unknown user or one that is not an object id.</summary>
        Task<bool> IsAssignedAsync(string objectId, CancellationToken ct);

        /// <summary>Every user assigned the access app role.</summary>
        Task<IReadOnlyList<AppRoleAssignment>> ListAsync(CancellationToken ct);

        /// <summary>Assigns the access app role to the user. Already assigned: nothing to do.</summary>
        Task AssignAsync(string objectId, CancellationToken ct);

        /// <summary>Removes the user's assignments of the access app role — and only those. Not assigned: nothing to do.</summary>
        Task UnassignAsync(string objectId, CancellationToken ct);

        /// <summary>Removes one assignment, by its id. Gone already: nothing to do.</summary>
        Task RemoveAsync(string assignmentId, CancellationToken ct);
    }

    /// <summary>
    /// The assignments of the <c>Access</c> app role on the application's Enterprise application, through Microsoft Graph:
    /// reading whether a person holds it, listing who does, assigning and unassigning.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The service principal and the app role come from configuration (<see cref="EntraGraphOptions.ServicePrincipalId"/>,
    /// <see cref="EntraGraphOptions.AccessAppRoleId"/>), never from a caller: with <c>AppRoleAssignment.ReadWrite.All</c>
    /// the credential could assign any role on any application, so no method takes either as a parameter. Only USER
    /// assignments count — on an Entra ID Free tenant groups cannot be assigned anyway.
    /// </para>
    /// <para>
    /// Application permissions: <c>AppRoleAssignment.ReadWrite.All</c> to assign and unassign, and to read; plus
    /// <c>User.Read.All</c> for the people. Every operation is idempotent: assigning an assigned person or unassigning an
    /// unassigned one ends in the state asked for.
    /// </para>
    /// </remarks>
    public sealed class GraphAppRoleAssignments : IAccessAssignments
    {
        private const string Fields = "id,appRoleId,principalId,principalType,resourceId";

        private readonly GraphClient _graph;
        private readonly IOptions<EntraGraphOptions> _options;

        public GraphAppRoleAssignments(GraphClient graph, IOptions<EntraGraphOptions> options)
        {
            _graph = graph;
            _options = options;
        }

        private string ServicePrincipalId => _options.Value.ServicePrincipalId;
        private string AppRoleId => _options.Value.AccessAppRoleId;

        /// <summary>Whether the user holds the access app role. False for an unknown user or one that is not an object id.</summary>
        public async Task<bool> IsAssignedAsync(string objectId, CancellationToken ct) =>
            (await OfUserAsync(objectId, ct)).Count > 0;

        /// <summary>Every user assigned the access app role.</summary>
        public async Task<IReadOnlyList<AppRoleAssignment>> ListAsync(CancellationToken ct)
        {
            RequireConfigured();
            var assignments = await _graph.GetAllAsync<GraphAssignment>(
                $"servicePrincipals/{ServicePrincipalId}/appRoleAssignedTo?$select={Fields}&$top=999",
                "listing the users assigned to the application", ct);

            return assignments
                .Where(IsAccess)
                .Where(a => string.Equals(a.PrincipalType, "User", StringComparison.OrdinalIgnoreCase))
                .Select(a => new AppRoleAssignment(a.Id!, a.PrincipalId!))
                .ToList();
        }

        /// <summary>Assigns the access app role to the user. Already assigned: nothing to do.</summary>
        public async Task AssignAsync(string objectId, CancellationToken ct)
        {
            RequireObjectId(objectId);
            RequireConfigured();

            using var response = await _graph.PostAsync(
                $"servicePrincipals/{ServicePrincipalId}/appRoleAssignedTo",
                new { principalId = objectId, resourceId = ServicePrincipalId, appRoleId = AppRoleId },
                ct);
            if (response.IsSuccessStatusCode)
                return;

            // Assigned already: Graph answers 400. The desired end state is the actual one.
            var error = await GraphClient.ReadErrorAsync(response, ct);
            if (response.StatusCode == HttpStatusCode.BadRequest && error.Contains("already exist", StringComparison.OrdinalIgnoreCase))
                return;

            throw new GraphException($"The directory rejected assigning the user to the application: {error}", response.StatusCode);
        }

        /// <summary>Removes the user's assignments of the access app role — and only those. Not assigned: nothing to do.</summary>
        public async Task UnassignAsync(string objectId, CancellationToken ct)
        {
            RequireObjectId(objectId);
            foreach (var assignment in await OfUserAsync(objectId, ct))
                await RemoveAsync(assignment.AssignmentId, ct);
        }

        /// <summary>Removes one assignment, by its id, from the application. Gone already: nothing to do.</summary>
        public async Task RemoveAsync(string assignmentId, CancellationToken ct)
        {
            RequireConfigured();

            // An assignment id is not a GUID: it is checked to be URL-safe instead, so it cannot reshape the path.
            if (string.IsNullOrWhiteSpace(assignmentId) || !assignmentId.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_'))
                throw new GraphException($"'{assignmentId}' is not an assignment id.");

            using var response = await _graph.DeleteAsync($"servicePrincipals/{ServicePrincipalId}/appRoleAssignedTo/{assignmentId}", ct);
            if (response.IsSuccessStatusCode || response.StatusCode == HttpStatusCode.NotFound)
                return;

            await _graph.EnsureSuccessAsync(response, "removing the user's assignment to the application", ct);
        }

        /// <summary>The user's assignments of the access app role on this application.</summary>
        private async Task<IReadOnlyList<AppRoleAssignment>> OfUserAsync(string objectId, CancellationToken ct)
        {
            if (!GraphClient.IsObjectId(objectId))
                return [];
            RequireConfigured();

            // Read from the user's side, filtered here: a person holds few assignments, and comparing the resource and the
            // role in code does not depend on which $filter Graph supports on this collection.
            var page = await _graph.GetOrNullAsync<GraphPage<GraphAssignment>>(
                $"users/{objectId}/appRoleAssignments?$select={Fields}&$top=999", "reading the user's assignments", ct);

            return (page?.Value ?? [])
                .Where(IsAccess)
                .Select(a => new AppRoleAssignment(a.Id!, a.PrincipalId ?? objectId))
                .ToList();
        }

        private bool IsAccess(GraphAssignment assignment) =>
            !string.IsNullOrWhiteSpace(assignment.Id)
            && string.Equals(assignment.AppRoleId, AppRoleId, StringComparison.OrdinalIgnoreCase)
            && (assignment.ResourceId is null || string.Equals(assignment.ResourceId, ServicePrincipalId, StringComparison.OrdinalIgnoreCase))
            && (assignment.PrincipalId is null || GraphClient.IsObjectId(assignment.PrincipalId));

        private void RequireConfigured()
        {
            if (!GraphClient.IsObjectId(ServicePrincipalId) || !GraphClient.IsObjectId(AppRoleId))
                throw new GraphException("The Enterprise application is not configured: Directory:ServicePrincipalId and Directory:AccessAppRoleId are needed.");
        }

        private static void RequireObjectId(string objectId)
        {
            if (!GraphClient.IsObjectId(objectId))
                throw new GraphException($"'{objectId}' is not a valid Entra object id.");
        }

        private sealed class GraphAssignment
        {
            public string? Id { get; set; }
            public string? AppRoleId { get; set; }
            public string? PrincipalId { get; set; }
            public string? PrincipalType { get; set; }
            public string? ResourceId { get; set; }
        }
    }
}
