using kdyf.Authorization.Administration.Abstractions;
using kdyf.Authorization.EntraId;

namespace kdyf.Authorization.Administration.EntraId
{
    /// <summary>
    /// <see cref="IAccessDirectory"/> over Microsoft Graph for <see cref="AccessGate.AppAssignment"/>: the users assigned
    /// the <c>Access</c> app role on the application's Enterprise application (<c>Directory:ServicePrincipalId</c>,
    /// <c>Directory:AccessAppRoleId</c>).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Giving access assigns the role; taking it away removes that role's assignments, and only those. Both are
    /// idempotent. The application and the role come from configuration, never from a request.
    /// </para>
    /// <para>
    /// Application permissions (admin consent): <c>AppRoleAssignment.ReadWrite.All</c> and <c>User.Read.All</c>. On an
    /// Entra ID Free tenant only users are assigned, one by one: there is no group assignment to inherit from.
    /// </para>
    /// </remarks>
    public sealed class GraphAccessAssignmentDirectory : IAccessDirectory
    {
        private readonly IAccessAssignments _assignments;
        private readonly GraphAccounts _accounts;

        public GraphAccessAssignmentDirectory(GraphClient graph, IAccessAssignments assignments)
        {
            _assignments = assignments;
            _accounts = new GraphAccounts(graph);
        }

        public Task<IReadOnlyList<DirectoryAccount>> ListWithAccessAsync(CancellationToken cancellationToken = default) => GraphAccounts.Call(async () =>
        {
            var assigned = await _assignments.ListAsync(cancellationToken);
            return await _accounts.GetUsersAsync(assigned.Select(a => a.PrincipalId).ToList(), cancellationToken);
        });

        public Task<DirectoryAccount?> GetUserAsync(string objectId, CancellationToken cancellationToken = default) =>
            _accounts.GetUserAsync(objectId, cancellationToken);

        public Task<IReadOnlyList<DirectoryAccount>> GetUsersAsync(IReadOnlyCollection<string> objectIds, CancellationToken cancellationToken = default) =>
            _accounts.GetUsersAsync(objectIds, cancellationToken);

        public Task<bool> HasAccessAsync(string objectId, CancellationToken cancellationToken = default) =>
            GraphAccounts.Call(() => _assignments.IsAssignedAsync(objectId, cancellationToken));

        public Task GrantAsync(string objectId, CancellationToken cancellationToken = default)
        {
            if (!GraphClient.IsObjectId(objectId))
                throw new DirectoryException($"'{objectId}' is not a valid Entra object id.");
            return GraphAccounts.Call(() => _assignments.AssignAsync(objectId, cancellationToken));
        }

        public Task RevokeAsync(string objectId, CancellationToken cancellationToken = default)
        {
            if (!GraphClient.IsObjectId(objectId))
                throw new DirectoryException($"'{objectId}' is not a valid Entra object id.");
            return GraphAccounts.Call(() => _assignments.UnassignAsync(objectId, cancellationToken));
        }
    }
}
