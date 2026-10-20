using System.Net;
using Microsoft.Extensions.Options;
using kdyf.Authorization.Administration.Abstractions;
using kdyf.Authorization.EntraId;

namespace kdyf.Authorization.Administration.EntraId
{
    /// <summary>
    /// <see cref="IAccessDirectory"/> over Microsoft Graph: the members of the access group
    /// (<c>Directory:GroupId</c> in the authorization section).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Application permissions (admin consent): <c>GroupMember.ReadWrite.All</c> to list, add and remove
    /// members, and <c>User.Read.All</c> for the people and their <c>accountEnabled</c>. Works on an Entra ID
    /// Free tenant: the group is not assigned to anything.
    /// </para>
    /// <para>
    /// Only USERS count as members. A nested group counts through its users (transitive membership); a device
    /// or a service principal in the group is ignored. Adding and removing touch the DIRECT membership only.
    /// </para>
    /// </remarks>
    public sealed class GraphAccessGroupDirectory : IAccessDirectory
    {
        private readonly GraphClient _graph;
        private readonly IOptions<EntraGraphOptions> _options;
        private readonly GraphAccounts _accounts;

        /// <summary>Creates the directory over the Graph client; <paramref name="options"/> names the access group.</summary>
        public GraphAccessGroupDirectory(GraphClient graph, IOptions<EntraGraphOptions> options)
        {
            _graph = graph;
            _options = options;
            _accounts = new GraphAccounts(graph);
        }

        private string GroupId => _options.Value.GroupId;

        /// <inheritdoc />
        public Task<IReadOnlyList<DirectoryAccount>> ListWithAccessAsync(CancellationToken cancellationToken = default) => GraphAccounts.Call(async () =>
        {
            // The cast to microsoft.graph.user keeps devices and service principals out; it is an advanced query,
            // hence eventual consistency and $count.
            var users = await _graph.GetAllAsync<GraphDirectoryService.GraphUser>(
                $"groups/{GroupId}/transitiveMembers/microsoft.graph.user?$select={GraphAccounts.UserFields}&$count=true&$top=999",
                "listing the members of the access group", cancellationToken, eventualConsistency: true);

            IReadOnlyList<DirectoryAccount> members = users
                .Where(u => GraphClient.IsObjectId(u.Id))
                .GroupBy(u => u.Id!, StringComparer.OrdinalIgnoreCase)
                .Select(g => GraphAccounts.ToAccount(g.First()))
                .ToList();
            return members;
        });

        /// <inheritdoc />
        public Task<DirectoryAccount?> GetUserAsync(string objectId, CancellationToken cancellationToken = default) =>
            _accounts.GetUserAsync(objectId, cancellationToken);

        /// <inheritdoc />
        public Task<IReadOnlyList<DirectoryAccount>> GetUsersAsync(IReadOnlyCollection<string> objectIds, CancellationToken cancellationToken = default) =>
            _accounts.GetUsersAsync(objectIds, cancellationToken);

        /// <inheritdoc />
        public Task<bool> HasAccessAsync(string objectId, CancellationToken cancellationToken = default) =>
            GraphAccounts.Call(() => _graph.IsMemberOfAsync(objectId, GroupId, cancellationToken));

        /// <inheritdoc />
        public Task GrantAsync(string objectId, CancellationToken cancellationToken = default) => GraphAccounts.Call(async () =>
        {
            if (!GraphClient.IsObjectId(objectId))
                throw new DirectoryException($"'{objectId}' is not a valid Entra object id.");

            // '@odata.id' is not a C# identifier: a dictionary carries it.
            var body = new Dictionary<string, string>
            {
                ["@odata.id"] = $"{_options.Value.GraphBaseUrl.TrimEnd('/')}/directoryObjects/{objectId}"
            };

            using var response = await _graph.PostAsync($"groups/{GroupId}/members/$ref", body, cancellationToken);
            if (response.IsSuccessStatusCode)
                return true;

            // A member already: Graph answers 400. The desired end state is the actual one.
            var error = await GraphClient.ReadErrorAsync(response, cancellationToken);
            if (response.StatusCode == HttpStatusCode.BadRequest && error.Contains("already exist", StringComparison.OrdinalIgnoreCase))
                return true;

            throw new DirectoryException($"The directory rejected adding the user to the access group: {error}");
        });

        /// <inheritdoc />
        public Task RevokeAsync(string objectId, CancellationToken cancellationToken = default) => GraphAccounts.Call(async () =>
        {
            if (!GraphClient.IsObjectId(objectId))
                throw new DirectoryException($"'{objectId}' is not a valid Entra object id.");

            using var response = await _graph.DeleteAsync($"groups/{GroupId}/members/{objectId}/$ref", cancellationToken);

            // Not a direct member (any more): the desired end state is the actual one.
            if (response.IsSuccessStatusCode || response.StatusCode == HttpStatusCode.NotFound)
                return true;

            var error = await GraphClient.ReadErrorAsync(response, cancellationToken);
            throw new DirectoryException($"The directory rejected removing the user from the access group: {error}");
        });
    }
}
