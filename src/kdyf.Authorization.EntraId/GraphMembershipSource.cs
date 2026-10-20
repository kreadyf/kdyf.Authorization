using Microsoft.Extensions.Options;
using kdyf.Authorization.Abstractions;

namespace kdyf.Authorization.EntraId
{
    /// <summary>
    /// <see cref="IMembershipSource"/> over Microsoft Graph: whether a person's account is enabled, and whether
    /// they are in the access group.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Two calls per person, sent together and cached upstream by the permission store for <c>CacheDuration</c>: the user
    /// (<c>accountEnabled</c>) and <c>checkMemberGroups</c> for the one group, which answers TRANSITIVE
    /// membership — somebody in a group nested inside the access group is a member.
    /// </para>
    /// <para>
    /// Works on an Entra ID Free tenant: nothing is assigned to the Enterprise application, the group is only
    /// read. Application permissions: <c>User.Read.All</c> and <c>GroupMember.Read.All</c>.
    /// </para>
    /// </remarks>
    internal sealed class GraphMembershipSource : IMembershipSource
    {
        private readonly GraphClient _graph;
        private readonly IOptions<EntraGraphOptions> _options;

        public GraphMembershipSource(GraphClient graph, IOptions<EntraGraphOptions> options)
        {
            _graph = graph;
            _options = options;
        }

        public async Task<Membership?> GetMembershipAsync(string subjectId, CancellationToken cancellationToken = default)
        {
            // Not a GUID: not an Entra object, and never pasted into a URL.
            if (!GraphClient.IsObjectId(subjectId))
                return null;

            // The two calls do not depend on each other: sent together, a cache miss costs one round trip to
            // Graph instead of two.
            var userCall = _graph.GetOrNullAsync<GraphUserStatus>(
                $"users/{subjectId}?$select=id,accountEnabled", "reading the user's account status", cancellationToken);
            var memberCall = _graph.IsMemberOfAsync(subjectId, _options.Value.GroupId, cancellationToken);

            await Task.WhenAll(userCall, memberCall);

            var user = await userCall;
            if (user is null)
                return null;

            var isMember = await memberCall;

            // accountEnabled is null only when Graph was not allowed to read it; treating that as enabled
            // would grant on a missing permission, so it counts as disabled.
            return new Membership(user.AccountEnabled == true, isMember);
        }

        public Task<DirectoryIdentity?> FindByEmailAsync(string email, CancellationToken cancellationToken = default) =>
            GraphPeople.FindByEmailAsync(_graph, email, cancellationToken);

        internal sealed class GraphUserStatus
        {
            public string? Id { get; set; }
            public bool? AccountEnabled { get; set; }
        }
    }
}
