using kdyf.Authorization.Abstractions;

namespace kdyf.Authorization.EntraId
{
    /// <summary>
    /// <see cref="IMembershipSource"/> over Microsoft Graph for <see cref="AccessGate.AppAssignment"/>: whether a person's
    /// account is enabled, and whether they are assigned the <c>Access</c> app role on the application's Enterprise
    /// application.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The same contract as the group: an unknown person is null, a Graph failure throws (the request is denied and
    /// nothing is cached), always by object id. Checked on the server on every resolution, cached upstream for
    /// <c>CacheDuration</c>: "Assignment required" alone would leave personal access tokens, tokens already issued and
    /// disabled accounts through.
    /// </para>
    /// <para>The two calls are sent together: a cache miss costs one round trip to Graph.</para>
    /// </remarks>
    public sealed class GraphAppAssignmentMembershipSource : IMembershipSource
    {
        private readonly GraphClient _graph;
        private readonly IAccessAssignments _assignments;

        public GraphAppAssignmentMembershipSource(GraphClient graph, IAccessAssignments assignments)
        {
            _graph = graph;
            _assignments = assignments;
        }

        public async Task<Membership?> GetMembershipAsync(string subjectId, CancellationToken cancellationToken = default)
        {
            // Not a GUID: not an Entra object, and never pasted into a URL.
            if (!GraphClient.IsObjectId(subjectId))
                return null;

            var enabledCall = GraphPeople.AccountEnabledAsync(_graph, subjectId, cancellationToken);
            var assignedCall = _assignments.IsAssignedAsync(subjectId, cancellationToken);
            await Task.WhenAll(enabledCall, assignedCall);

            var enabled = await enabledCall;
            return enabled is null ? null : new Membership(enabled.Value, await assignedCall);
        }

        public Task<DirectoryIdentity?> FindByEmailAsync(string email, CancellationToken cancellationToken = default) =>
            GraphPeople.FindByEmailAsync(_graph, email, cancellationToken);
    }
}
