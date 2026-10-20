using kdyf.Authorization.EntraId;
using Microsoft.Extensions.Options;

namespace kdyf.Authorization.Migrations.Legacy
{
    /// <summary><see cref="ILegacyDirectory"/> over Microsoft Graph, with the host's Graph registration (User.Read.All).</summary>
    internal sealed class GraphLegacyDirectory : ILegacyDirectory
    {
        private const string Fields = "id,userPrincipalName,mail,userType,accountEnabled";

        private readonly GraphClient _graph;
        private readonly LegacyImportOptions _options;

        public GraphLegacyDirectory(GraphClient graph, IOptions<LegacyImportOptions> options)
        {
            _graph = graph;
            _options = options.Value;
        }

        public async Task<DirectoryPerson?> GetAsync(string objectId, CancellationToken cancellationToken = default)
        {
            if (!Guid.TryParse(objectId, out var id))
                return null;
            var user = await _graph.GetOrNullAsync<GraphUser>($"users/{id}?$select={Fields}", "reading a legacy user", cancellationToken);
            return user is null ? null : ToPerson(user);
        }

        public async Task<IReadOnlyList<DirectoryPerson>> FindExactAsync(string email, CancellationToken cancellationToken = default)
        {
            // Exact equality on the two properties that name a person's own address, and nothing else. The single quote is
            // doubled, which is how a literal is escaped inside $filter.
            // Then URL-encoded: a guest's UPN carries '#EXT#', and '#' would end the query; '+' would arrive as a space.
            var value = Uri.EscapeDataString(email.Trim().ToLowerInvariant().Replace("'", "''"));
            var found = await _graph.GetAllAsync<GraphUser>(
                $"users?$select={Fields}&$count=true&$filter=userPrincipalName eq '{value}' or mail eq '{value}'",
                "looking up a legacy user by e-mail", cancellationToken, eventualConsistency: true);
            return found.Where(u => u.Id is not null).Select(ToPerson).ToList();
        }

        public Task<bool> InLegacyGroupAsync(string objectId, CancellationToken cancellationToken = default) =>
            _graph.IsMemberOfAsync(objectId, _options.LegacyGroupId
                ?? throw new InvalidOperationException("LegacyImport:LegacyGroupId is not set."), cancellationToken);

        private static DirectoryPerson ToPerson(GraphUser user) =>
            new(user.Id!, user.UserPrincipalName, user.Mail, user.UserType, user.AccountEnabled ?? false);

        private sealed class GraphUser
        {
            public string? Id { get; set; }
            public string? UserPrincipalName { get; set; }
            public string? Mail { get; set; }
            public string? UserType { get; set; }
            public bool? AccountEnabled { get; set; }
        }
    }
}
