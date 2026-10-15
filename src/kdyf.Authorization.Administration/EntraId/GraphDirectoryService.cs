using kdyf.Authorization.Administration.Abstractions;
using kdyf.Authorization.EntraId;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace kdyf.Authorization.Administration.EntraId
{
    /// <summary>
    /// <see cref="IDirectoryService"/> against Microsoft Graph with application permissions: searching
    /// people in the tenant and inviting external users as B2B guests.
    /// </summary>
    /// <remarks>
    /// Application permissions (admin consent): <c>User.Read.All</c> to search, <c>User.Invite.All</c>
    /// to invite. Who may use it is decided by the policy guarding the endpoint.
    /// </remarks>
    public sealed class GraphDirectoryService : IDirectoryService
    {
        private const string UserFields = "id,displayName,mail,otherMails,userPrincipalName,userType";

        private readonly GraphClient _graph;
        private readonly GraphDirectoryOptions _options;
        private readonly ILogger<GraphDirectoryService> _logger;

        public GraphDirectoryService(GraphClient graph, IOptions<GraphDirectoryOptions> options, ILogger<GraphDirectoryService> logger)
        {
            _graph = graph;
            _options = options.Value;
            _logger = logger;
        }

        public async Task<IReadOnlyList<DirectoryUser>> SearchAsync(string search, CancellationToken cancellationToken = default)
        {
            // $search takes quoted "property:term" clauses; a quote or a backslash in the term would end the
            // clause early, so they are dropped rather than escaped.
            var term = new string((search ?? string.Empty).Trim().Where(c => c is not '"' and not '\\').ToArray());
            if (term.Length == 0)
                return Array.Empty<DirectoryUser>();

            var clauses = Uri.EscapeDataString(
                $"\"displayName:{term}\" OR \"mail:{term}\" OR \"userPrincipalName:{term}\"");
            var url = $"users?$search={clauses}&$select={UserFields}&$top={_options.MaxSearchResults}&$count=true";

            var page = await Call(() => _graph.GetAsync<GraphPage<GraphUser>>(url, $"searching the directory for '{term}'", cancellationToken, eventualConsistency: true));

            // Graph matches word prefixes, including the tenant domain inside every guest's UPN. The filter
            // keeps only people the term really names (see DirectoryUserFilter).
            return (page.Value ?? new List<GraphUser>())
                .Select(ToDirectoryUser)
                .Where(user => DirectoryUserFilter.Matches(user, term))
                .OrderBy(user => user.DisplayName ?? user.Email ?? user.ObjectId, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        public async Task<DirectoryUser?> FindByEmailAsync(string email, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(email))
                return null;

            // 'mail' for a guest who HAS redeemed, 'otherMails' for one who has NOT yet (their 'mail' is
            // empty and their UPN carries #EXT#, so without it they would be invited twice), the UPN for an
            // internal member. otherMails/any is an advanced query: eventual consistency + $count. The single
            // quote is doubled, which is how a literal is escaped inside $filter.
            // Then URL-encoded: a guest's UPN carries '#EXT#', and '#' would end the query; '+' would arrive as a space.
            var value = Uri.EscapeDataString(email.Trim().ToLowerInvariant().Replace("'", "''"));
            var url = $"users?$select={UserFields}&$count=true" +
                      $"&$filter=mail eq '{value}' or otherMails/any(m:m eq '{value}') or userPrincipalName eq '{value}'&$top=1";

            var page = await Call(() => _graph.GetAsync<GraphPage<GraphUser>>(url, $"looking up '{email}'", cancellationToken, eventualConsistency: true));
            var match = page.Value?.FirstOrDefault();
            return match is null ? null : ToDirectoryUser(match);
        }

        public async Task<DirectoryInvitation> InviteAsync(string email, string? displayName, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(_options.InviteRedirectUrl))
                throw new DirectoryException("Directory:InviteRedirectUrl, in the authorization section, is not configured: an invitation cannot be created without it.");

            var body = new
            {
                invitedUserEmailAddress = email,
                invitedUserDisplayName = displayName,
                inviteRedirectUrl = _options.InviteRedirectUrl,
                sendInvitationMessage = _options.SendInvitationMessage,
                // Guest: an external person. 'Member' would give them the reach of an employee inside the directory.
                invitedUserType = "Guest"
            };

            var invitation = await Call(async () =>
            {
                using var response = await _graph.PostAsync("invitations", body, cancellationToken);
                await _graph.EnsureSuccessAsync(response, $"inviting '{email}'", cancellationToken);
                return await GraphClient.ReadAsync<InvitationResponse>(response, cancellationToken);
            });

            var objectId = invitation.InvitedUser?.Id;
            if (string.IsNullOrWhiteSpace(objectId))
                throw new DirectoryException($"The directory accepted the invitation for '{email}' but returned no user id.");

            _logger.LogInformation("Guest invited: {Email} ({ObjectId}), state {Status}", email, objectId, invitation.Status);

            var user = new DirectoryUser(objectId, displayName, email, null, IsGuest: true);
            return new DirectoryInvitation(user, invitation.InviteRedeemUrl, _options.SendInvitationMessage);
        }

        internal static DirectoryUser ToDirectoryUser(GraphUser user) => new(
            ObjectId: user.Id ?? string.Empty,
            DisplayName: user.DisplayName,
            // A guest who has not redeemed yet usually has no 'mail': the address they were invited with
            // sits in 'otherMails'. The UPN is not a fallback — it carries the #EXT# shape.
            Email: user.Mail ?? user.OtherMails?.FirstOrDefault(),
            UserPrincipalName: user.UserPrincipalName,
            IsGuest: string.Equals(user.UserType, "Guest", StringComparison.OrdinalIgnoreCase));

        /// <summary>Graph's failures, in this library's vocabulary.</summary>
        private static async Task<T> Call<T>(Func<Task<T>> call)
        {
            try
            {
                return await call();
            }
            catch (GraphException ex)
            {
                throw new DirectoryException(ex.Message, ex);
            }
        }

        internal sealed class GraphUser
        {
            public string? Id { get; set; }
            public string? DisplayName { get; set; }
            public string? Mail { get; set; }
            public List<string>? OtherMails { get; set; }
            public string? UserPrincipalName { get; set; }
            public string? UserType { get; set; }
            public bool? AccountEnabled { get; set; }
        }

        private sealed class InvitationResponse
        {
            public string? Status { get; set; }
            public string? InviteRedeemUrl { get; set; }
            public GraphUser? InvitedUser { get; set; }
        }
    }
}
