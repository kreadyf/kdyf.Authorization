using kdyf.Authorization.Abstractions;

namespace kdyf.Authorization.EntraId
{
    /// <summary>Finding people in Microsoft Graph, whatever decides who has access.</summary>
    internal static class GraphPeople
    {
        /// <summary>
        /// The one person answering to the e-mail: their mail, a guest's other mail, or the UPN. Null when nobody does, or
        /// more than one person does — simulating either would be a guess.
        /// </summary>
        public static async Task<DirectoryIdentity?> FindByEmailAsync(GraphClient graph, string email, CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(email))
                return null;

            var normalized = email.Trim().ToLowerInvariant();

            // 'mail' for members and redeemed guests, 'otherMails' for a guest who has not redeemed
            // yet, the UPN for internal accounts. The single quote is doubled: that is how a literal is
            // escaped inside $filter. otherMails/any is an advanced query: eventual consistency + $count.
            var value = normalized.Replace("'", "''");
            var url = "users?$select=id,displayName,mail&$count=true" +
                      $"&$filter=mail eq '{value}' or otherMails/any(m:m eq '{value}') or userPrincipalName eq '{value}'&$top=2";

            var page = await graph.GetAsync<GraphPage<GraphUserSummary>>(url, $"looking up '{normalized}'", cancellationToken, eventualConsistency: true);
            var matches = page.Value ?? new List<GraphUserSummary>();

            if (matches.Count != 1 || string.IsNullOrWhiteSpace(matches[0].Id))
                return null;

            return new DirectoryIdentity(matches[0].Id!, normalized, matches[0].DisplayName);
        }

        /// <summary>Whether the account is enabled, or null when Graph does not know the user.</summary>
        public static async Task<bool?> AccountEnabledAsync(GraphClient graph, string objectId, CancellationToken cancellationToken)
        {
            var user = await graph.GetOrNullAsync<GraphMembershipSource.GraphUserStatus>(
                $"users/{objectId}?$select=id,accountEnabled", "reading the user's account status", cancellationToken);

            // accountEnabled is null only when Graph was not allowed to read it; treating that as enabled would grant on a
            // missing permission, so it counts as disabled.
            return user is null ? null : user.AccountEnabled == true;
        }

        private sealed class GraphUserSummary
        {
            public string? Id { get; set; }
            public string? DisplayName { get; set; }
            public string? Mail { get; set; }
        }
    }
}
