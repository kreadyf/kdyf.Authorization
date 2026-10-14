using Azure.Core;
using Azure.Identity;
using Microsoft.Extensions.Options;

namespace kdyf.Authorization.EntraId
{
    /// <summary>
    /// Hands out the application token for Graph (client credentials).
    /// </summary>
    /// <remarks>
    /// Its own type, registered as a SINGLETON, so the credential's in-memory token cache survives
    /// between requests: a <see cref="ClientSecretCredential"/> per request would ask the identity
    /// provider for a token every single time. Not registered as <c>TokenCredential</c>, to avoid
    /// clashing with any other credential the host has in the container.
    /// </remarks>
    public sealed class GraphTokenProvider
    {
        /// <summary>Application permissions: the scope is always the resource's '.default'.</summary>
        private static readonly string[] Scopes = { "https://graph.microsoft.com/.default" };

        private readonly Lazy<TokenCredential> _credential;

        public GraphTokenProvider(IOptions<EntraGraphOptions> options)
        {
            // Lazy: the container must build even while the options are incomplete; the failure has to
            // surface when Graph is used (and the options validator stops the host before that).
            _credential = new Lazy<TokenCredential>(() =>
            {
                var value = options.Value;
                return new ClientSecretCredential(value.TenantId, value.ClientId, value.ClientSecret);
            });
        }

        /// <summary>For tests: a credential of their own instead of the client secret.</summary>
        internal GraphTokenProvider(TokenCredential credential) => _credential = new Lazy<TokenCredential>(() => credential);

        public async Task<string> GetAccessTokenAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                var token = await _credential.Value.GetTokenAsync(new TokenRequestContext(Scopes), cancellationToken);
                return token.Token;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // The exception text of the credential never contains the secret; the message names the
                // keys to check, not their values.
                throw new GraphException("Could not obtain a token for Microsoft Graph. Check the tenant, client id and client secret.", null, ex);
            }
        }
    }
}
