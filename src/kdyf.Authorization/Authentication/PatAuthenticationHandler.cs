using System.Security.Claims;
using System.Text.Encodings.Web;
using kdyf.Authorization.Abstractions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace kdyf.Authorization.Authentication
{
    /// <summary>Options of the PAT scheme. It adds nothing to <see cref="AuthenticationSchemeOptions"/>.</summary>
    public sealed class PatAuthenticationOptions : AuthenticationSchemeOptions
    {
    }

    /// <summary>
    /// Personal Access Token authentication scheme: <c>Authorization: PAT &lt;token&gt;</c>.
    /// Hashes the token (SHA-256) and resolves it against <see cref="IPatStore"/>. A valid PAT is NOT a
    /// person (it emits no email/subject), so authorization grants it by its role claims:
    /// each effective permission is emitted as a role.
    /// </summary>
    public sealed class PatAuthenticationHandler : AuthenticationHandler<PatAuthenticationOptions>
    {
        /// <summary>The default scheme name, also emitted as the <see cref="ClaimTypes.AuthenticationMethod"/> claim.</summary>
        public const string SchemeName = "PAT";
        private const string HeaderPrefix = "PAT ";

        /// <summary>For the authentication framework; the <see cref="IPatStore"/> is resolved per request, not injected here.</summary>
        public PatAuthenticationHandler(
            IOptionsMonitor<PatAuthenticationOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder)
            : base(options, logger, encoder)
        {
        }

        /// <summary>
        /// Whether an <c>Authorization</c> header carries a personal access token (<c>PAT &lt;token&gt;</c>). The one
        /// rule both this handler and a scheme selector that routes callers to it (<c>AddKdyfAuthorization</c>) apply.
        /// </summary>
        public static bool IsPatHeader(string? authorization) =>
            authorization is not null && authorization.StartsWith(HeaderPrefix, StringComparison.OrdinalIgnoreCase);

        /// <summary>
        /// Authenticates a <c>PAT &lt;token&gt;</c> header. No result when the header is absent, is not a PAT, or names
        /// a token the store does not resolve (unknown, disabled or expired); a failure when the store throws. On
        /// success the principal carries the token's name and one role claim per permission code.
        /// </summary>
        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.TryGetValue("Authorization", out var header))
                return AuthenticateResult.NoResult();

            var value = header.ToString();
            if (!IsPatHeader(value))
                return AuthenticateResult.NoResult();

            var token = value[HeaderPrefix.Length..].Trim();
            if (token.Length == 0)
                return AuthenticateResult.NoResult();

            var hash = PatToken.Hash(token);

            // The store is scoped: it is resolved from the request container, not via constructor,
            // to avoid capturing a scoped service in a longer-lived handler.
            var store = Context.RequestServices.GetRequiredService<IPatStore>();

            PatPrincipal? pat;
            try
            {
                pat = await store.ResolveAsync(hash, Context.RequestAborted);
            }
            catch (Exception ex)
            {
                Logger.LogError(ex, "PAT: failed to resolve the token against the store.");
                return AuthenticateResult.Fail("PAT store error");
            }

            if (pat is null)
            {
                Logger.LogWarning("Invalid, disabled or expired PAT from {Ip}.",
                    Context.Connection.RemoteIpAddress);
                return AuthenticateResult.NoResult();
            }

            var claims = new List<Claim>
            {
                new(ClaimTypes.Name, pat.Name),
                new(ClaimTypes.AuthenticationMethod, SchemeName)
            };
            foreach (var code in pat.PermissionCodes)
                claims.Add(new Claim(ClaimTypes.Role, code));

            var identity = new ClaimsIdentity(claims, Scheme.Name);
            var ticket = new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme.Name);
            return AuthenticateResult.Success(ticket);
        }
    }
}
