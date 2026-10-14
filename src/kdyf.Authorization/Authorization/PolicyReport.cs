using System.Security.Claims;
using kdyf.Authorization.Abstractions;
using Microsoft.Extensions.Logging;

namespace kdyf.Authorization.Authorization
{
    /// <summary>
    /// Which of the registered policies a caller satisfies right now, for a client that has to decide what to
    /// SHOW: one entry per door, for menus.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The permission codes answer "what does this person hold"; this answers the question a screen actually
    /// has — "may they open this door" — which stops being the same question as soon as a door takes more than
    /// one permission. A menu built from codes has to re-implement each policy's rule in the client, and the
    /// two drift.
    /// </para>
    /// <para>
    /// <b>The API stays the real gate.</b> This only reports; every endpoint still enforces its own policy.
    /// Which is why the evaluation mirrors <see cref="PermissionAuthorizationHandler"/> exactly — same resolver,
    /// same effective set, same exact-string comparison — and lives here, next to the handler, rather than in
    /// whichever host exposes it. A report kinder than the handler would send clients to doors that answer 403.
    /// </para>
    /// <para>
    /// No endpoint: the host decides where to expose it (usually <c>GET /auth/policies</c>).
    /// Registered by <c>AddPolicies</c>, since the policies it reports are the ones registered there.
    /// </para>
    /// </remarks>
    public sealed class PolicyReport
    {
        private readonly PolicyCatalog _catalog;
        private readonly IPrincipalPermissionResolver _permissions;
        private readonly ILogger<PolicyReport> _logger;

        public PolicyReport(PolicyCatalog catalog, IPrincipalPermissionResolver permissions, ILogger<PolicyReport> logger)
        {
            _catalog = catalog;
            _permissions = permissions;
            _logger = logger;
        }

        /// <summary>Every registered policy, and whether <paramref name="user"/> satisfies it.</summary>
        public async Task<IReadOnlyList<PolicyAccess>> EvaluateAsync(ClaimsPrincipal user, CancellationToken cancellationToken = default)
        {
            // Resolved ONCE for every policy. Asking IAuthorizationService per policy would repeat the whole
            // resolution as many times as there are doors.
            IReadOnlySet<string> held;
            try
            {
                held = await _permissions.ResolveAsync(user, cancellationToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // Fail closed, as the handler does: a store that cannot answer grants nothing. An error here
                // would tell the client something different from what every door says.
                _logger.LogError(ex, "Policy report: the permission store failed for {Name}; nothing reported as held.",
                    user.Identity?.Name);
                held = new HashSet<string>(StringComparer.Ordinal);
            }

            return _catalog.Policies
                .Select(policy => new PolicyAccess(policy.Name, Satisfies(policy, held)))
                .ToArray();
        }

        /// <summary>
        /// Every rule satisfied (AND), and within a rule any permission (OR) — the policy's own model, evaluated
        /// the way the handler evaluates its requirements.
        /// </summary>
        /// <remarks>
        /// <c>Contains</c>, not a wildcard-aware comparison: the effective set already holds the codes a pattern
        /// stands for, so exact matching is what the handler does and therefore what the truth is. A policy with
        /// no rules is satisfied by being authenticated, which the caller already is.
        /// </remarks>
        private static bool Satisfies(Policy policy, IReadOnlySet<string> held) =>
            policy.Rules.All(rule => rule.Any(permission => held.Contains(permission.Code)));
    }

    /// <param name="Name">The policy's name.</param>
    /// <param name="IsAuthorized">Whether this caller satisfies it right now.</param>
    public sealed record PolicyAccess(string Name, bool IsAuthorized);
}
