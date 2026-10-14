using kdyf.Authorization.Abstractions;
using kdyf.Authorization.Simulation;

namespace kdyf.Authorization.Administration
{
    /// <summary>
    /// Who is administering, and what they may hand out.
    /// </summary>
    /// <param name="Identity">
    /// Who they are. Audited by its subject id, and used to recognise "this is me": nobody changes their
    /// own access.
    /// </param>
    /// <param name="Permissions">
    /// Their EFFECTIVE permissions, already expanded. Nobody may hand out more than they hold, so a role
    /// is only assignable when everything it grants is covered by this set.
    /// </param>
    /// <param name="SimulatedBy">
    /// The real administrator's e-mail when this request is served AS somebody else (user simulation).
    /// Every change is refused then: the identity above is borrowed, and a change would be attributed —
    /// and self-checked — against the wrong person.
    /// </param>
    /// <remarks>
    /// Resolved ONCE per request, at the edge, and passed in: two lookups in one request could disagree
    /// across a cache expiry and leave the list offering a role the save then refuses.
    /// </remarks>
    public sealed record AdminActor(UserIdentity Identity, IReadOnlySet<string> Permissions, string? SimulatedBy = null)
    {
        /// <summary>An actor that may hand out nothing and change nothing.</summary>
        public static AdminActor Anonymous { get; } =
            new(new UserIdentity(null, null), new HashSet<string>(StringComparer.Ordinal));

        /// <summary>True when the request is served as somebody else.</summary>
        public bool IsSimulating => !string.IsNullOrWhiteSpace(SimulatedBy);

        /// <summary>
        /// True for an interactive sign-in of a person: the only kind of caller whose changes the audit log
        /// can attribute to somebody. A personal access token or an application token has no subject id.
        /// </summary>
        public bool IsPerson => !string.IsNullOrWhiteSpace(Identity.SubjectId);

        /// <summary>Whether <paramref name="objectId"/> is the actor themselves.</summary>
        public bool Is(string objectId) =>
            IsPerson && string.Equals(Identity.SubjectId, objectId, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Builds an <see cref="AdminActor"/> from a principal.</summary>
    /// <remarks>
    /// A host's endpoints use <see cref="IAdminActorAccessor"/>, which calls this with the registered simulation
    /// options: building the actor by hand is where a simulation goes unnoticed.
    /// </remarks>
    public static class AdminActorExtensions
    {
        /// <summary>
        /// Resolves who is asking and what they hold, through the very same services the authorization
        /// handler uses — so "may they call this" and "may they hand this out" can never be answered about
        /// two different people or two different permission sets.
        /// </summary>
        /// <param name="permissions">The resolver the authorization handler uses.</param>
        /// <param name="user">The principal of the request.</param>
        /// <param name="identities">Who the principal is.</param>
        /// <param name="simulation">
        /// The registered simulation options, or null when simulation is off: they name the claim a borrowed
        /// principal carries. Required, not defaulted — a wrong claim name reads a simulated request as the real
        /// person's, and every "no changes while simulating" rule then lets the change through.
        /// </param>
        /// <param name="ct">Cancellation.</param>
        public static async Task<AdminActor> ResolveActorAsync(
            this IPrincipalPermissionResolver permissions,
            System.Security.Claims.ClaimsPrincipal user,
            IUserIdentityResolver identities,
            UserSimulationOptions? simulation,
            CancellationToken ct = default)
        {
            ArgumentNullException.ThrowIfNull(user);
            ArgumentNullException.ThrowIfNull(identities);

            var identity = identities.Resolve(user) ?? new UserIdentity(null, null);
            var codes = await permissions.ResolveAsync(user, ct);

            // Without simulation the default claim is still read: a principal carrying it was borrowed by
            // something, and is refused changes rather than trusted.
            var claim = simulation?.SimulatedByClaimType ?? new UserSimulationOptions().SimulatedByClaimType;
            var simulatedBy = user.FindFirst(claim)?.Value;

            return new AdminActor(identity, codes, simulatedBy);
        }
    }
}
