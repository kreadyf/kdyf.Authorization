namespace kdyf.Authorization.Authorization
{
    /// <summary>
    /// The policies this application declared, kept for the things that need to see them ALL.
    /// </summary>
    /// <remarks>
    /// It exists because ASP.NET Core does not let anyone enumerate the registered policies:
    /// <c>AuthorizationOptions</c> exposes <c>AddPolicy</c>, <c>GetPolicy</c> and the two default
    /// ones, and keeps its map private. Anything that has to answer "which policies are there" —
    /// the report of the caller's access (<c>PolicyReport</c>), a coverage check, a screen listing the doors —
    /// has to hold its own list, so <c>AddPolicies</c> keeps the one it discovered.
    /// </remarks>
    public sealed class PolicyCatalog
    {
        /// <param name="policies">The declared policies, ordered by name.</param>
        public PolicyCatalog(IReadOnlyList<Policy> policies) => Policies = policies;

        /// <summary>Ordered by name.</summary>
        public IReadOnlyList<Policy> Policies { get; }
    }
}
