using kdyf.Authorization.Abstractions;

namespace kdyf.Authorization.Roles
{
    /// <summary>
    /// The permissions the application declares in code, completed into a tree: the only codes a role can be configured
    /// to grant.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Permissions stay in code because the doors (policies) that demand them are code: a permission
    /// created from a screen would be demanded by no endpoint. What is configurable is which role grants
    /// which of these — see <see cref="IRolePermissionSource"/>.
    /// </para>
    /// <para>
    /// Every ancestor of a declared code and the root are part of the catalog even without a class
    /// (<see cref="PermissionNode"/>): granting one of them grants everything below it.
    /// </para>
    /// </remarks>
    public sealed class DeclaredPermissions : IPermissionCatalog
    {
        private readonly Dictionary<string, PermissionDefinition> _byCode;

        /// <param name="permissions">The application's declarations, usually from <see cref="PermissionDefinition.DiscoverIn(System.Reflection.Assembly)"/>.</param>
        /// <exception cref="InvalidOperationException">A code that is not a path, or two paths differing only in capitalisation.</exception>
        public DeclaredPermissions(IEnumerable<PermissionDefinition> permissions)
        {
            Permissions = PermissionNode.Complete(permissions, out var ignored);
            IgnoredWildcards = ignored;
            _byCode = Permissions.ToDictionary(p => p.Code, StringComparer.Ordinal);
            Codes = _byCode.Keys.ToHashSet(StringComparer.Ordinal);
        }

        /// <summary>Every node of the tree — declared, implicit ancestors and the root — ordered by code.</summary>
        public IReadOnlyList<PermissionDefinition> Permissions { get; }

        /// <summary>Every code of the tree: what a grant expands against, and what a role may be given.</summary>
        public IReadOnlySet<string> Codes { get; }

        /// <summary>
        /// Declarations in the legacy wildcard syntax (<c>*</c>, <c>prefix.*</c>) that were left out: a node covers
        /// everything under it, so they stand for nothing. Reported at startup; delete their classes.
        /// </summary>
        public IReadOnlyList<string> IgnoredWildcards { get; }

        /// <summary>The declaration of this exact code, or null.</summary>
        public PermissionDefinition? Find(string code) =>
            code is not null && _byCode.TryGetValue(code, out var permission) ? permission : null;

        /// <summary>Whether a class declares this code, rather than it being an implicit node.</summary>
        public bool IsExplicit(string code) => Find(code) is { } permission && permission is not PermissionNode;

        /// <summary>The declared <see cref="Codes"/>; never reads a store.</summary>
        public Task<IReadOnlySet<string>> GetAllAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(Codes);
    }
}
