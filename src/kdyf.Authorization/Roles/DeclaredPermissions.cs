using kdyf.Authorization.Abstractions;

namespace kdyf.Authorization.Roles
{
    /// <summary>
    /// The permissions the application declares in code: the only codes a role can be configured to grant.
    /// </summary>
    /// <remarks>
    /// Permissions stay in code because the doors (policies) that demand them are code: a permission
    /// created from a screen would be demanded by no endpoint. What is configurable is which role grants
    /// which of these — see <see cref="IRolePermissionSource"/>.
    /// </remarks>
    public sealed class DeclaredPermissions : IPermissionCatalog
    {
        private readonly Dictionary<string, PermissionDefinition> _byCode;

        /// <param name="permissions">The application's declarations, usually from <see cref="PermissionDefinition.DiscoverIn(System.Reflection.Assembly)"/>.</param>
        /// <exception cref="ArgumentException">Two declarations share a code.</exception>
        public DeclaredPermissions(IEnumerable<PermissionDefinition> permissions)
        {
            Permissions = permissions.OrderBy(p => p.Code, StringComparer.Ordinal).ToList();
            _byCode = Permissions.ToDictionary(p => p.Code, StringComparer.Ordinal);
            Codes = _byCode.Keys.ToHashSet(StringComparer.Ordinal);
        }

        /// <summary>Every declared permission, patterns included, ordered by code.</summary>
        public IReadOnlyList<PermissionDefinition> Permissions { get; }

        /// <summary>Every declared code: what wildcards expand against, and what a role may be given.</summary>
        public IReadOnlySet<string> Codes { get; }

        /// <summary>The declaration of this exact code, or null.</summary>
        public PermissionDefinition? Find(string code) =>
            code is not null && _byCode.TryGetValue(code, out var permission) ? permission : null;

        /// <summary>The declared <see cref="Codes"/>; never reads a store.</summary>
        public Task<IReadOnlySet<string>> GetAllAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(Codes);
    }
}
