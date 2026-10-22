using kdyf.Authorization.Authorization;

namespace kdyf.Authorization.Roles
{
    /// <summary>
    /// A snapshot of the roles, what each one grants, and what every member of the access group holds without
    /// any role; plus the rules that read it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Only DECLARED codes count — the declared tree, ancestors and root included. A stored code nobody declares any
    /// more (renamed, removed) grants nothing: no door demands it, and a node only ever expands to declared codes. It
    /// is reported, not trusted.
    /// </para>
    /// <para>
    /// Stored grants are read as paths (<see cref="PermissionHierarchy.NormalizeStoredGrants"/>): a role still storing
    /// the legacy <c>*</c> or <c>prefix.*</c> grants the root or <c>prefix</c> until the rows are rewritten.
    /// </para>
    /// </remarks>
    public sealed class RolePermissionMap
    {
        private static readonly IReadOnlySet<string> None = new HashSet<string>(StringComparer.Ordinal);

        private readonly IReadOnlyDictionary<string, IReadOnlySet<string>> _grants;
        private readonly IReadOnlySet<string> _declared;
        private readonly IReadOnlySet<string> _memberGrants;

        /// <param name="grants">Every role, with what it grants as stored (legacy spellings are read as paths).</param>
        /// <param name="declared">The declared permission codes: the whole tree.</param>
        /// <param name="memberGrants">What being a member of the access group grants by itself (the base
        /// access). Only declared codes are kept.</param>
        public RolePermissionMap(
            IReadOnlyDictionary<string, IReadOnlySet<string>> grants,
            IReadOnlySet<string> declared,
            IEnumerable<string>? memberGrants = null)
        {
            // Ordinal: a role value is compared exactly, as it is stored.
            _grants = grants.ToDictionary(g => g.Key, g => PermissionHierarchy.NormalizeStoredGrants(g.Value), StringComparer.Ordinal);
            _declared = declared;
            _memberGrants = (memberGrants ?? Array.Empty<string>()).Where(declared.Contains).ToHashSet(StringComparer.Ordinal);
        }

        /// <summary>Every role that exists, ordered.</summary>
        public IReadOnlyList<string> Roles => _grants.Keys.OrderBy(r => r, StringComparer.Ordinal).ToList();

        /// <summary>Whether the role exists.</summary>
        public bool Exists(string role) => role is not null && _grants.ContainsKey(role);

        /// <summary>What every member holds without any role, as declared codes.</summary>
        public IReadOnlySet<string> MemberGrants => _memberGrants;

        /// <summary>What the role is configured to grant, as paths (undeclared codes included, malformed legacy values left out).</summary>
        public IReadOnlySet<string> GrantsOf(string role) =>
            role is not null && _grants.TryGetValue(role, out var codes) ? codes : None;

        /// <summary>Stored codes that no longer match a declaration, per role. They grant nothing.</summary>
        public IReadOnlyDictionary<string, IReadOnlyList<string>> Undeclared =>
            _grants
                .Select(g => (Role: g.Key, Codes: g.Value.Where(c => !_declared.Contains(c)).OrderBy(c => c, StringComparer.Ordinal).ToList()))
                .Where(g => g.Codes.Count > 0)
                .ToDictionary(g => g.Role, g => (IReadOnlyList<string>)g.Codes, StringComparer.Ordinal);

        /// <summary>
        /// What <paramref name="roles"/> grant: the union of their declared grants, each node expanded to the declared
        /// codes below it (and kept). Without the member grants: this answers "what do these roles add".
        /// </summary>
        public IReadOnlySet<string> EffectivePermissions(IEnumerable<string> roles)
        {
            var granted = new HashSet<string>(StringComparer.Ordinal);
            foreach (var role in roles)
                granted.UnionWith(GrantsOf(role).Where(_declared.Contains));

            return PermissionHierarchy.Expand(granted, _declared);
        }

        /// <summary>
        /// The EFFECTIVE permissions of a member of the access group holding <paramref name="roles"/>: what every
        /// member holds, plus what their roles grant. Somebody outside the group holds nothing — that is the
        /// caller's to check.
        /// </summary>
        public IReadOnlySet<string> ForMember(IEnumerable<string> roles)
        {
            var granted = new HashSet<string>(_memberGrants, StringComparer.Ordinal);
            foreach (var role in roles)
                granted.UnionWith(GrantsOf(role).Where(_declared.Contains));

            return PermissionHierarchy.Expand(granted, _declared);
        }

        /// <summary>The same map with <paramref name="role"/> granting <paramref name="codes"/> instead: what a change would leave.</summary>
        public RolePermissionMap With(string role, IEnumerable<string> codes)
        {
            var grants = _grants.ToDictionary(g => g.Key, g => g.Value, StringComparer.Ordinal);
            grants[role] = codes.ToHashSet(StringComparer.Ordinal);
            return new RolePermissionMap(grants, _declared, _memberGrants);
        }

        /// <summary>
        /// Whether somebody holding <paramref name="held"/> may hand this role out, or take it away:
        /// everything it grants is covered by what they hold. Nobody gives away more than they have.
        /// </summary>
        public bool IsCoveredBy(string role, IReadOnlySet<string> held) =>
            GrantsOf(role).Where(_declared.Contains).All(code => PermissionHierarchy.Covers(held, code));
    }
}
