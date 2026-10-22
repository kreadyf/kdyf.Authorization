using kdyf.Authorization.Authorization;

namespace kdyf.Authorization.Abstractions
{
    /// <summary>
    /// A node of the permission tree that no class declares: an ancestor of declared codes (<c>fabrikam</c> for
    /// <c>fabrikam.Controlling</c>) or the root. It exists so that it can be granted — granting it grants everything
    /// below it. See <see cref="PermissionHierarchy"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// It has no parameterless constructor, so <see cref="PermissionDefinition.DiscoverIn"/> never finds it: it exists
    /// only when <see cref="Complete"/> creates it. A class that declares the same code (with an empty code in the
    /// area's namespace) wins, and its name and description are the node's.
    /// </para>
    /// <para>
    /// The catalog sync inserts its row but never overwrites the row's name or description: an implicit node owns no
    /// metadata, so a label somebody gave it by hand stays.
    /// </para>
    /// </remarks>
    public sealed class PermissionNode : PermissionDefinition
    {
        /// <summary>The name of the root.</summary>
        public const string RootName = "Everything";

        /// <param name="code">The node's code: a valid path, or <see cref="PermissionHierarchy.Root"/>.</param>
        public PermissionNode(string code)
            : base(CodeShape.Verbatim, Checked(code), NameOf(code), DescriptionOf(code)) { }

        private static string Checked(string code)
        {
            if (!PermissionHierarchy.IsValidCode(code))
                throw new ArgumentException($"'{code}' is not a permission path.", nameof(code));
            return code;
        }

        private static string NameOf(string code) => code.Length == 0 ? RootName : code;

        private static string DescriptionOf(string code) =>
            code.Length == 0
                ? "All permissions, including those added later."
                : $"Everything under {code}, including permissions added later.";

        /// <summary>
        /// The declarations completed into a tree: each one as it is, plus every ancestor and the root that no class
        /// declares, ordered by code. Legacy wildcard declarations (<c>*</c>, <c>prefix.*</c>) are left out — a node
        /// already stands for everything under it — and returned in <paramref name="ignored"/>.
        /// </summary>
        /// <exception cref="InvalidOperationException">
        /// A declared code that is not a path, or two paths that differ only in capitalisation, which
        /// <c>auth.Permission</c>'s key could not hold apart.
        /// </exception>
        public static IReadOnlyList<PermissionDefinition> Complete(
            IEnumerable<PermissionDefinition> declared, out IReadOnlyList<string> ignored)
        {
            ArgumentNullException.ThrowIfNull(declared);

            var legacy = new List<string>();
            var invalid = new List<string>();
            var nodes = new Dictionary<string, PermissionDefinition>(StringComparer.OrdinalIgnoreCase);
            var miscased = new List<string>();

            foreach (var permission in declared)
            {
                if (PermissionHierarchy.IsLegacyWildcard(permission.Code))
                    legacy.Add(permission.Code);
                else if (!PermissionHierarchy.IsValidCode(permission.Code))
                    invalid.Add($"'{permission.Code}'");
                else if (!nodes.TryAdd(permission.Code, permission) && !ReferenceEquals(nodes[permission.Code], permission))
                    miscased.Add($"{nodes[permission.Code].Code} / {permission.Code}");
            }

            if (invalid.Count > 0)
                throw new InvalidOperationException(
                    $"These permission codes are not paths of the permission tree: {string.Join(", ", invalid)}. "
                    + "A code is dot-separated segments of printable ASCII, without empty segments, spaces, '*' or '|'.");

            foreach (var code in nodes.Keys.ToList())
            {
                foreach (var ancestor in PermissionHierarchy.Ancestors(code))
                {
                    if (nodes.TryGetValue(ancestor, out var existing))
                    {
                        if (!string.Equals(existing.Code, ancestor, StringComparison.Ordinal))
                            miscased.Add($"{existing.Code} / {ancestor} (ancestor of {code})");
                        continue;
                    }

                    nodes.Add(ancestor, new PermissionNode(ancestor));
                }
            }

            nodes.TryAdd(PermissionHierarchy.Root, new PermissionNode(PermissionHierarchy.Root));

            if (miscased.Count > 0)
                throw new InvalidOperationException(
                    "These permission paths are declared twice or differ only in capitalisation, which auth.Permission's key cannot hold apart: "
                    + string.Join("; ", miscased.Distinct(StringComparer.Ordinal)) + ".");

            ignored = legacy.Distinct(StringComparer.Ordinal).OrderBy(c => c, StringComparer.Ordinal).ToList();
            return nodes.Values.OrderBy(p => p.Code, StringComparer.Ordinal).ToList();
        }
    }
}
