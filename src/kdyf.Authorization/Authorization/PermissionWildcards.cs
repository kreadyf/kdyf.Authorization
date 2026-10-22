namespace kdyf.Authorization.Authorization
{
    /// <summary>
    /// The wildcards <c>*</c> and <c>prefix.*</c>, kept for compatibility. Since 1.2.0 a node of the permission tree
    /// covers everything under it, and every member here answers with <see cref="PermissionHierarchy"/>: <c>*</c> reads
    /// as the root, <c>prefix.*</c> as <c>prefix</c>.
    /// </summary>
    [Obsolete("Wildcards are replaced by the permission hierarchy: grant the node ('' for everything, 'prefix' for an area). See PermissionHierarchy.")]
    public static class PermissionWildcards
    {
        /// <summary>The legacy spelling of the root.</summary>
        public const string All = PermissionHierarchy.LegacyRoot;

        /// <summary>Whether <paramref name="code"/> is written in the legacy wildcard syntax.</summary>
        public static bool IsPattern(string code) => PermissionHierarchy.IsLegacyWildcard(code);

        /// <summary>Whether any of <paramref name="codes"/> is written in the legacy wildcard syntax.</summary>
        public static bool ContainsPattern(IEnumerable<string> codes) => codes.Any(PermissionHierarchy.IsLegacyWildcard);

        /// <summary><see cref="PermissionHierarchy.Expand"/>.</summary>
        public static IReadOnlySet<string> Expand(IReadOnlySet<string> granted, IReadOnlySet<string> catalog) =>
            PermissionHierarchy.Expand(granted, catalog);

        /// <summary><see cref="PermissionHierarchy.CoveringWithLegacy"/>: the paths that cover the code, with their legacy spellings.</summary>
        public static IReadOnlyList<string> Covering(string code) => PermissionHierarchy.CoveringWithLegacy(code);

        /// <summary><see cref="PermissionHierarchy.Covers"/>.</summary>
        public static bool Covers(IReadOnlySet<string> granted, string code) => PermissionHierarchy.Covers(granted, code);
    }
}
