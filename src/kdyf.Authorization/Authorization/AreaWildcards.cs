using kdyf.Authorization.Abstractions;

namespace kdyf.Authorization.Authorization
{
    /// <summary>
    /// The wildcard of an area, <c>area.*</c>. Kept for compatibility: since 1.2.0 the area's node (<c>area</c>) is in
    /// the catalog by itself and covers everything under it, so this declaration is left out of the catalog.
    /// </summary>
    [Obsolete("Area wildcards are replaced by the permission hierarchy: the area's node exists by itself and covers the area. See PermissionNode.")]
    public sealed class AreaWildcard : PermissionDefinition
    {
        /// <param name="area">The area, as the codes start with it: <c>fabrikam</c> for <c>fabrikam.Controlling</c>.</param>
        public AreaWildcard(string area)
            : base(CodeShape.Verbatim, Checked(area) + ".*", $"All {area}", $"Wildcard: everything under {area}")
        {
            Area = area;
        }

        /// <summary>The area it stands for.</summary>
        public string Area { get; }

        private static string Checked(string area)
        {
            if (string.IsNullOrWhiteSpace(area) || area.Contains('.') || area.Contains('*') || area.Any(char.IsWhiteSpace))
                throw new ArgumentException($"'{area}' is not an area: an area is the first segment of a code, without dots, stars or spaces.", nameof(area));

            return area;
        }
    }

    /// <summary>
    /// The area wildcards of 1.1.0, kept for compatibility. Since 1.2.0 every area has its node in the catalog (see
    /// <see cref="PermissionNode"/>), at every level and whatever the number of its permissions, so nothing is derived.
    /// </summary>
    [Obsolete("Area wildcards are replaced by the permission hierarchy: every area's node exists by itself. See PermissionNode.")]
    public static class AreaWildcards
    {
        /// <summary>The fewest permissions an area needed to get a wildcard in 1.1.0.</summary>
        public const int MinimumPermissions = 2;

        /// <summary>
        /// The area of <paramref name="code"/>: its first segment, or null for a code with none (<c>Default</c>) and for a
        /// legacy wildcard.
        /// </summary>
        public static string? AreaOf(string code)
        {
            ArgumentNullException.ThrowIfNull(code);
            if (PermissionHierarchy.IsLegacyWildcard(code))
                return null;

            var dot = code.IndexOf('.');
            return dot > 0 ? code[..dot] : null;
        }

        /// <summary>Nothing: the area nodes are part of the catalog already.</summary>
        public static IReadOnlyList<PermissionDefinition> Derive(IEnumerable<PermissionDefinition> declared, IEnumerable<string>? except = null)
        {
            ArgumentNullException.ThrowIfNull(declared);
            return Array.Empty<PermissionDefinition>();
        }
    }
}
