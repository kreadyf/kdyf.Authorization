using kdyf.Authorization.Abstractions;

namespace kdyf.Authorization.Authorization
{
    /// <summary>
    /// The wildcard of an area, <c>area.*</c>, derived from the permissions the host declares in it rather than
    /// declared by a class of its own. See <see cref="AreaWildcards"/>.
    /// </summary>
    /// <remarks>
    /// It has no parameterless constructor, so <see cref="PermissionDefinition.DiscoverIn"/> never finds it: it exists
    /// only when <see cref="AreaWildcards.Derive"/> creates it.
    /// </remarks>
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
            if (string.IsNullOrWhiteSpace(area) || area.Contains('.') || PermissionWildcards.IsPattern(area) || area.Any(char.IsWhiteSpace))
                throw new ArgumentException($"'{area}' is not an area: an area is the first segment of a code, without dots, stars or spaces.", nameof(area));

            return area;
        }
    }

    /// <summary>
    /// One wildcard per area, derived from the declarations: a host that declares <c>fabrikam.Controlling</c> and
    /// <c>fabrikam.Invoicing.Invoices</c> gets <c>fabrikam.*</c> without writing its class.
    /// </summary>
    /// <remarks>
    /// <para>
    /// It exists so that a new area does not depend on somebody remembering its wildcard: add the permissions, and an
    /// administrator can grant the area as a whole. The wildcard is an ordinary declaration from then on — the catalog
    /// sync writes its row, a role may grant it, <see cref="PermissionWildcards"/> expands it.
    /// </para>
    /// <para>
    /// The area is the FIRST segment of a code. A nested area (<c>fabrikam.Invoicing.*</c>) is never derived: one level
    /// is what a roles screen groups by, and every further level would put another entry there that grants more than
    /// it looks like. Declare a nested wildcard with a class when it is wanted.
    /// </para>
    /// <para>
    /// An area needs at least two permissions: the wildcard of a single one grants exactly what the permission does,
    /// and would only be a second way to say it. It appears when the second permission does.
    /// </para>
    /// <para>
    /// A wildcard declared by a class wins — its name and description are kept. An area that must not be granted as a
    /// whole (one holding a permission that is never to come through a wildcard) is excluded by name.
    /// </para>
    /// </remarks>
    public static class AreaWildcards
    {
        /// <summary>The fewest permissions an area needs to get a wildcard.</summary>
        public const int MinimumPermissions = 2;

        /// <summary>
        /// The area of <paramref name="code"/>: its first segment, or null for a code with none (<c>Default</c>) and for a
        /// pattern.
        /// </summary>
        public static string? AreaOf(string code)
        {
            ArgumentNullException.ThrowIfNull(code);
            if (PermissionWildcards.IsPattern(code))
                return null;

            var dot = code.IndexOf('.');
            return dot > 0 ? code[..dot] : null;
        }

        /// <summary>
        /// The area wildcards <paramref name="declared"/> calls for, ordered by code: one per area with at least
        /// <see cref="MinimumPermissions"/> permissions, except the areas named in <paramref name="except"/> and those
        /// whose wildcard is already declared.
        /// </summary>
        /// <param name="declared">Every permission the host declares, wildcards included.</param>
        /// <param name="except">Areas that get no wildcard. Each must be an area of <paramref name="declared"/>.</param>
        /// <exception cref="InvalidOperationException">
        /// An excluded area that does not exist (a typo would otherwise derive the very wildcard it meant to prevent),
        /// an excluded area whose wildcard a class declares anyway, or two areas — or an area and a declared wildcard —
        /// that differ only in capitalisation, which <c>auth.Permission</c>'s key could not hold apart.
        /// </exception>
        public static IReadOnlyList<PermissionDefinition> Derive(IEnumerable<PermissionDefinition> declared, IEnumerable<string>? except = null)
        {
            ArgumentNullException.ThrowIfNull(declared);

            var permissions = declared.ToList();
            var excluded = new HashSet<string>(except ?? [], StringComparer.Ordinal);

            var areas = permissions
                .Select(p => AreaOf(p.Code))
                .OfType<string>()
                .GroupBy(area => area, StringComparer.Ordinal)
                .ToDictionary(g => g.Key, g => g.Count(), StringComparer.Ordinal);

            var unknown = excluded.Where(area => !areas.ContainsKey(area)).OrderBy(area => area, StringComparer.Ordinal).ToList();
            if (unknown.Count > 0)
                throw new InvalidOperationException(
                    $"Area wildcards: excluded areas that no permission is declared in: {string.Join(", ", unknown)}. "
                    + $"The areas are: {string.Join(", ", areas.Keys.Order(StringComparer.Ordinal))}. Area names are case-sensitive.");

            var miscased = areas.Keys
                .GroupBy(area => area, StringComparer.OrdinalIgnoreCase)
                .Where(g => g.Count() > 1)
                .Select(g => string.Join(" / ", g.Order(StringComparer.Ordinal)))
                .ToList();
            if (miscased.Count > 0)
                throw new InvalidOperationException(
                    $"Area wildcards: areas that differ only in capitalisation cannot both have a wildcard row: {string.Join("; ", miscased)}.");

            var declaredCodes = permissions.Select(p => p.Code).ToHashSet(StringComparer.Ordinal);
            var derived = new List<PermissionDefinition>();

            foreach (var (area, count) in areas.OrderBy(a => a.Key, StringComparer.Ordinal))
            {
                var code = area + ".*";
                var declaredHere = declaredCodes.Contains(code);

                if (excluded.Contains(area))
                {
                    if (declaredHere)
                        throw new InvalidOperationException(
                            $"Area wildcards: '{area}' is excluded, but '{code}' is declared by a class. Remove one of the two.");
                    continue;
                }

                if (declaredHere || count < MinimumPermissions)
                    continue;

                var other = declaredCodes.FirstOrDefault(c => string.Equals(c, code, StringComparison.OrdinalIgnoreCase));
                if (other is not null)
                    throw new InvalidOperationException(
                        $"Area wildcards: '{other}' is declared, but the area is '{area}'. A wildcard matches codes case-sensitively, "
                        + "so the declared one covers nothing; correct its capitalisation.");

                derived.Add(new AreaWildcard(area));
            }

            return derived;
        }
    }
}
