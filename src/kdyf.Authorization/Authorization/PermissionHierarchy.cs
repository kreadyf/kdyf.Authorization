namespace kdyf.Authorization.Authorization
{
    /// <summary>
    /// The rule every permission comparison follows: a granted code covers itself and every code below it, one
    /// dot-separated segment at a time. <c>fabrikam</c> covers <c>fabrikam.Controlling</c> and
    /// <c>fabrikam.Invoicing.Invoices</c>; it does not cover <c>fabrikamArchive</c>. The root <see cref="Root"/> (the
    /// empty code) covers everything, areas added later included.
    /// </summary>
    /// <remarks>
    /// <para>
    /// It replaces the wildcards <c>*</c> and <c>prefix.*</c>. A node of the tree IS the "everything under here": no
    /// second row stands for it, so a role grants <c>fabrikam</c> and nobody has to declare <c>fabrikam.*</c>. The
    /// catalog holds every node — the declared codes, their ancestors and the root (see
    /// <see cref="Abstractions.PermissionNode"/>) — so any of them can be granted.
    /// </para>
    /// <para>
    /// Holding every child never implies the parent: the parent also grants the children added later, which nobody
    /// was given. An empty set grants nothing; <c>[""]</c> grants everything. The two must never be confused.
    /// </para>
    /// <para>
    /// <b>Transition.</b> Data written before 1.2.0 can hold <c>*</c> and <c>prefix.*</c>. Reading tolerates them —
    /// <see cref="TryNormalizeStoredGrant"/> turns them into <c>""</c> and <c>prefix</c> — and writing refuses them. A
    /// post-deployment script rewrites the stored rows (docs/auth-migrate-permission-hierarchy.sql).
    /// </para>
    /// </remarks>
    public static class PermissionHierarchy
    {
        /// <summary>The whole tree. A set containing it is not an empty set: it grants everything.</summary>
        public const string Root = "";

        /// <summary>What separates the segments of a code.</summary>
        public const char Separator = '.';

        /// <summary>The legacy spelling of the root, read during the transition and never written.</summary>
        internal const string LegacyRoot = "*";

        /// <summary>The legacy suffix of an area wildcard (<c>prefix.*</c>), read during the transition.</summary>
        internal const string LegacySuffix = ".*";

        /// <summary>
        /// Whether <paramref name="code"/> is a path of the tree: the root, or segments separated by dots, none of
        /// them empty, each made of printable ASCII other than <c>*</c> (the legacy wildcard) and <c>|</c> (the
        /// any-of separator of policy names).
        /// </summary>
        /// <remarks>
        /// <c>a..b</c>, <c>.a</c>, <c>a.</c>, spaces and anything outside ASCII are refused: the column is VARCHAR,
        /// and an empty segment would make an ancestor nobody could name.
        /// </remarks>
        public static bool IsValidCode(string? code)
        {
            if (code is null)
                return false;
            if (code.Length == 0)
                return true;

            var segmentLength = 0;
            foreach (var character in code)
            {
                if (character == Separator)
                {
                    if (segmentLength == 0)
                        return false;
                    segmentLength = 0;
                }
                else if (character is > ' ' and <= '~' and not '*' and not '|')
                {
                    segmentLength++;
                }
                else
                {
                    return false;
                }
            }

            return segmentLength > 0;
        }

        /// <summary>
        /// Whether <paramref name="code"/> is written in the legacy wildcard syntax: <c>*</c> or <c>prefix.*</c>
        /// (well-formed or not). Such a code is never valid input.
        /// </summary>
        public static bool IsLegacyWildcard(string? code) => code is not null && code.Contains('*');

        /// <summary>
        /// Reads a stored grant during the transition: a valid path as it is, <c>*</c> as the root and a
        /// well-formed <c>prefix.*</c> as <c>prefix</c>. Anything else is false, and the out value must not be used.
        /// </summary>
        /// <remarks>
        /// Malformed legacy values (<c>.*</c>, <c>a..*</c>, <c>*.*</c>, a star in the middle) are refused rather
        /// than read as something broader: a typo must never widen a grant.
        /// </remarks>
        public static bool TryNormalizeStoredGrant(string? stored, out string path)
        {
            if (IsValidCode(stored))
            {
                path = stored!;
                return true;
            }

            if (stored == LegacyRoot)
            {
                path = Root;
                return true;
            }

            if (stored is not null && stored.EndsWith(LegacySuffix, StringComparison.Ordinal))
            {
                var prefix = stored[..^LegacySuffix.Length];
                if (prefix.Length > 0 && IsValidCode(prefix))
                {
                    path = prefix;
                    return true;
                }
            }

            path = Root;
            return false;
        }

        /// <summary>The stored grants as paths (see <see cref="TryNormalizeStoredGrant"/>); malformed ones grant nothing.</summary>
        public static IReadOnlySet<string> NormalizeStoredGrants(IEnumerable<string> stored)
        {
            ArgumentNullException.ThrowIfNull(stored);

            var normalized = new HashSet<string>(StringComparer.Ordinal);
            foreach (var code in stored)
                if (TryNormalizeStoredGrant(code, out var path))
                    normalized.Add(path);
            return normalized;
        }

        /// <summary>
        /// The paths that cover <paramref name="code"/>, nearest first: the code itself, each ancestor and the root.
        /// Never siblings nor descendants. Empty for an invalid code.
        /// </summary>
        /// <remarks>
        /// For the places that compare inside a database query: "does anybody hold one of these" is translatable,
        /// "does anybody hold something that covers X" is not.
        /// </remarks>
        public static IReadOnlyList<string> Covering(string code)
        {
            if (!IsValidCode(code))
                return Array.Empty<string>();

            var paths = new List<string> { code };
            for (var dot = code.LastIndexOf(Separator); dot > 0; dot = code.LastIndexOf(Separator, dot - 1))
                paths.Add(code[..dot]);
            if (code.Length > 0)
                paths.Add(Root);
            return paths;
        }

        /// <summary>The ancestors of <paramref name="code"/>, nearest first, the root last. Empty for the root and for an invalid code.</summary>
        public static IReadOnlyList<string> Ancestors(string code) => Covering(code).Skip(1).ToList();

        /// <summary>How <paramref name="path"/> was written before 1.2.0: <c>*</c> for the root, <c>prefix.*</c> for a node.</summary>
        public static string LegacySpellingOf(string path)
        {
            ArgumentNullException.ThrowIfNull(path);
            return path.Length == 0 ? LegacyRoot : path + LegacySuffix;
        }

        /// <summary>
        /// <see cref="Covering"/> plus the legacy spelling of each path (<c>*</c>, <c>prefix.*</c>): what a query over
        /// rows not yet rewritten has to look for.
        /// </summary>
        public static IReadOnlyList<string> CoveringWithLegacy(string code) =>
            Covering(code)
                .SelectMany(path => new[] { path, LegacySpellingOf(path) })
                .Distinct(StringComparer.Ordinal)
                .ToList();

        /// <summary>
        /// Whether <paramref name="granted"/> covers <paramref name="code"/>: it holds the code, one of its ancestors
        /// or the root. Legacy spellings in <paramref name="granted"/> are honoured.
        /// </summary>
        /// <remarks>
        /// This is what "holds at least as much as" means. Holding today's children of a node is NOT holding the node.
        /// </remarks>
        public static bool Covers(IReadOnlySet<string> granted, string code)
        {
            ArgumentNullException.ThrowIfNull(granted);
            return CoveringWithLegacy(code).Any(granted.Contains);
        }

        /// <summary>
        /// The effective set behind <paramref name="granted"/>: the grants, as paths, plus every code of
        /// <paramref name="catalog"/> they cover.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Expanding once, where the set is produced, keeps every reader on exact matching: the handler, the
        /// authorization endpoint, the administration screens, and the role claims of a personal access token.
        /// </para>
        /// <para>
        /// The grants themselves stay in the set, so the holder of <c>fabrikam</c> covers a role that stores
        /// <c>fabrikam</c>. Legacy spellings are normalized; malformed ones are dropped. Catalog entries that are not
        /// paths (legacy rows not yet rewritten) are never added.
        /// </para>
        /// </remarks>
        public static IReadOnlySet<string> Expand(IEnumerable<string> granted, IEnumerable<string> catalog)
        {
            ArgumentNullException.ThrowIfNull(granted);
            ArgumentNullException.ThrowIfNull(catalog);

            var normalized = NormalizeStoredGrants(granted);
            var effective = new HashSet<string>(normalized, StringComparer.Ordinal);
            if (normalized.Count == 0)
                return effective;

            foreach (var code in catalog)
                if (IsValidCode(code) && Covers(normalized, code))
                    effective.Add(code);
            return effective;
        }
    }
}
