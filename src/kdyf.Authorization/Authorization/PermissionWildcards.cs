namespace kdyf.Authorization.Authorization
{
    /// <summary>
    /// Turns the patterns a role may grant — <c>*</c> and <c>prefix.*</c> — into the real permission
    /// codes they stand for.
    /// </summary>
    /// <remarks>
    /// <para>
    /// It exists so that an administrator role can hold a whole area without anybody having to
    /// remember to add each new code to it. Resolving here rather than in the authorization handler
    /// is deliberate: the handler is only ONE reader of the effective set. The same set is answered
    /// to the client by the authorization endpoint, compared against by the administration screens,
    /// and turned into role claims for personal access tokens — all of which do exact string
    /// matching. Expanding once, where the set is produced, keeps every one of them unchanged.
    /// </para>
    /// <para>
    /// A pattern NEVER expands onto another pattern: the target set is only the catalog entries that
    /// are plain codes. Otherwise <c>*</c> would drag <c>prefix.*</c> in with it and an effective set
    /// would contain patterns where consumers expect codes.
    /// </para>
    /// </remarks>
    public static class PermissionWildcards
    {
        /// <summary>The pattern that stands for every permission in the catalog.</summary>
        public const string All = "*";

        private const char Star = '*';

        /// <summary>
        /// True for a granted code that is a pattern rather than a permission.
        /// </summary>
        /// <remarks>
        /// Any <c>*</c> makes it a pattern. A star in the middle of a code is not a wildcard syntax
        /// this package supports — it is a configuration mistake, and treating it as a pattern that
        /// matches nothing surfaces it as "no access" rather than as a silent exact-match failure.
        /// </remarks>
        public static bool IsPattern(string code) => code.IndexOf(Star) >= 0;

        /// <summary>Whether expansion is needed at all — the cheap check that spares the catalog
        /// read for everybody who holds no pattern, which is nearly everybody.</summary>
        public static bool ContainsPattern(IEnumerable<string> codes) => codes.Any(IsPattern);

        /// <summary>
        /// The effective codes behind <paramref name="granted"/>.
        /// </summary>
        /// <param name="granted">What the roles grant, patterns included.</param>
        /// <param name="catalog">Every known permission code (<see cref="Abstractions.IPermissionCatalog"/>).</param>
        /// <returns>
        /// The plain codes from <paramref name="granted"/>, everything the patterns match, AND the
        /// patterns themselves.
        /// <para>
        /// Keeping the patterns matters: an administration screen decides whether a role may be
        /// handed out by asking whether the role's stored codes are a subset of the caller's
        /// effective set. The role that grants <c>*</c> stores <c>*</c> — so without the pattern in
        /// the set, the one person who may hand out everything could not see the role that does it.
        /// </para>
        /// </returns>
        public static IReadOnlySet<string> Expand(IReadOnlySet<string> granted, IReadOnlySet<string> catalog)
        {
            if (!ContainsPattern(granted))
                return granted;

            var expanded = new HashSet<string>(granted, StringComparer.Ordinal);

            foreach (var pattern in granted.Where(IsPattern))
            {
                if (pattern == All)
                {
                    foreach (var code in catalog.Where(c => !IsPattern(c)))
                        expanded.Add(code);

                    continue;
                }

                // "prefix.*" — the dot belongs to the prefix, so 'contoso.*' does not reach
                // 'contosoX.Foo'. Depth beyond it is unrestricted: 'fabrikam.*' covers
                // 'fabrikam.Invoicing.Invoices'.
                if (!pattern.EndsWith(".*", StringComparison.Ordinal))
                    continue;

                var prefix = pattern[..^1];

                foreach (var code in catalog)
                {
                    if (!IsPattern(code) && code.StartsWith(prefix, StringComparison.Ordinal))
                        expanded.Add(code);
                }
            }

            return expanded;
        }

        /// <summary>
        /// The patterns that would cover <paramref name="code"/> — itself, <c>*</c>, and every
        /// <c>prefix.*</c> along its dots.
        /// </summary>
        /// <remarks>
        /// For the places that cannot expand because they compare inside a database query. Turning
        /// "does anybody hold X" into "does anybody hold one of these" keeps the comparison
        /// translatable while staying wildcard-aware.
        /// </remarks>
        public static IReadOnlyList<string> Covering(string code)
        {
            var covering = new List<string> { code, All };

            for (var i = code.IndexOf('.'); i >= 0; i = code.IndexOf('.', i + 1))
                covering.Add(string.Concat(code.AsSpan(0, i + 1), "*"));

            return covering;
        }

        /// <summary>
        /// Whether <paramref name="granted"/> covers <paramref name="code"/> — which may itself be a
        /// pattern.
        /// </summary>
        /// <remarks>
        /// <para>
        /// This is what "holds at least as much as" means, and plain set containment is NOT it. A
        /// role that grants everything stores <c>*</c>; a role that grants all of one area stores
        /// <c>prefix.*</c>. Expansion deliberately never turns one pattern into another, so the
        /// holder of <c>*</c> does not literally have <c>fabrikam.*</c> in their set — and a raw
        /// subset test would conclude that the person who can do everything cannot do what somebody
        /// with one area can. That is exactly the wrong answer, and it is the one that refused a
        /// full administrator the right to simulate a lesser one.
        /// </para>
        /// <para>
        /// Asking whether ANY covering pattern is held gets it right in both directions and needs no
        /// catalog.
        /// </para>
        /// </remarks>
        public static bool Covers(IReadOnlySet<string> granted, string code) =>
            Covering(code).Any(granted.Contains);
    }
}
