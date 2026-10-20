using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace kdyf.Authorization.Migrations.Legacy
{
    /// <summary>A legacy role: its numeric id and its name.</summary>
    internal sealed record LegacyRole(int RoleId, string Name, string? Description = null);

    /// <summary>
    /// Gives each legacy role (numeric <c>RoleId</c>) the <c>roleValue</c> it has in the new schema: deterministic, stable
    /// across runs, never merging two roles.
    /// </summary>
    /// <remarks>
    /// <list type="number">
    /// <item>A role already mapped (<c>LegacyRoleMap</c>) keeps its value, forever: the map is never rewritten.</item>
    /// <item>An override (<c>RoleId → roleValue</c>, frozen before the first copy) is used as given, once validated.</item>
    /// <item>Otherwise the value is generated from the name: NFKD without diacritics, lower case; every run of characters
    /// other than <c>a-z 0-9 .</c> becomes <c>-</c>; trimmed; at most 90 characters; <c>role-</c> in front when it does
    /// not start with a letter (a role value must); <c>role-{RoleId}</c> when nothing is left.</item>
    /// <item>A value taken already (by the map, an override or an earlier role, ignoring case) gets <c>-{RoleId}</c>.</item>
    /// </list>
    /// Changing an override after a copy is a rename, an explicit step of its own: here it is an error.
    /// </remarks>
    public static partial class LegacyRoleValues
    {
        /// <summary>The longest value generated from a name, before a <c>-{RoleId}</c> suffix.</summary>
        public const int MaxGeneratedLength = 90;

        [GeneratedRegex("^[A-Za-z][A-Za-z0-9._-]{0,99}$")]
        private static partial Regex Shape();

        [GeneratedRegex("[^a-z0-9.]+")]
        private static partial Regex NotAllowed();

        /// <summary>The value a name generates, before collisions are resolved.</summary>
        public static string Generate(string name, int roleId)
        {
            var decomposed = (name ?? string.Empty).Normalize(NormalizationForm.FormKD);
            var plain = new StringBuilder(decomposed.Length);
            foreach (var c in decomposed)
                if (CharUnicodeInfo.GetUnicodeCategory(c) != UnicodeCategory.NonSpacingMark)
                    plain.Append(c);

            var value = NotAllowed().Replace(plain.ToString().ToLowerInvariant(), "-").Trim('-', '.');
            if (value.Length > MaxGeneratedLength)
                value = value[..MaxGeneratedLength].Trim('-', '.');
            if (value.Length == 0)
                return $"role-{roleId}";
            return char.IsAsciiLetterLower(value[0]) ? value : $"role-{value}";
        }

        /// <summary>
        /// The value of every role: <paramref name="mapped"/> first, then <paramref name="overrides"/>, then generated, in
        /// <c>RoleId</c> order. Throws, with every problem listed, when an override is invalid, collides, or renames a
        /// role already mapped.
        /// </summary>
        internal static IReadOnlyDictionary<int, string> Assign(
            IEnumerable<LegacyRole> roles,
            IReadOnlyDictionary<int, string>? mapped = null,
            IReadOnlyDictionary<int, string>? overrides = null)
        {
            mapped ??= new Dictionary<int, string>();
            overrides ??= new Dictionary<int, string>();
            var problems = new List<string>();

            foreach (var (roleId, value) in overrides)
            {
                if (!Shape().IsMatch(value))
                    problems.Add($"override {roleId} → '{value}': a role value starts with a letter and has only letters, digits, '.', '_' and '-' (at most 100).");
                if (mapped.TryGetValue(roleId, out var current) && !string.Equals(current, value, StringComparison.Ordinal))
                    problems.Add($"override {roleId} → '{value}': the role was copied as '{current}'. Renaming it is an explicit step, not an override.");
            }

            var result = new Dictionary<int, string>(mapped);
            var taken = new HashSet<string>(mapped.Values, StringComparer.OrdinalIgnoreCase);

            foreach (var (roleId, value) in overrides.Where(o => !mapped.ContainsKey(o.Key)).OrderBy(o => o.Key))
            {
                if (!taken.Add(value))
                    problems.Add($"override {roleId} → '{value}': the value is taken by another role (compared ignoring case).");
                result[roleId] = value;
            }

            if (problems.Count > 0)
                throw new InvalidOperationException("The role values cannot be assigned: " + string.Join(" ", problems));

            foreach (var role in roles.Where(r => !result.ContainsKey(r.RoleId)).OrderBy(r => r.RoleId))
            {
                var value = Generate(role.Name, role.RoleId);
                if (!taken.Add(value))
                {
                    value = $"{value[..Math.Min(value.Length, MaxGeneratedLength)]}-{role.RoleId}";
                    if (!taken.Add(value))
                        throw new InvalidOperationException($"Role {role.RoleId} '{role.Name}': '{value}' is taken too. Give it an override.");
                }
                result[role.RoleId] = value;
            }

            return result;
        }
    }
}
