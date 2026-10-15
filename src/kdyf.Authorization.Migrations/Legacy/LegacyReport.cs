using System.Text;
using kdyf.Authorization.Migrations.Schema;

namespace kdyf.Authorization.Migrations.Legacy
{
    /// <summary>One thing found in the legacy data, with how much it matters for the import.</summary>
    public sealed record LegacyFinding(IssueSeverity Severity, string Code, string Message)
    {
        public override string ToString() => $"{Severity.ToString().ToUpperInvariant()} {Code}: {Message}";
    }

    /// <summary>What a role becomes: its value in the new schema, who holds it and what it grants.</summary>
    public sealed record LegacyRolePlan(int RoleId, string Name, string RoleValue, int Holders, int Grants);

    /// <summary>
    /// The read-only report of a legacy schema before anything is imported: its shape, its numbers, what each role will
    /// be called, and every row the import will have to decide about. Nothing in it is written anywhere.
    /// </summary>
    /// <remarks>People are named by their legacy id, never by e-mail: the report may be shared.</remarks>
    public sealed class LegacyReport
    {
        private LegacyReport(LegacyData data, IReadOnlyList<LegacyRolePlan> roles, IReadOnlyList<LegacyFinding> findings)
        {
            Data = data;
            Roles = roles;
            Findings = findings;
        }

        public LegacyData Data { get; }

        public IReadOnlyList<LegacyRolePlan> Roles { get; }

        public IReadOnlyList<LegacyFinding> Findings { get; }

        public bool HasBlockers => Findings.Any(f => f.Severity == IssueSeverity.Blocker);

        public static LegacyReport Build(LegacyData data, IReadOnlyDictionary<int, string>? overrides = null)
        {
            var findings = new List<LegacyFinding>();
            void Add(IssueSeverity severity, string code, string message) => findings.Add(new(severity, code, message));
            static string Ids(IEnumerable<int> ids) => string.Join(", ", ids.OrderBy(i => i).Take(20)) + (ids.Count() > 20 ? ", …" : "");

            var users = data.Users.ToDictionary(u => u.UserId);
            var roleIds = data.Roles.Select(r => r.RoleId).ToHashSet();
            var heldBy = data.UserRoles.Where(ur => users.ContainsKey(ur.UserId) && roleIds.Contains(ur.RoleId)).ToLookup(ur => ur.UserId, ur => ur.RoleId);

            // ── People ──
            var withoutObjectId = data.Users.Where(u => string.IsNullOrWhiteSpace(u.ObjectId)).ToList();
            if (withoutObjectId.Count > 0)
                Add(IssueSeverity.Warning, "user-without-object-id",
                    $"{withoutObjectId.Count} user(s) have no object id ({withoutObjectId.Count(u => heldBy[u.UserId].Any())} with roles, "
                    + $"{data.Tokens.Count(t => withoutObjectId.Any(u => u.UserId == t.UserId))} token(s)): resolved by e-mail in Entra, or their "
                    + $"roles and tokens are lost unless approved. Users {Ids(withoutObjectId.Select(u => u.UserId))}.");

            var invalid = data.Users.Where(u => !string.IsNullOrWhiteSpace(u.ObjectId) && !Guid.TryParse(u.ObjectId, out _)).ToList();
            if (invalid.Count > 0)
                Add(IssueSeverity.Warning, "user-invalid-object-id", $"{invalid.Count} user(s) have an object id that is not a GUID: resolved by e-mail. Users {Ids(invalid.Select(u => u.UserId))}.");

            var unnormalized = data.Users.Where(u => Guid.TryParse(u.ObjectId, out var g) && u.ObjectId != g.ToString()).ToList();
            if (unnormalized.Count > 0)
                Add(IssueSeverity.Info, "user-object-id-format", $"{unnormalized.Count} object id(s) in upper case or with braces: normalised on import.");

            foreach (var group in data.Users.Where(u => Guid.TryParse(u.ObjectId, out _)).GroupBy(u => Guid.Parse(u.ObjectId!)).Where(g => g.Count() > 1))
                Add(IssueSeverity.Blocker, "duplicate-object-id",
                    $"users {Ids(group.Select(u => u.UserId))} share one object id: merging their roles would give each more than before. Needs an approval.");

            foreach (var group in data.Users.GroupBy(u => u.Email.Trim().ToLowerInvariant()).Where(g => g.Count() > 1))
            {
                var distinct = group.Select(u => Guid.TryParse(u.ObjectId, out var g) ? g.ToString() : null).Where(o => o is not null).Distinct().Count();
                Add(distinct > 1 ? IssueSeverity.Blocker : IssueSeverity.Warning, "duplicate-email",
                    $"users {Ids(group.Select(u => u.UserId))} share one e-mail{(distinct > 1 ? " with different object ids: the import stops" : "")}.");
            }

            var inactive = data.Users.Count(u => !u.IsActive);
            if (inactive > 0)
                Add(IssueSeverity.Info, "user-inactive", $"{inactive} inactive user(s): imported suspended, with their roles.");

            // In the packages every member of the gate holds the base access; in the legacy schema a user whose roles
            // grant nothing holds nothing. Importing them as they are is a gain (finding 9 of the plan).
            var granting = data.Grants.Select(g => g.RoleId).ToHashSet();
            var nothing = data.Users.Where(u => u.IsActive && !heldBy[u.UserId].Any(granting.Contains)).ToList();
            if (nothing.Count > 0)
                Add(IssueSeverity.Warning, "user-without-permissions",
                    $"{nothing.Count} active user(s) hold no role that grants anything: today they can do nothing; as members of the access gate they would "
                    + $"get the base access. Keep them out of the gate, or approve it. Users {Ids(nothing.Select(u => u.UserId))}.");

            // ── Roles ──
            IReadOnlyDictionary<int, string> values;
            try
            {
                values = LegacyRoleValues.Assign(data.Roles, overrides: overrides);
            }
            catch (InvalidOperationException ex)
            {
                Add(IssueSeverity.Blocker, "role-values", ex.Message);
                values = LegacyRoleValues.Assign(data.Roles);
            }
            var roles = data.Roles.OrderBy(r => r.RoleId).Select(r => new LegacyRolePlan(
                r.RoleId, r.Name, values[r.RoleId],
                data.UserRoles.Count(ur => ur.RoleId == r.RoleId && users.ContainsKey(ur.UserId)),
                data.Grants.Count(g => g.RoleId == r.RoleId))).ToList();

            foreach (var role in roles.Where(r => r.Holders > 0 && r.Grants == 0))
                Add(IssueSeverity.Info, "role-grants-nothing", $"role {role.RoleId} '{role.Name}' is held by {role.Holders} and grants nothing.");

            foreach (var group in data.Roles.GroupBy(r => r.Name.Trim(), StringComparer.OrdinalIgnoreCase).Where(g => g.Count() > 1))
                Add(IssueSeverity.Warning, "role-similar-names", $"roles {Ids(group.Select(r => r.RoleId))} differ only in case or spaces ('{group.Key}'): kept as separate roles.");

            // ── What roles grant ──
            var codes = data.Grants.Select(g => g.PermissionCode).Distinct(StringComparer.Ordinal).OrderBy(c => c, StringComparer.Ordinal).ToList();
            var wildcards = codes.Where(c => c == "*" || c.EndsWith(".*", StringComparison.Ordinal)).ToList();
            if (wildcards.Count > 0)
                Add(IssueSeverity.Info, "wildcards", $"granted as they are, never expanded: {string.Join(", ", wildcards)}.");

            var latin1 = Encoding.Latin1;
            var unrepresentable = codes.Where(c => latin1.GetString(latin1.GetBytes(c)) != c || c.Any(char.IsControl)).ToList();
            if (unrepresentable.Count > 0)
                Add(IssueSeverity.Blocker, "code-not-representable", $"codes that do not survive varchar: {string.Join(", ", unrepresentable)}.");

            var tooLong = codes.Where(c => c.Length > 50).ToList();
            if (tooLong.Count > 0)
                Add(IssueSeverity.Blocker, "code-too-long", $"codes longer than 50: {string.Join(", ", tooLong)}.");

            foreach (var group in codes.GroupBy(c => c, StringComparer.OrdinalIgnoreCase).Where(g => g.Count() > 1))
                Add(IssueSeverity.Warning, "code-case", $"codes that differ only in case: {string.Join(", ", group)}. The new schema compares them exactly.");

            var catalog = data.CatalogCodes.ToHashSet(StringComparer.Ordinal);
            var notInCatalog = codes.Where(c => !catalog.Contains(c)).ToList();
            if (notInCatalog.Count > 0)
                Add(IssueSeverity.Warning, "code-not-in-catalog", $"granted but not in the legacy catalog: {string.Join(", ", notInCatalog)}.");

            var orphanGrants = data.Grants.Count(g => !roleIds.Contains(g.RoleId));
            if (orphanGrants > 0)
                Add(IssueSeverity.Warning, "grant-without-role", $"{orphanGrants} grant(s) of a role that does not exist: not imported.");

            var orphanHolders = data.UserRoles.Count(ur => !users.ContainsKey(ur.UserId) || !roleIds.Contains(ur.RoleId));
            if (orphanHolders > 0)
                Add(IssueSeverity.Warning, "user-role-orphan", $"{orphanHolders} user-role row(s) point at a user or role that does not exist: not imported.");

            Add(IssueSeverity.Info, "codes", $"{codes.Count} distinct codes granted. Those the host does not declare grant nothing after the import (they are reported per person).");

            // ── Tokens ──
            foreach (var token in data.Tokens)
            {
                if (!users.TryGetValue(token.UserId, out var owner))
                    Add(IssueSeverity.Warning, "token-without-owner", $"token {token.Id} belongs to user {token.UserId}, who does not exist: imported inactive.");
                else if (string.IsNullOrWhiteSpace(owner.ObjectId))
                    Add(IssueSeverity.Warning, "token-owner-without-object-id",
                        $"token {token.Id}{(token.IsActive ? " (active)" : "")} belongs to user {owner.UserId}, who has no object id: it dies unless the owner is resolved.");
                else if (!owner.IsActive && token.IsActive)
                    Add(IssueSeverity.Info, "token-owner-inactive", $"token {token.Id} is active but its owner {owner.UserId} is not: it grants nothing, as today.");
            }
            // Shape B: a token limited to some of its owner's roles. In the new schema a token holds what its owner holds,
            // so importing it as it is would widen it.
            foreach (var group in data.TokenRoles.GroupBy(tr => tr.TokenId))
            {
                var token = data.Tokens.FirstOrDefault(t => t.Id == group.Key);
                if (token is null)
                    continue;
                var ownerRoles = heldBy[token.UserId].ToHashSet();
                var limited = ownerRoles.Except(group.Select(tr => tr.RoleId)).Any();
                if (limited)
                    Add(token.IsActive ? IssueSeverity.Blocker : IssueSeverity.Warning, "token-limited-to-roles",
                        $"token {token.Id} is limited to roles {Ids(group.Select(tr => tr.RoleId))} of its owner's {Ids(ownerRoles)}: "
                        + "imported, it would hold all of them. Import it inactive, or approve the widening.");
            }

            if (data.Tokens.Count > 0)
                Add(IssueSeverity.Info, "tokens",
                    $"{data.Tokens.Count} token(s), {data.Tokens.Count(t => t.IsActive)} active. After the import a token is worth what its owner holds through the access "
                    + "gate: tokens of people outside it stop working.");

            // ── The rest ──
            Add(IssueSeverity.Info, "audit-log", $"{data.AuditLogCount} audit entries (last id {data.AuditLogMaxId?.ToString() ?? "-"}): copied as they are.");

            foreach (var reference in data.ExternalReferences)
                Add(reference.Kind.StartsWith("foreign key", StringComparison.Ordinal) ? IssueSeverity.Blocker : IssueSeverity.Warning, "external-reference",
                    $"{reference.Table}.{reference.Column} ({reference.Kind}) may point at legacy ids: it needs a host step, or confirm it does not.");

            return new LegacyReport(data, roles, findings);
        }

        public string ToText(LegacyShape shape)
        {
            var text = new StringBuilder();
            text.AppendLine($"Legacy shape {shape.Label}: {shape.Description}");
            foreach (var note in shape.Notes)
                text.AppendLine($"  {note}");
            text.AppendLine($"Users {Data.Users.Count} · roles {Data.Roles.Count} · grants {Data.Grants.Count} · user-roles {Data.UserRoles.Count} · tokens {Data.Tokens.Count} · audit {Data.AuditLogCount}");
            text.AppendLine();
            text.AppendLine("Roles (RoleId → roleValue, holders, grants):");
            foreach (var role in Roles)
                text.AppendLine($"  {role.RoleId,5} {role.Name,-35} → {role.RoleValue,-35} {role.Holders,4} {role.Grants,4}");
            text.AppendLine();
            foreach (var finding in Findings.OrderByDescending(f => f.Severity == IssueSeverity.Blocker).ThenBy(f => f.Severity))
                text.AppendLine(finding.ToString());
            text.AppendLine();
            text.AppendLine(HasBlockers ? "Blockers stand: the import would not start." : "No blockers in the data.");
            return text.ToString();
        }
    }
}
