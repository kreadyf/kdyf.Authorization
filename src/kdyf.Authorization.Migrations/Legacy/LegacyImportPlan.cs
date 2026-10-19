using kdyf.Authorization.Migrations.Schema;

namespace kdyf.Authorization.Migrations.Legacy
{
    public sealed record TargetRole(int LegacyRoleId, string RoleValue, string Name, string? Description);

    public sealed record TargetGrant(string RoleValue, string PermissionCode);

    public sealed record TargetProfile(string ObjectId, int LegacyUserId, string Email, string? DisplayName, bool IsActive, DateTime CreatedAt);

    public sealed record TargetUserRole(string ObjectId, string RoleValue);

    public sealed record TargetToken(
        int LegacyId, byte[] TokenHash, string Name, string? TokenPrefix, string OwnerObjectId, string OwnerLabel, bool IsActive,
        DateTime? ExpiresAt, DateTime CreatedAt, DateTime? LastUsedAt);

    /// <summary>Something the import decided, or refuses to decide alone. Kept in <c>MigrationIssue</c>, by legacy id.</summary>
    public sealed record ImportIssue(IssueSeverity Severity, string Code, int? LegacyUserId, string Detail)
    {
        public override string ToString() => $"{Severity.ToString().ToUpperInvariant()} {Code}{(LegacyUserId is null ? "" : $" (user {LegacyUserId})")}: {Detail}";
    }

    /// <summary>The choices of the import that are not in the data.</summary>
    public sealed class LegacyImportSettings
    {
        /// <summary>
        /// The legacy role given to everybody who signed in (<c>Default</c>): not copied. The base access comes from the new
        /// gate to its members, so nobody keeps for good what depended on signing in again.
        /// </summary>
        public string? AutoProvisionedRole { get; init; }

        /// <summary>The hash (hex) of a bootstrap token published in a repository's history: copied inactive.</summary>
        public string? BootstrapTokenHash { get; init; }

        /// <summary>Overrides of role values (RoleId → roleValue), frozen before the first copy.</summary>
        public IReadOnlyDictionary<int, string> RoleValueOverrides { get; init; } = new Dictionary<int, string>();

        /// <summary>What a person approved: <see cref="LegacyImportApprovals"/>.</summary>
        public IReadOnlySet<string> Approvals { get; init; } = new HashSet<string>();
    }

    public static class LegacyImportApprovals
    {
        /// <summary>Import although users who passed the legacy gate and hold roles have no usable identity: they lose their access.</summary>
        public const string UnresolvedUsers = "unresolved-users";
    }

    /// <summary>
    /// What the target schema must hold after the import, computed from the legacy data, the resolved identities and the
    /// permissions the host declares. Pure: no database. The importer reconciles the target to it, and verifies it.
    /// </summary>
    /// <remarks>
    /// Nothing is widened: a token limited to some roles, the bootstrap token and a token whose owner has no identity are
    /// copied inactive; a code the host does not declare is not copied; wildcards are copied as they are, never expanded.
    /// </remarks>
    public sealed class LegacyImportPlan
    {
        public required IReadOnlyList<TargetRole> Roles { get; init; }
        public required IReadOnlyList<TargetGrant> Grants { get; init; }
        public required IReadOnlyList<TargetProfile> Profiles { get; init; }
        public required IReadOnlyList<TargetUserRole> UserRoles { get; init; }
        public required IReadOnlyList<TargetToken> Tokens { get; init; }

        /// <summary>Legacy user id → object id, for the users imported (the audit log is translated with it).</summary>
        public required IReadOnlyDictionary<int, string> UserMap { get; init; }

        /// <summary>Legacy role id → role value, for every role copied.</summary>
        public required IReadOnlyDictionary<int, string> RoleMap { get; init; }

        /// <summary>
        /// Legacy role id → role value, for the auto-provisioned role (<see cref="LegacyImportSettings.AutoProvisionedRole"/>): it is not
        /// copied as a role, but its number is kept in <c>LegacyRoleMap</c>, because what a host stored by that number (a vault entry shared
        /// with <c>Default</c>, that is, with everybody who signed in) has to keep meaning it.
        /// </summary>
        public IReadOnlyDictionary<int, string> AutoProvisionedRoles { get; init; } = new Dictionary<int, string>();

        public required IReadOnlyList<ImportIssue> Issues { get; init; }

        public bool HasBlockers => Issues.Any(i => i.Severity == IssueSeverity.Blocker);

        public static LegacyImportPlan Build(
            LegacyData data, LegacyReport report, IReadOnlyList<ResolvedIdentity> identities, IReadOnlySet<string> declaredCodes,
            IReadOnlyDictionary<int, string> mappedRoles, LegacyImportSettings settings, DateTime now)
        {
            var issues = new List<ImportIssue>();
            void Add(IssueSeverity severity, string code, int? user, string detail) => issues.Add(new(severity, code, user, detail));

            foreach (var blocker in report.Findings.Where(f => f.Severity == IssueSeverity.Blocker))
                Add(IssueSeverity.Blocker, blocker.Code, null, blocker.Message);

            // ── Roles ──
            var copied = data.Roles
                .Where(r => settings.AutoProvisionedRole is null || !string.Equals(r.Name.Trim(), settings.AutoProvisionedRole, StringComparison.OrdinalIgnoreCase))
                .ToList();
            var skippedRole = data.Roles.Except(copied).Select(r => r.RoleId).ToHashSet();
            if (skippedRole.Count > 0)
                Add(IssueSeverity.Info, "auto-provisioned-role", null,
                    $"role {string.Join(", ", skippedRole)} ('{settings.AutoProvisionedRole}') is not copied: the base access comes from the new gate.");

            IReadOnlyDictionary<int, string> values;
            try
            {
                values = LegacyRoleValues.Assign(copied, mappedRoles, settings.RoleValueOverrides);
            }
            catch (InvalidOperationException ex)
            {
                Add(IssueSeverity.Blocker, "role-values", null, ex.Message);
                values = LegacyRoleValues.Assign(copied, mappedRoles.Where(m => copied.Any(r => r.RoleId == m.Key)).ToDictionary(m => m.Key, m => m.Value));
            }
            var roleMap = copied.ToDictionary(r => r.RoleId, r => values[r.RoleId]);
            var roles = copied.OrderBy(r => r.RoleId).Select(r => new TargetRole(r.RoleId, roleMap[r.RoleId], Trim(r.Name, 200)!, Trim(r.Description, 500))).ToList();

            // The number of the role that is not copied stays reserved for what a host stored by it; its value never collides with a copied role's.
            var autoRoles = new Dictionary<int, string>();
            var taken = new HashSet<string>(roleMap.Values, StringComparer.OrdinalIgnoreCase);
            foreach (var role in data.Roles.Where(r => skippedRole.Contains(r.RoleId)).OrderBy(r => r.RoleId))
            {
                var value = mappedRoles.TryGetValue(role.RoleId, out var kept) ? kept : LegacyRoleValues.Generate(role.Name, role.RoleId);
                if (!taken.Add(value))
                {
                    value = $"{value[..Math.Min(value.Length, LegacyRoleValues.MaxGeneratedLength)]}-{role.RoleId}";
                    taken.Add(value);
                }
                autoRoles[role.RoleId] = value;
            }

            // ── What roles grant ──
            var grants = new List<TargetGrant>();
            foreach (var group in data.Grants.Where(g => roleMap.ContainsKey(g.RoleId)).GroupBy(g => g.PermissionCode, StringComparer.Ordinal))
            {
                if (declaredCodes.Contains(group.Key))
                    grants.AddRange(group.Select(g => new TargetGrant(roleMap[g.RoleId], g.PermissionCode)));
                else
                    Add(IssueSeverity.Warning, "code-undeclared", null,
                        $"'{group.Key}' is granted by roles {string.Join(", ", group.Select(g => g.RoleId).Distinct())} but the host does not declare it: not copied (it would grant nothing).");
            }
            grants = grants.Distinct().ToList();

            // ── People ──
            var users = data.Users.ToDictionary(u => u.UserId);
            var byUser = identities.ToDictionary(i => i.LegacyUserId);
            var userMap = new Dictionary<int, string>();
            foreach (var user in data.Users)
                if (byUser.TryGetValue(user.UserId, out var identity) && identity.Importable)
                    userMap[user.UserId] = identity.ObjectId!;

            // Two legacy users on one person would each get the other's roles.
            foreach (var group in userMap.GroupBy(m => m.Value).Where(g => g.Count() > 1))
                Add(IssueSeverity.Blocker, "duplicate-identity", null,
                    $"users {string.Join(", ", group.Select(g => g.Key))} resolve to one person: merging them widens each. Fix the legacy rows or the identities.");

            var heldBy = data.UserRoles.Where(ur => users.ContainsKey(ur.UserId)).ToLookup(ur => ur.UserId, ur => ur.RoleId);
            foreach (var user in data.Users.Where(u => !userMap.ContainsKey(u.UserId) && heldBy[u.UserId].Any()))
            {
                var identity = byUser.GetValueOrDefault(user.UserId);
                var passed = identity?.PassedLegacyGate ?? user.IsActive;
                var status = identity?.Status ?? "not resolved";
                if (!passed)
                    Add(IssueSeverity.Info, "unresolved-user", user.UserId, $"{status}; had no access (inactive or outside the legacy gate): their roles are not copied.");
                else
                    Add(settings.Approvals.Contains(LegacyImportApprovals.UnresolvedUsers) ? IssueSeverity.Warning : IssueSeverity.Blocker, "unresolved-user", user.UserId,
                        $"{status}: has access today and roles {string.Join(", ", heldBy[user.UserId])}, which are not copied. "
                        + $"Resolve them (identities import), or approve the loss ('{LegacyImportApprovals.UnresolvedUsers}').");
            }

            var profiles = data.Users.Where(u => userMap.ContainsKey(u.UserId)).OrderBy(u => u.UserId)
                .Select(u => new TargetProfile(userMap[u.UserId], u.UserId, u.Email.Trim().ToLowerInvariant(), Trim(u.DisplayName, 200), u.IsActive, u.CreatedAt ?? now))
                .ToList();
            foreach (var profile in profiles.Where(p => !p.IsActive))
                Add(IssueSeverity.Info, "inactive-user", profile.LegacyUserId, "imported suspended, with their roles.");

            var userRoles = data.UserRoles
                .Where(ur => userMap.ContainsKey(ur.UserId) && roleMap.ContainsKey(ur.RoleId))
                .Select(ur => new TargetUserRole(userMap[ur.UserId], roleMap[ur.RoleId]))
                .Distinct()
                .ToList();

            // ── Tokens ──
            var limited = data.TokenRoles.GroupBy(tr => tr.TokenId).ToDictionary(g => g.Key, g => g.Select(tr => tr.RoleId).ToHashSet());
            var bootstrap = settings.BootstrapTokenHash is null ? null : Convert.FromHexString(settings.BootstrapTokenHash.Trim());
            var tokens = new List<TargetToken>();
            foreach (var token in data.Tokens.OrderBy(t => t.Id))
            {
                var active = token.IsActive;
                string owner, label;
                if (userMap.TryGetValue(token.UserId, out var objectId))
                {
                    owner = objectId;
                    label = users[token.UserId].Email.Trim().ToLowerInvariant();
                }
                else
                {
                    // A token belongs to somebody; with no identity, to nobody the gate knows. Inactive.
                    owner = $"legacy:{token.UserId}";
                    label = users.TryGetValue(token.UserId, out var legacyOwner) ? legacyOwner.Email.Trim().ToLowerInvariant() : $"legacy user {token.UserId}";
                    if (active)
                        Add(IssueSeverity.Warning, "token-owner-unresolved", token.UserId, $"token {token.Id} is copied inactive: its owner has no identity.");
                    active = false;
                }

                if (limited.TryGetValue(token.Id, out var tokenRoles) && heldBy[token.UserId].Except(tokenRoles).Any())
                {
                    if (active)
                        Add(IssueSeverity.Warning, "token-limited-to-roles", token.UserId, $"token {token.Id} is copied inactive: with all its owner's roles it would hold more.");
                    active = false;
                }

                if (bootstrap is not null && token.TokenHash.AsSpan().SequenceEqual(bootstrap))
                {
                    Add(IssueSeverity.Warning, "token-bootstrap", token.UserId, $"token {token.Id} is the bootstrap token whose hash was published: copied inactive.");
                    active = false;
                }

                tokens.Add(new TargetToken(token.Id, token.TokenHash, Trim(token.Name, 100)!, token.TokenPrefix, owner, Trim(label, 256)!, active,
                    token.ExpiresAt, token.CreatedAt ?? now, token.LastUsedAt));
            }

            return new LegacyImportPlan
            {
                Roles = roles, Grants = grants, Profiles = profiles, UserRoles = userRoles, Tokens = tokens,
                UserMap = userMap, RoleMap = roleMap, AutoProvisionedRoles = autoRoles, Issues = issues,
            };
        }

        private static string? Trim(string? text, int length) =>
            text is null ? null : text.Trim().Length <= length ? text.Trim() : text.Trim()[..length];
    }
}
