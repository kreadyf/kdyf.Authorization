using kdyf.Authorization.Authorization;
using kdyf.Authorization.Migrations.Schema;
using kdyf.Authorization.Roles;

namespace kdyf.Authorization.Migrations.Legacy
{
    /// <summary>An exception to the invariant, approved by a person: what may differ, and why.</summary>
    /// <param name="Kind">
    /// <c>member-base-access</c>: members of the new gate may gain what every member holds (finding 9).
    /// <c>gain</c>: <see cref="ObjectId"/> may gain <see cref="Code"/> (<c>*</c>: any code).
    /// <c>exact</c>: <see cref="ObjectId"/> may differ on the exact code <see cref="Code"/>.
    /// <c>token-count</c>: the tokens that validate change by <see cref="Value"/> (after − before).
    /// <c>min-administrators</c>: fewer administrators than the minimum, down to <see cref="Value"/>.
    /// </param>
    /// <param name="ObjectId">The person it is about; null for every person.</param>
    /// <param name="Code">The permission code it is about; <c>*</c> or null for any.</param>
    /// <param name="Value">The number a count exception allows.</param>
    /// <param name="Reason">Why it is accepted, for whoever reads the record later.</param>
    /// <param name="ApprovedBy">Who approved it.</param>
    internal sealed record InvariantException(string Kind, string? ObjectId, string? Code, int? Value, string Reason, string ApprovedBy);

    internal static class InvariantKinds
    {
        public const string MemberBaseAccess = "member-base-access";
        public const string Gain = "gain";
        public const string Exact = "exact";
        public const string TokenCount = "token-count";
        public const string MinAdministrators = "min-administrators";

        public static readonly IReadOnlySet<string> All = new HashSet<string> { MemberBaseAccess, Gain, Exact, TokenCount, MinAdministrators };
    }

    /// <summary>How the invariant is checked for an application.</summary>
    internal sealed class InvariantSettings
    {
        /// <summary>What every member of the new gate holds without roles (the host's <c>MemberPermissionCodes</c>).</summary>
        public IReadOnlyCollection<string> MemberGrants { get; init; } = Array.Empty<string>();

        /// <summary>Codes that must be held after by exactly who held them before: administration, a vault.</summary>
        public IReadOnlyCollection<string> ExactCodes { get; init; } = Array.Empty<string>();

        /// <summary>The code that means "administers access", and how many must hold it after.</summary>
        public string? AdministrationCode { get; init; }

        public int MinAdministrators { get; init; } = 2;

        /// <summary>Group-gated legacy hosts: tokens passed the legacy gate on their own, whatever their owner's membership.</summary>
        public bool TokensExemptFromGate { get; init; }
    }

    /// <summary>The outcome: what is refused, what is approved, and what is lost (to be accepted before the cutover).</summary>
    internal sealed class InvariantReport
    {
        public required IReadOnlyList<ImportIssue> Issues { get; init; }

        /// <summary>Per legacy user: codes held before and not after (undeclared ones included).</summary>
        public required IReadOnlyDictionary<int, IReadOnlyList<string>> Reductions { get; init; }

        public required int TokensBefore { get; init; }
        public required int TokensAfter { get; init; }
        public required int AdministratorsAfter { get; init; }
    }

    /// <summary>
    /// The invariant of the legacy import: nobody gains. For each person (by object id) and each token, what they may do
    /// after the import is a subset of what they could do before, compared on the codes the host declares with nodes
    /// expanded the same way on both sides. "Before" is the legacy application as it decided (its gate, as snapshotted,
    /// and the roles); "after" is this package as it will decide (the new gate, the suspension, the roles and the base
    /// access of members), exactly as <see cref="RolePermissionMap.ForMember"/> computes it at run time.
    /// </summary>
    /// <remarks>Pure: from the plan, which the import then verifies the target equals row by row.</remarks>
    internal static class AccessInvariant
    {
        public static InvariantReport Check(
            LegacyData data, IReadOnlyList<ResolvedIdentity> identities, LegacyImportPlan plan, IReadOnlySet<string> declared,
            InvariantSettings settings, IReadOnlyList<InvariantException> exceptions, DateTime now)
        {
            var issues = new List<ImportIssue>();
            var concrete = declared.Where(PermissionHierarchy.IsValidCode).ToHashSet(StringComparer.Ordinal);
            IReadOnlySet<string> Concrete(IReadOnlySet<string> granted) =>
                concrete.Where(c => PermissionHierarchy.Covers(granted, c)).ToHashSet(StringComparer.Ordinal);
            bool Excepted(string kind, string? objectId, string? code) => exceptions.Any(e =>
                e.Kind == kind && (e.ObjectId is null || string.Equals(e.ObjectId, objectId, StringComparison.OrdinalIgnoreCase))
                && (e.Code is null or "*" || string.Equals(e.Code, code, StringComparison.Ordinal)));

            // ── Before: the legacy application ──
            var legacyGrants = data.Grants.ToLookup(g => g.RoleId, g => g.PermissionCode);
            var heldBy = data.UserRoles.ToLookup(ur => ur.UserId, ur => ur.RoleId);
            var users = data.Users.ToDictionary(u => u.UserId);
            var snapshot = identities.ToDictionary(i => i.LegacyUserId);
            IReadOnlySet<string> LegacyCodes(IEnumerable<int> roles) => PermissionHierarchy.NormalizeStoredGrants(roles.SelectMany(r => legacyGrants[r]));
            IReadOnlySet<string> BeforeOf(int userId) =>
                snapshot.TryGetValue(userId, out var identity) && identity.PassedLegacyGate
                    ? Concrete(PermissionHierarchy.Expand(LegacyCodes(heldBy[userId]).Where(declared.Contains).ToHashSet(StringComparer.Ordinal), declared))
                    : new HashSet<string>();

            // ── After: this package ──
            var map = new RolePermissionMap(
                plan.Roles.ToDictionary(r => r.RoleValue, r => (IReadOnlySet<string>)plan.Grants.Where(g => g.RoleValue == r.RoleValue).Select(g => g.PermissionCode).ToHashSet(StringComparer.Ordinal), StringComparer.Ordinal),
                declared, settings.MemberGrants);
            var rolesOf = plan.UserRoles.ToLookup(ur => ur.ObjectId, ur => ur.RoleValue, StringComparer.OrdinalIgnoreCase);
            // Several legacy users on one person is refused by the plan; here it must not throw: the person counts as active
            // and inside the gate only if every one of them is.
            var profiles = plan.Profiles.GroupBy(p => p.ObjectId, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(g => g.Key, g => g.All(p => p.IsActive), StringComparer.OrdinalIgnoreCase);
            var gate = plan.Profiles.GroupBy(p => p.ObjectId, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(g => g.Key, g => g.All(p => snapshot.TryGetValue(p.LegacyUserId, out var i) && i.PassesNewGate == true), StringComparer.OrdinalIgnoreCase);
            IReadOnlySet<string> AfterOf(string objectId) =>
                profiles.GetValueOrDefault(objectId) && gate.GetValueOrDefault(objectId)
                    ? Concrete(map.ForMember(rolesOf[objectId]))
                    : new HashSet<string>();
            var memberCodes = Concrete(map.ForMember(Array.Empty<string>()));

            // ── People ──
            var reductions = new Dictionary<int, IReadOnlyList<string>>();
            foreach (var (userId, objectId) in plan.UserMap.OrderBy(m => m.Key))
            {
                var before = BeforeOf(userId);
                var after = AfterOf(objectId);

                foreach (var code in after.Except(before).OrderBy(c => c, StringComparer.Ordinal))
                {
                    var baseAccess = memberCodes.Contains(code) && Excepted(InvariantKinds.MemberBaseAccess, null, null);
                    var approved = baseAccess || Excepted(InvariantKinds.Gain, objectId, code);
                    issues.Add(new(approved ? IssueSeverity.Info : IssueSeverity.Blocker, "gain", userId,
                        $"would gain '{code}'{(approved ? " (approved)" : "")}. Nobody gains in the import: approve it as an exception, or change the roles."));
                }

                foreach (var code in settings.ExactCodes)
                    if (PermissionHierarchy.Covers(before, code) != PermissionHierarchy.Covers(after, code) && !Excepted(InvariantKinds.Exact, objectId, code))
                        issues.Add(new(IssueSeverity.Blocker, "exact", userId,
                            $"'{code}' must be held after by exactly who held it before: {(PermissionHierarchy.Covers(before, code) ? "held before, not after" : "held after, not before")}."));

                var lost = before.Except(after).ToList();
                if (snapshot.TryGetValue(userId, out var id) && id.PassedLegacyGate)
                    lost.AddRange(LegacyCodes(heldBy[userId]).Where(c => !declared.Contains(c)).Select(c => $"{c} (undeclared)"));
                if (lost.Count > 0)
                    reductions[userId] = lost.Distinct().OrderBy(c => c, StringComparer.Ordinal).ToList();
            }

            // People who had access and are not imported at all lose everything: a reduction too.
            foreach (var user in data.Users.Where(u => !plan.UserMap.ContainsKey(u.UserId)))
            {
                var before = BeforeOf(user.UserId);
                if (before.Count > 0)
                    reductions[user.UserId] = before.OrderBy(c => c, StringComparer.Ordinal).ToList();
            }

            // ── Administrators ──
            var administrators = settings.AdministrationCode is null ? 0
                : plan.UserMap.Values.Distinct(StringComparer.OrdinalIgnoreCase).Count(oid => AfterOf(oid).Contains(settings.AdministrationCode));
            if (settings.AdministrationCode is not null && administrators < settings.MinAdministrators
                && !exceptions.Any(e => e.Kind == InvariantKinds.MinAdministrators && e.Value <= administrators))
                issues.Add(new(IssueSeverity.Blocker, "min-administrators", null,
                    $"{administrators} person(s) would hold '{settings.AdministrationCode}' after the import; at least {settings.MinAdministrators} are required."));

            // ── Tokens ──
            var tokensBefore = 0;
            var tokensAfter = 0;
            var limited = data.TokenRoles.GroupBy(tr => tr.TokenId).ToDictionary(g => g.Key, g => g.Select(tr => tr.RoleId).ToHashSet());
            foreach (var token in data.Tokens)
            {
                var valid = token.IsActive && (token.ExpiresAt is null || token.ExpiresAt > now)
                            && users.TryGetValue(token.UserId, out var owner) && owner.IsActive
                            && (settings.TokensExemptFromGate || (snapshot.TryGetValue(token.UserId, out var o) && o.PassedLegacyGate));
                var before = !valid ? new HashSet<string>()
                    : Concrete(PermissionHierarchy.Expand(LegacyCodes(limited.TryGetValue(token.Id, out var only) ? only : heldBy[token.UserId])
                        .Where(declared.Contains).ToHashSet(StringComparer.Ordinal), declared));
                if (before.Count > 0)
                    tokensBefore++;

                var copied = plan.Tokens.FirstOrDefault(t => t.LegacyId == token.Id);
                var after = copied is { IsActive: true } && (copied.ExpiresAt is null || copied.ExpiresAt > now) ? AfterOf(copied.OwnerObjectId) : new HashSet<string>();
                if (after.Count > 0)
                    tokensAfter++;

                foreach (var code in after.Except(before).OrderBy(c => c, StringComparer.Ordinal))
                    if (!(memberCodes.Contains(code) && Excepted(InvariantKinds.MemberBaseAccess, null, null)) && !Excepted(InvariantKinds.Gain, copied?.OwnerObjectId, code))
                        issues.Add(new(IssueSeverity.Blocker, "token-gain", token.UserId, $"token {token.Id} would gain '{code}'."));
            }

            if (tokensAfter != tokensBefore && !exceptions.Any(e => e.Kind == InvariantKinds.TokenCount && e.Value == tokensAfter - tokensBefore))
                issues.Add(new(IssueSeverity.Blocker, "token-count", null,
                    $"{tokensBefore} token(s) validate today and {tokensAfter} would after the import: approve the difference ({tokensAfter - tokensBefore}) as an exception, with the count."));

            if (reductions.Count > 0)
                issues.Add(new(IssueSeverity.Info, "reductions", null,
                    $"{reductions.Count} user(s) lose permissions; the list must be accepted before the cutover."));

            return new InvariantReport
            {
                Issues = issues, Reductions = reductions, TokensBefore = tokensBefore, TokensAfter = tokensAfter, AdministratorsAfter = administrators,
            };
        }
    }
}
