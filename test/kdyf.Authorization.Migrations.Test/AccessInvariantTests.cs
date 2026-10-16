using kdyf.Authorization.Migrations.Legacy;
using kdyf.Authorization.Migrations.Schema;

namespace kdyf.Authorization.Migrations.Test;

/// <summary>
/// The invariant of the import, on data in memory: each case tries to make somebody gain, and must be refused, or
/// accepted only with its exception. And what is lost is listed, per person.
/// </summary>
[TestClass]
public sealed class AccessInvariantTests
{
    private const string A = "0f1e2d3c-0000-0000-0000-00000000000a";
    private const string B = "0f1e2d3c-0000-0000-0000-00000000000b";
    private static readonly DateTime Now = new(2026, 10, 16, 12, 0, 0, DateTimeKind.Utc);
    private static readonly IReadOnlySet<string> Declared = new HashSet<string> { "*", "Default", "Orders.Read", "Orders.Write", "Admin" };

    /// <summary>Two users, each holding one role: A administers (role 1 '*'), B reads orders (role 2).</summary>
    private static LegacyData Data(IEnumerable<LegacyGrant>? grants = null, IEnumerable<LegacyToken>? tokens = null, IEnumerable<LegacyTokenRole>? tokenRoles = null) => new()
    {
        Schema = "auth",
        Users = new[] { new LegacyUser(1, "a@test", A, null, true), new LegacyUser(2, "b@test", B, null, true) },
        Roles = new[] { new LegacyRole(1, "Admins"), new LegacyRole(2, "Readers") },
        Grants = (grants ?? new[] { new LegacyGrant(1, "*"), new LegacyGrant(2, "Orders.Read") }).ToList(),
        UserRoles = new[] { new LegacyUserRole(1, 1), new LegacyUserRole(2, 2) },
        Tokens = (tokens ?? Array.Empty<LegacyToken>()).ToList(),
        TokenRoles = (tokenRoles ?? Array.Empty<LegacyTokenRole>()).ToList(),
        CatalogCodes = Declared.ToList(),
        AuditLogCount = 0,
        AuditLogMaxId = null,
        ExternalReferences = Array.Empty<ExternalReference>(),
    };

    private static List<ResolvedIdentity> Identities(LegacyData data, bool legacyGateB = true, bool newGateB = true) => data.Users.Select(u => new ResolvedIdentity(
        u.UserId, u.Email, u.ObjectId, u.ObjectId, "existing", 1, "Member", true, IdentityStatus.Ok, IdentityResolver.RowVersion(u),
        u.UserId == 2 ? legacyGateB : true, u.UserId == 2 ? newGateB : true, Now)).ToList();

    private static InvariantReport Check(
        LegacyData data, List<ResolvedIdentity> identities, InvariantSettings? settings = null, params InvariantException[] exceptions)
    {
        var plan = LegacyImportPlan.Build(data, LegacyReport.Build(data), identities, Declared, new Dictionary<int, string>(), new LegacyImportSettings(), Now);
        return AccessInvariant.Check(data, identities, plan, Declared, settings ?? new InvariantSettings(), exceptions, Now);
    }

    private static IEnumerable<ImportIssue> Blockers(InvariantReport report) => report.Issues.Where(i => i.Severity == IssueSeverity.Blocker);

    [TestMethod]
    public void A_faithful_copy_passes()
    {
        var data = Data();

        var report = Check(data, Identities(data));

        Assert.AreEqual(0, Blockers(report).Count(), string.Join("\n", report.Issues));
    }

    /// <summary>Finding 9: in the packages every member of the gate holds the base access; in the legacy app B did not.</summary>
    [TestMethod]
    public void The_base_access_of_members_is_a_gain_unless_approved()
    {
        var data = Data();
        var settings = new InvariantSettings { MemberGrants = new[] { "Default" } };

        var refused = Check(data, Identities(data), settings);
        var approved = Check(data, Identities(data), settings, new InvariantException(InvariantKinds.MemberBaseAccess, null, null, null, "finding 9", "carlos"));

        StringAssert.Contains(Blockers(refused).Single().Detail, "'Default'");
        Assert.AreEqual(1, Blockers(refused).Count(), "only B: A held it through '*'");
        Assert.AreEqual(0, Blockers(approved).Count());
    }

    /// <summary>Somebody outside the legacy gate (nothing) but inside the new one (their roles) would gain everything.</summary>
    [TestMethod]
    public void Being_let_in_by_the_new_gate_is_a_gain()
    {
        var data = Data();

        var report = Check(data, Identities(data, legacyGateB: false, newGateB: true));

        Assert.IsTrue(Blockers(report).Any(i => i.Code == "gain" && i.LegacyUserId == 2 && i.Detail.Contains("Orders.Read")));
    }

    [TestMethod]
    public void A_gain_approved_for_one_person_and_code_passes_and_only_that()
    {
        var data = Data();
        var identities = Identities(data, legacyGateB: false);

        var report = Check(data, identities, null, new InvariantException(InvariantKinds.Gain, B, "Orders.Read", null, "joined the team", "carlos"));
        var otherCode = Check(data, identities, null, new InvariantException(InvariantKinds.Gain, B, "Orders.Write", null, "x", "carlos"));
        var otherPerson = Check(data, identities, null, new InvariantException(InvariantKinds.Gain, A, "Orders.Read", null, "x", "carlos"));

        Assert.AreEqual(0, Blockers(report).Count());
        Assert.AreEqual(1, Blockers(otherCode).Count());
        Assert.AreEqual(1, Blockers(otherPerson).Count());
    }

    /// <summary>The administration code: whoever held it holds it, whoever did not does not. Losing it is refused too.</summary>
    [TestMethod]
    public void An_exact_code_may_neither_be_gained_nor_lost()
    {
        var data = Data();
        var settings = new InvariantSettings { ExactCodes = new[] { "Admin" } };

        var lost = Check(data, Identities(data).Select(i => i.LegacyUserId == 1 ? i with { PassesNewGate = false } : i).ToList(), settings);

        Assert.IsTrue(Blockers(lost).Any(i => i.Code == "exact" && i.LegacyUserId == 1 && i.Detail.Contains("held before, not after")));
    }

    [TestMethod]
    public void Too_few_administrators_after_the_import_block_unless_approved()
    {
        var data = Data();
        var settings = new InvariantSettings { AdministrationCode = "Admin", MinAdministrators = 2 };

        var refused = Check(data, Identities(data), settings);
        var approved = Check(data, Identities(data), settings, new InvariantException(InvariantKinds.MinAdministrators, null, null, 1, "one admin in test", "carlos"));

        Assert.AreEqual(1, refused.AdministratorsAfter);
        Assert.IsTrue(Blockers(refused).Any(i => i.Code == "min-administrators"));
        Assert.AreEqual(0, Blockers(approved).Count());
    }

    /// <summary>
    /// The import copies a limited token inactive. If something ever copied it active, the invariant catches it: defence
    /// in depth, checked here on a plan altered by hand.
    /// </summary>
    [TestMethod]
    public void A_token_that_would_hold_more_than_before_is_refused()
    {
        var data = Data(
            grants: new[] { new LegacyGrant(1, "Orders.Read"), new LegacyGrant(2, "Orders.Write") },
            tokens: new[] { new LegacyToken(7, "t", new byte[32], null, 1, true, null) },
            tokenRoles: new[] { new LegacyTokenRole(7, 1) });
        var identities = Identities(data);
        var users = new[] { new LegacyUserRole(1, 1), new LegacyUserRole(1, 2), new LegacyUserRole(2, 2) };
        data = new LegacyData
        {
            Schema = data.Schema, Users = data.Users, Roles = data.Roles, Grants = data.Grants, UserRoles = users, Tokens = data.Tokens,
            TokenRoles = data.TokenRoles, CatalogCodes = data.CatalogCodes, AuditLogCount = 0, AuditLogMaxId = null, ExternalReferences = data.ExternalReferences,
        };
        var plan = LegacyImportPlan.Build(data, LegacyReport.Build(data), identities, Declared, new Dictionary<int, string>(), new LegacyImportSettings(), Now);
        Assert.IsFalse(plan.Tokens.Single().IsActive, "the import copies it inactive");

        var altered = new LegacyImportPlan
        {
            Roles = plan.Roles, Grants = plan.Grants, Profiles = plan.Profiles, UserRoles = plan.UserRoles, UserMap = plan.UserMap, RoleMap = plan.RoleMap, Issues = plan.Issues,
            Tokens = plan.Tokens.Select(t => t with { IsActive = true }).ToList(),
        };
        var report = AccessInvariant.Check(data, identities, altered, Declared, new InvariantSettings(), Array.Empty<InvariantException>(), Now);

        Assert.IsTrue(Blockers(report).Any(i => i.Code == "token-gain" && i.Detail.Contains("Orders.Write")));
    }

    /// <summary>A group-gated host's tokens passed the gate on their own: their owner outside the new gate makes them stop. Counted.</summary>
    [TestMethod]
    public void Tokens_that_stop_validating_are_counted_and_need_their_count_approved()
    {
        var data = Data(tokens: new[] { new LegacyToken(7, "t", new byte[32], null, 2, true, null) });
        var identities = Identities(data, legacyGateB: false, newGateB: false);
        var settings = new InvariantSettings { TokensExemptFromGate = true };

        var refused = Check(data, identities, settings);
        var approved = Check(data, identities, settings, new InvariantException(InvariantKinds.TokenCount, null, null, -1, "B is not in the group", "carlos"));
        var wrongCount = Check(data, identities, settings, new InvariantException(InvariantKinds.TokenCount, null, null, -2, "x", "carlos"));

        Assert.AreEqual((1, 0), (refused.TokensBefore, refused.TokensAfter));
        Assert.IsTrue(Blockers(refused).Any(i => i.Code == "token-count"));
        Assert.AreEqual(0, Blockers(approved).Count());
        Assert.AreEqual(1, Blockers(wrongCount).Count(), "the exception approves THIS count only");
    }

    [TestMethod]
    public void What_each_person_loses_is_listed_undeclared_codes_included()
    {
        var data = Data(grants: new[] { new LegacyGrant(1, "*"), new LegacyGrant(2, "Orders.Read"), new LegacyGrant(2, "Old.Report") });

        var report = Check(data, Identities(data, newGateB: false));

        CollectionAssert.AreEqual(new[] { "Old.Report (undeclared)", "Orders.Read" }, report.Reductions[2].ToArray());
        Assert.IsFalse(report.Reductions.ContainsKey(1));
        Assert.AreEqual(0, Blockers(report).Count(), "losing is not refused: it is accepted before the cutover");
    }

    // ── The exceptions file ──────────────────────────────────────────────────

    [TestMethod]
    public void The_exceptions_file_is_read_and_its_mistakes_are_listed_together()
    {
        var parsed = InvariantExceptions.Parse("""
            { "exceptions": [
              { "kind": "member-base-access", "reason": "finding 9" },
              { "kind": "gain", "objectId": "0F1E2D3C-0000-0000-0000-00000000000B", "code": "Orders.Read", "reason": "joined" },
              { "kind": "token-count", "value": -2, "reason": "outside the group" } ] }
            """, "carlos");

        Assert.AreEqual(3, parsed.Count);
        Assert.AreEqual(B, parsed[1].ObjectId, "normalised");
        Assert.IsTrue(parsed.All(e => e.ApprovedBy == "carlos"));

        var error = Assert.ThrowsException<FormatException>(() => InvariantExceptions.Parse("""
            { "exceptions": [ { "kind": "everything", "reason": "x" }, { "kind": "gain", "reason": "no person" }, { "kind": "token-count", "reason": "" } ] }
            """, "carlos"));
        StringAssert.Contains(error.Message, "#1");
        StringAssert.Contains(error.Message, "#2");
        StringAssert.Contains(error.Message, "#3");
    }

    [TestMethod]
    public void The_checksum_identifies_the_file_exactly() =>
        Assert.AreNotEqual(InvariantExceptions.Checksum("{ }"), InvariantExceptions.Checksum("{  }"));
}
