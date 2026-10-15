using kdyf.Authorization.Migrations.Legacy;
using kdyf.Authorization.Migrations.Schema;

namespace kdyf.Authorization.Migrations.Test;

/// <summary>The rules of the report, on data built in memory: each dirty case says what the import has to decide.</summary>
[TestClass]
public sealed class LegacyReportTests
{
    private const string A = "0f1e2d3c-0000-0000-0000-00000000000a";
    private const string B = "0f1e2d3c-0000-0000-0000-00000000000b";

    private static LegacyData Data(
        IEnumerable<LegacyUser>? users = null, IEnumerable<LegacyRole>? roles = null, IEnumerable<LegacyGrant>? grants = null,
        IEnumerable<LegacyUserRole>? userRoles = null, IEnumerable<LegacyToken>? tokens = null, IEnumerable<LegacyTokenRole>? tokenRoles = null,
        IEnumerable<string>? catalog = null) => new()
    {
        Schema = "auth",
        Users = (users ?? new[] { new LegacyUser(1, "a@test", A, null, true) }).ToList(),
        Roles = (roles ?? new[] { new LegacyRole(1, "Reader") }).ToList(),
        Grants = (grants ?? new[] { new LegacyGrant(1, "Orders.Read") }).ToList(),
        UserRoles = (userRoles ?? new[] { new LegacyUserRole(1, 1) }).ToList(),
        Tokens = (tokens ?? Array.Empty<LegacyToken>()).ToList(),
        TokenRoles = (tokenRoles ?? Array.Empty<LegacyTokenRole>()).ToList(),
        CatalogCodes = (catalog ?? new[] { "Orders.Read", "Orders.Write", "*" }).ToList(),
        AuditLogCount = 0,
        AuditLogMaxId = null,
        ExternalReferences = Array.Empty<ExternalReference>(),
    };

    private static LegacyFinding? Finding(LegacyReport report, string code) => report.Findings.SingleOrDefault(f => f.Code == code);

    [TestMethod]
    public void Clean_data_has_no_blockers_nor_warnings()
    {
        var report = LegacyReport.Build(Data());

        Assert.IsFalse(report.Findings.Any(f => f.Severity != IssueSeverity.Info), string.Join("\n", report.Findings));
    }

    /// <summary>Merging two legacy users onto one person would give each the other's roles.</summary>
    [TestMethod]
    public void Two_users_with_one_object_id_block()
    {
        var report = LegacyReport.Build(Data(users: new[] { new LegacyUser(1, "a@test", A, null, true), new LegacyUser(2, "a2@test", A.ToUpperInvariant(), null, true) }));

        Assert.AreEqual(IssueSeverity.Blocker, Finding(report, "duplicate-object-id")!.Severity);
    }

    [TestMethod]
    public void One_email_with_two_object_ids_blocks_and_with_one_warns()
    {
        var two = LegacyReport.Build(Data(users: new[] { new LegacyUser(1, "a@test", A, null, true), new LegacyUser(2, " A@Test ", B, null, true) }));
        var one = LegacyReport.Build(Data(users: new[] { new LegacyUser(1, "a@test", A, null, true), new LegacyUser(2, "A@test", null, null, true) }));

        Assert.AreEqual(IssueSeverity.Blocker, Finding(two, "duplicate-email")!.Severity);
        Assert.AreEqual(IssueSeverity.Warning, Finding(one, "duplicate-email")!.Severity);
    }

    [TestMethod]
    public void Object_ids_missing_malformed_or_in_upper_case_are_told_apart()
    {
        var report = LegacyReport.Build(Data(users: new[]
        {
            new LegacyUser(1, "a@test", null, null, true),
            new LegacyUser(2, "b@test", "not-a-guid", null, true),
            new LegacyUser(3, "c@test", "{" + B.ToUpperInvariant() + "}", null, true),
        }));

        StringAssert.Contains(Finding(report, "user-without-object-id")!.Message, "Users 1.");
        StringAssert.Contains(Finding(report, "user-invalid-object-id")!.Message, "Users 2.");
        Assert.AreEqual(IssueSeverity.Info, Finding(report, "user-object-id-format")!.Severity);
    }

    /// <summary>Finding 9 of the plan: a member of the gate without roles gets the base access in the packages.</summary>
    [TestMethod]
    public void A_user_whose_roles_grant_nothing_would_gain_the_base_access()
    {
        var report = LegacyReport.Build(Data(
            users: new[] { new LegacyUser(1, "a@test", A, null, true), new LegacyUser(2, "b@test", B, null, true) },
            roles: new[] { new LegacyRole(1, "Reader"), new LegacyRole(2, "Empty") },
            userRoles: new[] { new LegacyUserRole(1, 1), new LegacyUserRole(2, 2) }));

        StringAssert.Contains(Finding(report, "user-without-permissions")!.Message, "Users 2.");
    }

    [TestMethod]
    public void An_inactive_user_is_imported_suspended_and_does_not_count_as_a_gain()
    {
        var report = LegacyReport.Build(Data(users: new[] { new LegacyUser(1, "a@test", A, null, false) }, userRoles: Array.Empty<LegacyUserRole>()));

        Assert.IsNotNull(Finding(report, "user-inactive"));
        Assert.IsNull(Finding(report, "user-without-permissions"));
    }

    [TestMethod]
    public void Codes_that_varchar_cannot_hold_or_too_long_block()
    {
        var report = LegacyReport.Build(Data(
            grants: new[] { new LegacyGrant(1, "Pedidos.Facturación"), new LegacyGrant(1, "Orders.Ω"), new LegacyGrant(1, new string('x', 51)) }));

        StringAssert.Contains(Finding(report, "code-not-representable")!.Message, "Orders.Ω");
        Assert.IsFalse(Finding(report, "code-not-representable")!.Message.Contains("Facturación"), "Latin-1 holds it");
        Assert.AreEqual(IssueSeverity.Blocker, Finding(report, "code-too-long")!.Severity);
    }

    [TestMethod]
    public void Codes_differing_only_in_case_and_codes_outside_the_catalog_warn()
    {
        var report = LegacyReport.Build(Data(grants: new[] { new LegacyGrant(1, "Orders.Read"), new LegacyGrant(1, "orders.read"), new LegacyGrant(1, "Old.Code") }));

        Assert.IsNotNull(Finding(report, "code-case"));
        StringAssert.Contains(Finding(report, "code-not-in-catalog")!.Message, "Old.Code");
    }

    [TestMethod]
    public void Rows_pointing_at_nothing_are_reported()
    {
        var report = LegacyReport.Build(Data(grants: new[] { new LegacyGrant(1, "Orders.Read"), new LegacyGrant(9, "Orders.Read") },
            userRoles: new[] { new LegacyUserRole(1, 1), new LegacyUserRole(7, 1) }));

        Assert.IsNotNull(Finding(report, "grant-without-role"));
        Assert.IsNotNull(Finding(report, "user-role-orphan"));
    }

    [TestMethod]
    public void A_token_of_an_owner_without_object_id_dies_unless_resolved()
    {
        var report = LegacyReport.Build(Data(
            users: new[] { new LegacyUser(1, "svc@test", null, null, true) },
            tokens: new[] { new LegacyToken(5, "Florian", new byte[32], null, 1, true, null) }));

        var finding = Finding(report, "token-owner-without-object-id")!;
        StringAssert.Contains(finding.Message, "token 5");
        Assert.IsFalse(finding.Message.Contains("Florian"), "a token's name can be a person's");
    }

    /// <summary>A token limited to one of its owner's roles would hold all of them: it is imported inactive.</summary>
    [TestMethod]
    public void A_token_limited_to_some_roles_is_reported_and_marked_active_when_it_is()
    {
        var data = Data(
            roles: new[] { new LegacyRole(1, "Reader"), new LegacyRole(2, "Writer") },
            grants: new[] { new LegacyGrant(1, "Orders.Read"), new LegacyGrant(2, "Orders.Write") },
            userRoles: new[] { new LegacyUserRole(1, 1), new LegacyUserRole(1, 2) },
            tokens: new[] { new LegacyToken(5, "t", new byte[32], null, 1, true, null), new LegacyToken(6, "u", new byte[32], null, 1, false, null) },
            tokenRoles: new[] { new LegacyTokenRole(5, 1), new LegacyTokenRole(6, 1) });

        var findings = LegacyReport.Build(data).Findings.Where(f => f.Code == "token-limited-to-roles").ToList();

        StringAssert.Contains(findings.Single(f => f.Message.Contains("token 5")).Message, "token 5 (active)");
        Assert.IsFalse(findings.Single(f => f.Message.Contains("token 6")).Message.Contains("(active)"));
        Assert.IsTrue(findings.All(f => f.Severity == IssueSeverity.Warning));
    }

    [TestMethod]
    public void A_token_with_all_its_owners_roles_is_not_limited()
    {
        var report = LegacyReport.Build(Data(
            tokens: new[] { new LegacyToken(5, "t", new byte[32], null, 1, true, null) },
            tokenRoles: new[] { new LegacyTokenRole(5, 1) }));

        Assert.IsNull(Finding(report, "token-limited-to-roles"));
    }

    [TestMethod]
    public void An_override_that_cannot_be_used_blocks()
    {
        var report = LegacyReport.Build(Data(), new Dictionary<int, string> { [1] = "9 lives" });

        Assert.AreEqual(IssueSeverity.Blocker, Finding(report, "role-values")!.Severity);
    }
}
