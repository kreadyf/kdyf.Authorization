using kdyf.Authorization.Migrations.Legacy;
using kdyf.Authorization.Migrations.Schema;

namespace kdyf.Authorization.Migrations.Test;

/// <summary>Each legacy shape of the history is told apart, read, and reported on, without writing anything.</summary>
[TestClass]
public sealed class LegacyInspectorTests
{
    private static async Task<(LegacyShape Shape, LegacyReport? Report)> InspectAsync(params string[] scripts)
    {
        await using var db = await TestDatabase.CreateAsync();
        foreach (var script in scripts)
            await db.ExecuteAsync(script);
        return await LegacyInspector.InspectAsync(db.ConnectionString, "auth");
    }

    [TestMethod]
    public async Task Shape_A_is_recognised_and_not_supported()
    {
        var (shape, report) = await InspectAsync(LegacyFixtures.ShapeA);

        Assert.AreEqual("A", shape.Label);
        Assert.IsFalse(shape.Supported);
        Assert.IsNull(report);
    }

    [TestMethod]
    public async Task Shape_B_limits_tokens_to_roles_and_a_limited_active_token_blocks()
    {
        var (shape, report) = await InspectAsync(LegacyFixtures.ShapeB, LegacyFixtures.Data, LegacyFixtures.TokenData, LegacyFixtures.TokenRoleData);

        Assert.AreEqual("B", shape.Label);
        Assert.IsTrue(report!.HasBlockers);
        StringAssert.Contains(report.Findings.Single(f => f.Code == "token-limited-to-roles").Message, "token 1");
    }

    [TestMethod]
    public async Task Shape_B_prime_has_the_audit_log_and_the_token_roles_still()
    {
        var (shape, _) = await InspectAsync(LegacyFixtures.ShapeBPrime);

        Assert.AreEqual("B′", shape.Label);
    }

    [TestMethod]
    public async Task Shape_C_is_read_whole()
    {
        var (shape, report) = await InspectAsync(LegacyFixtures.ShapeC, LegacyFixtures.Data, LegacyFixtures.TokenData);

        Assert.AreEqual("C", shape.Label);
        Assert.AreEqual(4, report!.Data.Users.Count);
        Assert.AreEqual(3, report.Data.Roles.Count);
        Assert.AreEqual(2, report.Data.Tokens.Count);
        CollectionAssert.AreEqual(new[] { "super-admin", "order-reader", "empty-role" }, report.Roles.Select(r => r.RoleValue).ToArray());
        Assert.IsFalse(report.HasBlockers, string.Join("\n", report.Findings));
    }

    [TestMethod]
    public async Task Shape_K0_has_the_wide_object_id_and_no_tokens()
    {
        var (shape, report) = await InspectAsync(LegacyFixtures.ShapeK0, LegacyFixtures.Data);

        Assert.AreEqual("K0", shape.Label);
        Assert.AreEqual(0, report!.Data.Tokens.Count);
    }

    /// <summary>The import must know who else points at the legacy ids (kdyf.admin's vault.EntryAccess.RoleId).</summary>
    [TestMethod]
    public async Task A_column_in_another_schema_named_like_a_legacy_id_is_reported()
    {
        var (_, report) = await InspectAsync(LegacyFixtures.ShapeC, LegacyFixtures.Data,
            "CREATE SCHEMA vault;", "CREATE TABLE vault.EntryAccess (EntryId INT NOT NULL, RoleId INT NOT NULL, CONSTRAINT PK_EntryAccess PRIMARY KEY (EntryId, RoleId));");

        StringAssert.Contains(report!.Findings.Single(f => f.Code == "external-reference").Message, "vault.EntryAccess.RoleId");
    }

    [TestMethod]
    public async Task The_schema_is_found_whatever_its_case()
    {
        await using var db = await TestDatabase.CreateAsync();
        await db.ExecuteAsync(LegacyFixtures.ShapeC.Replace("auth.", "Auth.").Replace("SCHEMA auth", "SCHEMA Auth"));

        var (shape, _) = await LegacyInspector.InspectAsync(db.ConnectionString, "auth");

        Assert.AreEqual("C", shape.Label);
    }

    [TestMethod]
    public async Task The_command_prints_the_report_and_exits_1_on_blockers()
    {
        await using var db = await TestDatabase.CreateAsync();
        await db.ExecuteAsync(LegacyFixtures.ShapeB);
        await db.ExecuteAsync(LegacyFixtures.Data);
        await db.ExecuteAsync(LegacyFixtures.TokenData);
        await db.ExecuteAsync(LegacyFixtures.TokenRoleData);
        var output = new StringWriter();

        var code = await SchemaCommandLine.RunAsync(new[] { "legacy-report" }, db.ConnectionString, "authz", output);

        Assert.AreEqual(SchemaCommandLine.NotDone, code);
        StringAssert.Contains(output.ToString(), "Legacy shape B");
        StringAssert.Contains(output.ToString(), "super-admin");
        Assert.IsFalse(output.ToString().Contains("admin@test"), "people appear by legacy id, never by e-mail");
    }
}
