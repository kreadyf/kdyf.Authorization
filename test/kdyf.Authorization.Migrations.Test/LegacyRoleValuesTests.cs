using kdyf.Authorization.Migrations.Legacy;

namespace kdyf.Authorization.Migrations.Test;

/// <summary>The role values the legacy roles get: deterministic, stable, never merging two roles.</summary>
[TestClass]
public sealed class LegacyRoleValuesTests
{
    [DataTestMethod]
    [DataRow("Super Admin", "super-admin")]
    [DataRow("WIMBA Office", "wimba-office")]
    [DataRow("Compliance Mail Reader", "compliance-mail-reader")]
    [DataRow("MFA Viewer", "mfa-viewer")]
    [DataRow("Gestión de Créditos", "gestion-de-creditos")]
    [DataRow("  Portal.Admin  ", "portal.admin")]
    [DataRow("Ops / Night-Shift (EU)", "ops-night-shift-eu")]
    [DataRow("2FA Reviewers", "role-2fa-reviewers")]
    [DataRow("___", "role-7")]
    [DataRow("", "role-7")]
    public void A_name_generates_its_value(string name, string expected) =>
        Assert.AreEqual(expected, LegacyRoleValues.Generate(name, 7));

    [TestMethod]
    public void A_long_name_is_cut_to_90_characters() =>
        Assert.AreEqual(90, LegacyRoleValues.Generate(new string('a', 300), 1).Length);

    /// <summary>'MFA Viewer' and 'MfaViewer' are two roles in kdyf.admin: two values, never one.</summary>
    [TestMethod]
    public void Two_roles_that_generate_the_same_value_stay_two_roles()
    {
        var values = LegacyRoleValues.Assign(new[] { new LegacyRole(4, "MFA viewer"), new LegacyRole(9, "MFA Viewer") });

        Assert.AreEqual("mfa-viewer", values[4]);
        Assert.AreEqual("mfa-viewer-9", values[9]);
    }

    /// <summary>The map is permanent: a role copied once keeps its value, whatever happens to the others since.</summary>
    [TestMethod]
    public void A_mapped_role_keeps_its_value_and_new_ones_avoid_it()
    {
        var mapped = new Dictionary<int, string> { [9] = "mfa-viewer" };

        var values = LegacyRoleValues.Assign(new[] { new LegacyRole(4, "MFA Viewer"), new LegacyRole(9, "Renamed since") }, mapped);

        Assert.AreEqual("mfa-viewer", values[9]);
        Assert.AreEqual("mfa-viewer-4", values[4]);
    }

    [TestMethod]
    public void An_override_wins_over_the_generated_value()
    {
        var values = LegacyRoleValues.Assign(
            new[] { new LegacyRole(1, "Super Admin"), new LegacyRole(2, "Wimba SuperAdmin") },
            overrides: new Dictionary<int, string> { [1] = "Wimba.SuperAdmin" });

        Assert.AreEqual("Wimba.SuperAdmin", values[1]);
        Assert.AreEqual("wimba-superadmin", values[2]);
    }

    [TestMethod]
    public void An_override_that_renames_a_copied_role_is_refused()
    {
        var error = Assert.ThrowsException<InvalidOperationException>(() => LegacyRoleValues.Assign(
            new[] { new LegacyRole(1, "Super Admin") },
            mapped: new Dictionary<int, string> { [1] = "super-admin" },
            overrides: new Dictionary<int, string> { [1] = "Wimba.SuperAdmin" }));

        StringAssert.Contains(error.Message, "explicit step");
    }

    [TestMethod]
    public void Overrides_that_collide_or_have_the_wrong_shape_are_refused_together()
    {
        var error = Assert.ThrowsException<InvalidOperationException>(() => LegacyRoleValues.Assign(
            new[] { new LegacyRole(1, "a"), new LegacyRole(2, "b"), new LegacyRole(3, "c") },
            overrides: new Dictionary<int, string> { [1] = "Same", [2] = "same", [3] = "9 lives" }));

        StringAssert.Contains(error.Message, "taken by another role");
        StringAssert.Contains(error.Message, "starts with a letter");
    }

    [TestMethod]
    public void The_assignment_does_not_depend_on_the_order_the_roles_come_in()
    {
        var roles = new[] { new LegacyRole(3, "Admin"), new LegacyRole(1, "admin"), new LegacyRole(2, "ADMIN") };

        var a = LegacyRoleValues.Assign(roles);
        var b = LegacyRoleValues.Assign(roles.AsEnumerable().Reverse());

        CollectionAssert.AreEquivalent(a.ToList(), b.ToList());
        Assert.AreEqual("admin", a[1]);
    }
}
