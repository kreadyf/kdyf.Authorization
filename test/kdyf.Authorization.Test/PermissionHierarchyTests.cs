using kdyf.Authorization.Authorization;

namespace kdyf.Authorization.Test;

/// <summary>
/// What a node of the permission tree grants.
/// </summary>
/// <remarks>
/// These rules are load-bearing. They decide whether the holder of a role granting the root or an area can do a given
/// thing at all — and when the answer looks wrong in a running system, this is the file that says whether the CODE is
/// wrong or the deployment is.
/// </remarks>
[TestClass]
public class PermissionHierarchyTests
{
    /// <summary>A realistic catalogue, as the tree is completed: codes, their ancestors and the root.</summary>
    private static readonly IReadOnlySet<string> Catalog = new HashSet<string>(StringComparer.Ordinal)
    {
        "", "Default",
        "my", "my.Timesheet", "my.Authenticator", "my.AccessTokens",
        "global", "global.Timesheet", "global.TimesheetWriter", "global.TimesheetAdmin",
        "global.Vault", "global.UserAdministration", "global.UserSimulation",
        "fabrikam", "fabrikam.Controlling",
        "fabrikam.Invoicing", "fabrikam.Invoicing.Invoices", "fabrikam.Invoicing.Catalogs", "fabrikam.Invoicing.Contingency",
        "fabrikamArchive", "fabrikamArchive.Read",
        "contoso", "contoso.Accounting", "contoso.Invoicing",
    };

    private static IReadOnlySet<string> Granted(params string[] codes) =>
        new HashSet<string>(codes, StringComparer.Ordinal);

    // =====================================================================
    // What a node grants
    // =====================================================================

    /// <summary>
    /// Whoever holds the root must be able to simulate users, because <c>global.UserSimulation</c> is granted on its own
    /// to no role. If this fails, the simulate button shows up for nobody.
    /// </summary>
    [TestMethod]
    public void The_root_reaches_the_codes_no_role_grants_on_its_own()
    {
        var effective = PermissionHierarchy.Expand(Granted(PermissionHierarchy.Root), Catalog);

        Assert.IsTrue(effective.Contains("global.UserSimulation"), "simulate users");
        Assert.IsTrue(effective.Contains("global.UserAdministration"), "administer users");
        Assert.IsTrue(effective.Contains("fabrikam.Controlling"), "controlling");
    }

    [TestMethod]
    public void The_root_reaches_every_node_of_the_catalogue()
    {
        var effective = PermissionHierarchy.Expand(Granted(PermissionHierarchy.Root), Catalog);

        CollectionAssert.AreEquivalent(Catalog.ToArray(), effective.ToArray());
    }

    [TestMethod]
    public void An_area_reaches_itself_and_everything_below_it_and_stops_there()
    {
        var effective = PermissionHierarchy.Expand(Granted("fabrikam"), Catalog);

        Assert.IsTrue(effective.Contains("fabrikam"), "the node itself");
        Assert.IsTrue(effective.Contains("fabrikam.Controlling"));
        Assert.IsTrue(effective.Contains("fabrikam.Invoicing"), "an intermediate node");
        Assert.IsTrue(effective.Contains("fabrikam.Invoicing.Invoices"), "any depth");
        Assert.IsFalse(effective.Contains("global.UserSimulation"), "another area");
        Assert.IsFalse(effective.Contains(PermissionHierarchy.Root), "not the root");
    }

    /// <summary>The cut is by segment: 'fabrikam' is not a prefix of 'fabrikamArchive'.</summary>
    [TestMethod]
    public void A_node_does_not_reach_a_sibling_that_merely_starts_with_its_name()
    {
        var effective = PermissionHierarchy.Expand(Granted("fabrikam"), Catalog);

        Assert.IsFalse(effective.Contains("fabrikamArchive"));
        Assert.IsFalse(effective.Contains("fabrikamArchive.Read"));
    }

    [TestMethod]
    public void An_intermediate_node_reaches_only_its_branch()
    {
        var effective = PermissionHierarchy.Expand(Granted("fabrikam.Invoicing"), Catalog);

        CollectionAssert.AreEquivalent(
            new[] { "fabrikam.Invoicing", "fabrikam.Invoicing.Invoices", "fabrikam.Invoicing.Catalogs", "fabrikam.Invoicing.Contingency" },
            effective.ToArray());
    }

    /// <summary>Nothing granted is not the root granted: the two must never be confused.</summary>
    [TestMethod]
    public void Nothing_granted_grants_nothing()
    {
        Assert.AreEqual(0, PermissionHierarchy.Expand(Granted(), Catalog).Count);
    }

    [TestMethod]
    public void A_leaf_grants_only_itself()
    {
        CollectionAssert.AreEquivalent(new[] { "my.Timesheet" }, PermissionHierarchy.Expand(Granted("my.Timesheet"), Catalog).ToArray());
    }

    [TestMethod]
    public void A_node_with_no_row_in_the_catalogue_reaches_only_itself()
    {
        // The catalog is the target of the expansion: a declared code with no row is reached by nobody, not even the
        // root. It is the reason the synchronizer exists.
        var effective = PermissionHierarchy.Expand(Granted(PermissionHierarchy.Root), new HashSet<string>(StringComparer.Ordinal));

        CollectionAssert.AreEqual(new[] { PermissionHierarchy.Root }, effective.ToArray());
    }

    // =====================================================================
    // "Holds at least as much as"
    // =====================================================================

    [TestMethod]
    public void The_root_covers_every_node()
    {
        var held = Granted(PermissionHierarchy.Root);

        Assert.IsTrue(PermissionHierarchy.Covers(held, "fabrikam"));
        Assert.IsTrue(PermissionHierarchy.Covers(held, "global.UserSimulation"));
        Assert.IsTrue(PermissionHierarchy.Covers(held, PermissionHierarchy.Root));
    }

    [TestMethod]
    public void An_area_does_not_cover_the_root_nor_another_area()
    {
        var held = Granted("fabrikam");

        Assert.IsTrue(PermissionHierarchy.Covers(held, "fabrikam.Invoicing.Invoices"));
        Assert.IsFalse(PermissionHierarchy.Covers(held, PermissionHierarchy.Root));
        Assert.IsFalse(PermissionHierarchy.Covers(held, "global.UserSimulation"));
        Assert.IsFalse(PermissionHierarchy.Covers(held, "fabrikamArchive.Read"));
    }

    /// <summary>
    /// Holding every code of an area is NOT holding its node: the node also covers whatever is added tomorrow. It is
    /// what makes a role editor disable <c>my</c> for whoever holds the three <c>my.</c> codes individually.
    /// </summary>
    [TestMethod]
    public void Holding_every_child_is_not_holding_the_parent()
    {
        var held = Granted("my.Timesheet", "my.Authenticator", "my.AccessTokens");

        Assert.IsTrue(PermissionHierarchy.Covers(held, "my.Timesheet"));
        Assert.IsFalse(PermissionHierarchy.Covers(held, "my"));
    }

    [TestMethod]
    public void Covering_lists_the_code_its_ancestors_and_the_root_nearest_first()
    {
        CollectionAssert.AreEqual(
            new[] { "fabrikam.Invoicing.Invoices", "fabrikam.Invoicing", "fabrikam", PermissionHierarchy.Root },
            PermissionHierarchy.Covering("fabrikam.Invoicing.Invoices").ToArray());
        CollectionAssert.AreEqual(new[] { PermissionHierarchy.Root }, PermissionHierarchy.Covering(PermissionHierarchy.Root).ToArray());
        CollectionAssert.AreEqual(Array.Empty<string>(), PermissionHierarchy.Covering("a..b").ToArray());
    }

    [TestMethod]
    public void Ancestors_leave_the_code_out()
    {
        CollectionAssert.AreEqual(new[] { "a.b", "a", PermissionHierarchy.Root }, PermissionHierarchy.Ancestors("a.b.c").ToArray());
        CollectionAssert.AreEqual(Array.Empty<string>(), PermissionHierarchy.Ancestors(PermissionHierarchy.Root).ToArray());
    }

    // =====================================================================
    // What a code is
    // =====================================================================

    [TestMethod]
    [DataRow("")]
    [DataRow("Default")]
    [DataRow("a.b.c")]
    [DataRow("my_area-1.Read")]
    [DataRow("Order.Invoices")]
    public void Valid_codes(string code) => Assert.IsTrue(PermissionHierarchy.IsValidCode(code), code);

    [TestMethod]
    [DataRow(null)]
    [DataRow(" ")]
    [DataRow("*")]
    [DataRow("a.*")]
    [DataRow("a..b")]
    [DataRow(".a")]
    [DataRow("a.")]
    [DataRow("a b")]
    [DataRow("a|b")]
    [DataRow("ä")]
    public void Invalid_codes(string? code) => Assert.IsFalse(PermissionHierarchy.IsValidCode(code), code);

    // =====================================================================
    // Data written before 1.2.0
    // =====================================================================

    [TestMethod]
    public void A_stored_star_reads_as_the_root_and_an_area_wildcard_as_its_node()
    {
        CollectionAssert.AreEquivalent(
            new[] { PermissionHierarchy.Root, "fabrikam", "my.Timesheet" },
            PermissionHierarchy.NormalizeStoredGrants(new[] { "*", "fabrikam.*", "my.Timesheet" }).ToArray());
    }

    /// <summary>A typo must never widen a grant: a malformed wildcard grants nothing at all.</summary>
    [TestMethod]
    [DataRow(".*")]
    [DataRow("a..*")]
    [DataRow("*.*")]
    [DataRow("fabrikam*")]
    [DataRow("*.Timesheet")]
    [DataRow("kre*dyf.Controlling")]
    public void A_malformed_legacy_wildcard_grants_nothing(string stored)
    {
        Assert.AreEqual(0, PermissionHierarchy.Expand(Granted(stored), Catalog).Count, stored);
    }

    [TestMethod]
    public void A_stored_wildcard_expands_like_its_node()
    {
        CollectionAssert.AreEquivalent(
            PermissionHierarchy.Expand(Granted("fabrikam"), Catalog).ToArray(),
            PermissionHierarchy.Expand(Granted("fabrikam.*"), Catalog).ToArray());
        CollectionAssert.AreEquivalent(
            Catalog.ToArray(),
            PermissionHierarchy.Expand(Granted("*"), Catalog).ToArray());
    }

    /// <summary>A set read from rows not yet rewritten covers what the node would.</summary>
    [TestMethod]
    public void Covers_honours_legacy_spellings_in_the_held_set()
    {
        Assert.IsTrue(PermissionHierarchy.Covers(Granted("*"), "global.Vault"));
        Assert.IsTrue(PermissionHierarchy.Covers(Granted("fabrikam.*"), "fabrikam.Invoicing.Invoices"));
        Assert.IsFalse(PermissionHierarchy.Covers(Granted("fabrikam.*"), "global.Vault"));
    }

    [TestMethod]
    public void The_legacy_spelling_of_a_node()
    {
        Assert.AreEqual("*", PermissionHierarchy.LegacySpellingOf(PermissionHierarchy.Root));
        Assert.AreEqual("fabrikam.*", PermissionHierarchy.LegacySpellingOf("fabrikam"));
    }

    // =====================================================================
    // The complete case
    // =====================================================================

    /// <summary>
    /// A global administrator's roles as they would be stored: the base role, invoicing, and "Global Admin" with the
    /// root. With the root expanded they have EVERYTHING — so if in some environment they are missing something from
    /// <c>global.</c>, what is failing is not this calculation.
    /// </summary>
    [TestMethod]
    public void The_roles_of_a_global_admin_resolve_to_the_whole_catalogue()
    {
        var granted = Granted(
            "Default",
            "my.Timesheet", "my.Authenticator", "my.AccessTokens",
            "fabrikam.Invoicing",
            PermissionHierarchy.Root);

        var effective = PermissionHierarchy.Expand(granted, Catalog);

        Assert.IsTrue(effective.Contains("global.UserSimulation"), "the simulate button");
        Assert.IsTrue(effective.Contains("global.UserAdministration"), "the users screen");
        Assert.IsTrue(effective.Contains("fabrikam.Controlling"), "the Controlling menu");
        Assert.IsTrue(effective.Contains("contoso.Accounting"), "the whole other area");
    }
}
