using kdyf.Authorization.Authorization;

namespace kdyf.Authorization.Test;

/// <summary>
/// What a wildcard actually grants.
/// </summary>
/// <remarks>
/// These rules are load-bearing and were until now only covered indirectly. They decide whether the
/// holder of a role granting <c>*</c> can do a given thing at all — and when the answer looks wrong
/// in a running system, this is the file that says whether the CODE is wrong or the deployment is.
/// </remarks>
[TestClass]
public class PermissionWildcardsTests
{
    /// <summary>A realistic catalogue: areas, nested areas and wildcards at every level.</summary>
    private static readonly IReadOnlySet<string> Catalog = new HashSet<string>(StringComparer.Ordinal)
    {
        "*", "Default",
        "my.*", "my.Timesheet", "my.Authenticator", "my.AccessTokens",
        "global.*", "global.Timesheet", "global.TimesheetWriter", "global.TimesheetAdmin",
        "global.Authenticator", "global.UserAdministration", "global.UserSimulation",
        "fabrikam.*", "fabrikam.Controlling",
        "fabrikam.Invoicing.Invoices", "fabrikam.Invoicing.Catalogs", "fabrikam.Invoicing.Contingency",
        "contoso.*", "contoso.Accounting", "contoso.Invoicing",
    };

    private static IReadOnlySet<string> Granted(params string[] codes) =>
        new HashSet<string>(codes, StringComparer.Ordinal);

    // =====================================================================
    // What a wildcard grants
    // =====================================================================

    /// <summary>
    /// The concrete case that prompted these tests: whoever holds the "Global Admin" role —which stores
    /// <c>*</c>— must be able to simulate users, because <c>global.UserSimulation</c> is not granted
    /// on its own to any role. If this fails, the simulate button shows up for nobody.
    /// </summary>
    [TestMethod]
    public void Everything_reaches_the_codes_no_role_grants_on_its_own()
    {
        var effective = PermissionWildcards.Expand(Granted("*"), Catalog);

        Assert.IsTrue(effective.Contains("global.UserSimulation"), "simulate users");
        Assert.IsTrue(effective.Contains("global.UserAdministration"), "administer users");
        Assert.IsTrue(effective.Contains("fabrikam.Controlling"), "controlling");
    }

    [TestMethod]
    public void Everything_reaches_every_plain_code_in_the_catalogue()
    {
        var effective = PermissionWildcards.Expand(Granted("*"), Catalog);

        foreach (var code in Catalog.Where(c => !c.Contains('*')))
            Assert.IsTrue(effective.Contains(code), code + " should have been covered");
    }

    /// <summary>
    /// A pattern NEVER expands onto another pattern. It is deliberate, and it is the reason
    /// <see cref="PermissionWildcards.Covers"/> exists: whoever holds <c>*</c> does not literally carry
    /// <c>fabrikam.*</c> in their set.
    /// </summary>
    [TestMethod]
    public void Everything_does_not_drag_the_other_patterns_in()
    {
        var effective = PermissionWildcards.Expand(Granted("*"), Catalog);

        foreach (var pattern in new[] { "my.*", "global.*", "fabrikam.*", "contoso.*" })
            Assert.IsFalse(effective.Contains(pattern), pattern + " should not have got in");
    }

    [TestMethod]
    public void An_area_pattern_reaches_its_area_and_stops_there()
    {
        var effective = PermissionWildcards.Expand(Granted("fabrikam.*"), Catalog);

        Assert.IsTrue(effective.Contains("fabrikam.Controlling"));
        Assert.IsTrue(effective.Contains("fabrikam.Invoicing.Invoices"), "any depth");
        Assert.IsFalse(effective.Contains("global.UserSimulation"), "another area");
        Assert.IsFalse(effective.Contains("my.Timesheet"), "another area");
    }

    /// <summary>The pattern is kept: the administration screen decides whether a role may be
    /// handed out by comparing against the set, and the role that grants <c>*</c> stores <c>*</c>.</summary>
    [TestMethod]
    public void The_pattern_itself_stays_in_the_effective_set()
    {
        Assert.IsTrue(PermissionWildcards.Expand(Granted("fabrikam.*"), Catalog).Contains("fabrikam.*"));
    }

    [TestMethod]
    public void A_set_without_patterns_is_returned_untouched()
    {
        var granted = Granted("my.Timesheet", "Default");

        Assert.AreSame(granted, PermissionWildcards.Expand(granted, Catalog));
    }

    // =====================================================================
    // The trap: patterns that are not patterns
    // =====================================================================

    /// <summary>
    /// There are only two forms: <c>*</c> and <c>prefix.*</c>. Anything else with an asterisk is
    /// recognized AS a pattern —and therefore not compared literally— but expands to nothing: whoever
    /// holds it is left without access, silently.
    /// </summary>
    [TestMethod]
    public void A_malformed_pattern_grants_nothing_and_says_nothing()
    {
        foreach (var malformed in new[] { "fabrikam*", "*.Timesheet", "kre*dyf.Controlling" })
        {
            var effective = PermissionWildcards.Expand(Granted(malformed), Catalog);

            Assert.AreEqual(1, effective.Count, malformed + " should not have granted anything");
            Assert.IsTrue(effective.Contains(malformed), "only itself is kept");
        }
    }

    [TestMethod]
    public void A_pattern_with_no_row_in_the_catalogue_reaches_nothing()
    {
        // The catalog is the target of the expansion: a declared code with no row is reached by
        // NOBODY, not even '*'. It is the reason the synchronizer exists.
        var effective = PermissionWildcards.Expand(Granted("*"), new HashSet<string>(StringComparer.Ordinal));

        CollectionAssert.AreEqual(new[] { "*" }, effective.ToArray());
    }

    // =====================================================================
    // "Holds at least as much as"
    // =====================================================================

    [TestMethod]
    public void Everything_covers_every_other_pattern()
    {
        var held = PermissionWildcards.Expand(Granted("*"), Catalog);

        Assert.IsTrue(PermissionWildcards.Covers(held, "fabrikam.*"));
        Assert.IsTrue(PermissionWildcards.Covers(held, "global.UserSimulation"));
        Assert.IsTrue(PermissionWildcards.Covers(held, "*"));
    }

    [TestMethod]
    public void An_area_pattern_does_not_cover_everything()
    {
        var held = PermissionWildcards.Expand(Granted("fabrikam.*"), Catalog);

        Assert.IsTrue(PermissionWildcards.Covers(held, "fabrikam.Invoicing.Invoices"));
        Assert.IsFalse(PermissionWildcards.Covers(held, "*"));
        Assert.IsFalse(PermissionWildcards.Covers(held, "global.UserSimulation"));
    }

    /// <summary>
    /// Holding every code of an area is NOT holding its wildcard: the pattern also covers whatever is
    /// added tomorrow. It is what makes the role editor disable <c>my.*</c> for whoever holds the
    /// three <c>my.</c> codes individually.
    /// </summary>
    [TestMethod]
    public void Holding_every_code_of_an_area_is_not_holding_its_pattern()
    {
        var held = Granted("my.Timesheet", "my.Authenticator", "my.AccessTokens");

        Assert.IsTrue(PermissionWildcards.Covers(held, "my.Timesheet"));
        Assert.IsFalse(PermissionWildcards.Covers(held, "my.*"));
    }

    // =====================================================================
    // The complete case
    // =====================================================================

    /// <summary>
    /// A global administrator's roles as they would be stored: the base role, invoicing, and "Global Admin" with
    /// <c>*</c>. With the wildcard resolved they have EVERYTHING — so if in
    /// some environment they are missing something from <c>global.</c>, what is failing is not this calculation.
    /// </summary>
    [TestMethod]
    public void The_roles_of_a_global_admin_resolve_to_the_whole_catalogue()
    {
        var granted = Granted(
            "Default",
            "my.Timesheet", "my.Authenticator", "my.AccessTokens",
            "fabrikam.Invoicing.Invoices", "fabrikam.Invoicing.Catalogs", "fabrikam.Invoicing.Contingency",
            "*");

        var effective = PermissionWildcards.Expand(granted, Catalog);

        Assert.IsTrue(effective.Contains("global.UserSimulation"), "the simulate button");
        Assert.IsTrue(effective.Contains("global.UserAdministration"), "the users screen");
        Assert.IsTrue(effective.Contains("fabrikam.Controlling"), "the Controlling menu");
        Assert.IsTrue(effective.Contains("contoso.Accounting"), "the whole other area");
    }
}
