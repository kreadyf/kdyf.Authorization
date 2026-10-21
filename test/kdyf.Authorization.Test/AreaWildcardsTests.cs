using kdyf.Authorization.Abstractions;
using kdyf.Authorization.Authorization;
using kdyf.Authorization.Roles;

namespace kdyf.Authorization.Test;

/// <summary>
/// Which area wildcards a host's declarations call for, and that a derived one grants like a declared one.
/// </summary>
[TestClass]
public class AreaWildcardsTests
{
    /// <summary>A permission with exactly this code, wherever the test class lives.</summary>
    private sealed class Declared(string code) : PermissionDefinition(CodeShape.Verbatim, code, code);

    private static PermissionDefinition[] Permissions(params string[] codes) =>
        codes.Select(code => (PermissionDefinition)new Declared(code)).ToArray();

    private static string[] Derived(PermissionDefinition[] declared, params string[] except) =>
        AreaWildcards.Derive(declared, except).Select(p => p.Code).ToArray();

    // =====================================================================
    // What gets a wildcard
    // =====================================================================

    /// <summary>The case that asked for this: two permissions in a new area, and its wildcard comes with them.</summary>
    [TestMethod]
    public void An_area_with_two_permissions_gets_its_wildcard()
    {
        CollectionAssert.AreEqual(new[] { "aaa.*" }, Derived(Permissions("aaa.aaa", "aaa.bbb")));
    }

    [TestMethod]
    public void Every_area_gets_one_ordered_by_code()
    {
        var declared = Permissions("Order.Invoices", "Compliance.Cases", "Order.Tool", "Compliance.List", "Amazon.Mapping", "Amazon.Products");

        CollectionAssert.AreEqual(new[] { "Amazon.*", "Compliance.*", "Order.*" }, Derived(declared));
    }

    /// <summary>Its wildcard would grant exactly what the one permission does: a second way to say the same.</summary>
    [TestMethod]
    public void An_area_with_a_single_permission_gets_none()
    {
        CollectionAssert.AreEqual(new[] { "two.*" }, Derived(Permissions("one.Only", "two.A", "two.B")));
    }

    [TestMethod]
    public void A_code_without_an_area_and_the_global_wildcard_get_none()
    {
        CollectionAssert.AreEqual(Array.Empty<string>(), Derived(Permissions("*", "Default", "DataAdministration")));
    }

    /// <summary>One level, what a roles screen groups by. The nested codes count for the first segment.</summary>
    [TestMethod]
    public void A_nested_area_counts_for_its_first_segment_and_gets_no_wildcard_of_its_own()
    {
        var declared = Permissions("kreadyf.Invoicing.Catalogs", "kreadyf.Invoicing.Contingency");

        CollectionAssert.AreEqual(new[] { "kreadyf.*" }, Derived(declared));
    }

    /// <summary>The class's name and description are what the administrators see: they are kept.</summary>
    [TestMethod]
    public void A_wildcard_declared_by_a_class_wins()
    {
        CollectionAssert.AreEqual(new[] { "b.*" }, Derived(Permissions("a.X", "a.Y", "a.*", "b.X", "b.Y")));
    }

    [TestMethod]
    public void An_excepted_area_gets_none()
    {
        CollectionAssert.AreEqual(new[] { "kreadyf.*" }, Derived(Permissions("global.Vault", "global.Timesheet", "kreadyf.A", "kreadyf.B"), "global"));
    }

    [TestMethod]
    public void A_derived_wildcard_says_what_it_is()
    {
        var wildcard = (AreaWildcard)AreaWildcards.Derive(Permissions("Compliance.Cases", "Compliance.List")).Single();

        Assert.AreEqual("Compliance.*", wildcard.Code);
        Assert.AreEqual("Compliance", wildcard.Area);
        Assert.AreEqual("All Compliance", wildcard.Name);
        Assert.AreEqual("Wildcard: everything under Compliance", wildcard.Description);
        Assert.IsTrue(wildcard.IsPattern);
    }

    [TestMethod]
    public void Areas_are_the_first_segment_of_plain_codes()
    {
        Assert.AreEqual("fabrikam", AreaWildcards.AreaOf("fabrikam.Invoicing.Invoices"));
        Assert.IsNull(AreaWildcards.AreaOf("Default"));
        Assert.IsNull(AreaWildcards.AreaOf("fabrikam.*"));
        Assert.IsNull(AreaWildcards.AreaOf("*"));
        Assert.IsNull(AreaWildcards.AreaOf(".Orphan"));
    }

    // =====================================================================
    // What is refused
    // =====================================================================

    /// <summary>A misspelt exception would derive the very wildcard it was written to prevent.</summary>
    [TestMethod]
    public void An_excepted_area_that_does_not_exist_is_refused()
    {
        var error = Assert.ThrowsException<InvalidOperationException>(() => Derived(Permissions("global.Vault", "global.Timesheet"), "Global"));

        StringAssert.Contains(error.Message, "Global");
        StringAssert.Contains(error.Message, "The areas are: global");
    }

    [TestMethod]
    public void Excepting_an_area_whose_wildcard_a_class_declares_is_refused()
    {
        var error = Assert.ThrowsException<InvalidOperationException>(() => Derived(Permissions("global.A", "global.B", "global.*"), "global"));

        StringAssert.Contains(error.Message, "'global.*' is declared");
    }

    /// <summary>auth.Permission's key is case-insensitive: Order.* and order.* could not both be rows.</summary>
    [TestMethod]
    public void Areas_that_differ_only_in_capitalisation_are_refused()
    {
        var error = Assert.ThrowsException<InvalidOperationException>(() => Derived(Permissions("Order.A", "Order.B", "order.C")));

        StringAssert.Contains(error.Message, "Order / order");
    }

    /// <summary>A wildcard matches codes case-sensitively: 'compliance.*' covers none of 'Compliance.Cases'.</summary>
    [TestMethod]
    public void A_declared_wildcard_whose_capitalisation_does_not_match_its_area_is_refused()
    {
        var error = Assert.ThrowsException<InvalidOperationException>(() => Derived(Permissions("Compliance.Cases", "Compliance.List", "compliance.*")));

        StringAssert.Contains(error.Message, "'compliance.*' is declared, but the area is 'Compliance'");
    }

    [TestMethod]
    [DataRow("")]
    [DataRow(" ")]
    [DataRow("a.b")]
    [DataRow("a*")]
    [DataRow("a b")]
    public void An_area_wildcard_needs_an_area(string area) =>
        Assert.ThrowsException<ArgumentException>(() => new AreaWildcard(area));

    /// <summary>It exists only when derived: scanning an assembly never instantiates it.</summary>
    [TestMethod]
    public void Discovery_never_finds_it()
    {
        var discovered = PermissionDefinition.DiscoverIn(typeof(AreaWildcard).Assembly);

        Assert.IsFalse(discovered.Any(p => p is AreaWildcard));
    }

    // =====================================================================
    // What a derived wildcard grants
    // =====================================================================

    /// <summary>
    /// The point of the whole feature: a role granting the derived wildcard holds every code of the area — nested ones
    /// included — and nothing outside it, through the same map that authorizes requests.
    /// </summary>
    [TestMethod]
    public void A_role_granting_a_derived_wildcard_holds_its_area_and_nothing_else()
    {
        var declared = Permissions("Default", "Compliance.Cases", "Compliance.List", "Compliance.Mail.Unassigned", "Order.Invoices", "Order.Tool");
        var catalog = new DeclaredPermissions([.. declared, .. AreaWildcards.Derive(declared)]);

        var map = new RolePermissionMap(
            new Dictionary<string, IReadOnlySet<string>>
            {
                ["compliance-lead"] = new HashSet<string>(StringComparer.Ordinal) { "Default", "Compliance.*" },
            },
            catalog.Codes,
            []);

        CollectionAssert.AreEquivalent(
            new[] { "Default", "Compliance.*", "Compliance.Cases", "Compliance.List", "Compliance.Mail.Unassigned" },
            map.EffectivePermissions(["compliance-lead"]).ToArray());
    }

    /// <summary>Without the derivation the same grant is a code nobody declares: it grants nothing, as before.</summary>
    [TestMethod]
    public void Without_the_derivation_the_same_grant_holds_nothing_of_the_area()
    {
        var catalog = new DeclaredPermissions(Permissions("Default", "Compliance.Cases", "Compliance.List"));

        var map = new RolePermissionMap(
            new Dictionary<string, IReadOnlySet<string>>
            {
                ["compliance-lead"] = new HashSet<string>(StringComparer.Ordinal) { "Default", "Compliance.*" },
            },
            catalog.Codes,
            []);

        CollectionAssert.AreEquivalent(new[] { "Default" }, map.EffectivePermissions(["compliance-lead"]).ToArray());
    }
}
