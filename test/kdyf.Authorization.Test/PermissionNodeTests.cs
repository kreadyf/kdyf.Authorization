using kdyf.Authorization.Abstractions;
using kdyf.Authorization.Authorization;
using kdyf.Authorization.Roles;

namespace kdyf.Authorization.Test;

/// <summary>
/// The catalog is a tree: every ancestor of a declared code and the root exist without a class, and granting one of
/// them grants its branch.
/// </summary>
[TestClass]
public class PermissionNodeTests
{
    /// <summary>A permission with exactly this code, wherever the test class lives.</summary>
    private sealed class Declared(string code, string? name = null) : PermissionDefinition(CodeShape.Verbatim, code, name ?? code);

    private static PermissionDefinition[] Permissions(params string[] codes) =>
        codes.Select(code => (PermissionDefinition)new Declared(code)).ToArray();

    private static string[] Codes(IEnumerable<PermissionDefinition> permissions) => permissions.Select(p => p.Code).ToArray();

    // =====================================================================
    // The tree
    // =====================================================================

    /// <summary>The case that asked for this: two permissions in a new area, and its node comes with them.</summary>
    [TestMethod]
    public void Every_ancestor_and_the_root_join_the_declarations()
    {
        var tree = PermissionNode.Complete(Permissions("aaa.aaa", "aaa.bbb", "Default"), out _);

        CollectionAssert.AreEqual(new[] { "", "Default", "aaa", "aaa.aaa", "aaa.bbb" }, Codes(tree), "ordinal order");
    }

    /// <summary>Unlike the area wildcards of 1.1.0: every level, and an area with a single permission too.</summary>
    [TestMethod]
    public void Nested_areas_and_single_permission_areas_get_their_nodes()
    {
        var tree = PermissionNode.Complete(Permissions("kreadyf.Invoicing.Catalogs", "one.Only"), out _);

        CollectionAssert.AreEqual(new[] { "", "kreadyf", "kreadyf.Invoicing", "kreadyf.Invoicing.Catalogs", "one", "one.Only" }, Codes(tree));
    }

    [TestMethod]
    public void An_implicit_node_says_what_it_is()
    {
        var tree = PermissionNode.Complete(Permissions("Compliance.Cases"), out _);

        var area = tree.Single(p => p.Code == "Compliance");
        Assert.IsInstanceOfType<PermissionNode>(area);
        Assert.AreEqual("Compliance", area.Name);
        StringAssert.Contains(area.Description, "Everything under Compliance");

        var root = tree.Single(p => p.Code == PermissionHierarchy.Root);
        Assert.AreEqual(PermissionNode.RootName, root.Name);
    }

    /// <summary>A class may give a node its name: it wins over the implicit one.</summary>
    [TestMethod]
    public void A_node_declared_by_a_class_wins()
    {
        var tree = PermissionNode.Complete([new Declared("Compliance", "All of Compliance"), .. Permissions("Compliance.Cases")], out _);

        var area = tree.Single(p => p.Code == "Compliance");
        Assert.IsNotInstanceOfType<PermissionNode>(area);
        Assert.AreEqual("All of Compliance", area.Name);
    }

    /// <summary>An empty code in a namespace declares that namespace's node.</summary>
    [TestMethod]
    public void An_empty_code_declares_the_node_of_its_namespace()
    {
        Assert.AreEqual("kdyf.Authorization.Test", new NamespaceNode().Code);
    }

    private sealed class NamespaceNode : PermissionDefinition
    {
        public NamespaceNode() : base(string.Empty, "Tests") { }
    }

    /// <summary>A legacy wildcard class stands for nothing any more: it is left out, and reported.</summary>
    [TestMethod]
    public void Legacy_wildcard_declarations_are_left_out_and_reported()
    {
        var tree = PermissionNode.Complete(Permissions("*", "Order.*", "Order.Tool"), out var ignored);

        CollectionAssert.AreEqual(new[] { "", "Order", "Order.Tool" }, Codes(tree));
        CollectionAssert.AreEqual(new[] { "*", "Order.*" }, ignored.ToArray());
    }

    /// <summary>auth.Permission's key is case-insensitive: Order and order could not both be rows.</summary>
    [TestMethod]
    public void Paths_that_differ_only_in_capitalisation_are_refused()
    {
        var error = Assert.ThrowsException<InvalidOperationException>(() => PermissionNode.Complete(Permissions("Order.A", "order.B"), out _));

        StringAssert.Contains(error.Message, "Order / order");
    }

    [TestMethod]
    public void A_code_that_is_not_a_path_is_refused()
    {
        var error = Assert.ThrowsException<InvalidOperationException>(() => PermissionNode.Complete(Permissions("a..b"), out _));

        StringAssert.Contains(error.Message, "'a..b'");
    }

    [TestMethod]
    [DataRow(" ")]
    [DataRow("a..b")]
    [DataRow("*")]
    public void A_node_needs_a_path(string code) =>
        Assert.ThrowsException<ArgumentException>(() => new PermissionNode(code));

    /// <summary>It exists only when the tree is completed: scanning an assembly never instantiates it.</summary>
    [TestMethod]
    public void Discovery_never_finds_it()
    {
        Assert.IsFalse(PermissionDefinition.DiscoverIn(typeof(PermissionNode).Assembly).Any(p => p is PermissionNode));
    }

    // =====================================================================
    // What a node grants, through the map that authorizes requests
    // =====================================================================

    /// <summary>
    /// The point of the whole feature: a role granting an area's node holds every code of the area — nested ones
    /// included — and nothing outside it, with no class written for the node.
    /// </summary>
    [TestMethod]
    public void A_role_granting_an_area_holds_its_branch_and_nothing_else()
    {
        var catalog = new DeclaredPermissions(Permissions("Default", "Compliance.Cases", "Compliance.List", "Compliance.Mail.Unassigned", "Order.Invoices", "Order.Tool"));

        var map = new RolePermissionMap(
            new Dictionary<string, IReadOnlySet<string>>
            {
                ["compliance-lead"] = new HashSet<string>(StringComparer.Ordinal) { "Default", "Compliance" },
            },
            catalog.Codes,
            []);

        CollectionAssert.AreEquivalent(
            new[] { "Default", "Compliance", "Compliance.Cases", "Compliance.List", "Compliance.Mail", "Compliance.Mail.Unassigned" },
            map.EffectivePermissions(["compliance-lead"]).ToArray());
    }

    /// <summary>A role still storing a wildcard from before 1.2.0 grants what its node does, until the rows are rewritten.</summary>
    [TestMethod]
    public void A_role_still_storing_a_wildcard_grants_its_node()
    {
        var catalog = new DeclaredPermissions(Permissions("Default", "Compliance.Cases", "Compliance.List"));

        var map = new RolePermissionMap(
            new Dictionary<string, IReadOnlySet<string>>
            {
                ["compliance-lead"] = new HashSet<string>(StringComparer.Ordinal) { "Compliance.*" },
                ["admin"] = new HashSet<string>(StringComparer.Ordinal) { "*" },
            },
            catalog.Codes,
            []);

        CollectionAssert.AreEquivalent(new[] { "Compliance", "Compliance.Cases", "Compliance.List" }, map.EffectivePermissions(["compliance-lead"]).ToArray());
        CollectionAssert.AreEquivalent(catalog.Codes.ToArray(), map.EffectivePermissions(["admin"]).ToArray());
        Assert.AreEqual(0, map.Undeclared.Count, "a legacy wildcard is read as its node, not reported as undeclared");
    }

    [TestMethod]
    public void The_catalog_says_which_codes_a_class_declares()
    {
        var catalog = new DeclaredPermissions(Permissions("Compliance.Cases"));

        Assert.IsTrue(catalog.IsExplicit("Compliance.Cases"));
        Assert.IsFalse(catalog.IsExplicit("Compliance"));
        Assert.IsFalse(catalog.IsExplicit(PermissionHierarchy.Root));
        Assert.IsFalse(catalog.IsExplicit("Nope"));
    }
}
