#pragma warning disable CS0618 // The obsolete API is what these tests are about.
using kdyf.Authorization.Abstractions;
using kdyf.Authorization.Authorization;

namespace kdyf.Authorization.Test;

/// <summary>
/// The wildcard API of 1.1.0, kept so that a host compiles against 1.2.0 unchanged: every member answers with the
/// permission hierarchy.
/// </summary>
[TestClass]
public class LegacyWildcardApiTests
{
    private sealed class Declared(string code) : PermissionDefinition(CodeShape.Verbatim, code, code);

    private static readonly IReadOnlySet<string> Catalog =
        new HashSet<string>(StringComparer.Ordinal) { "", "a", "a.X", "a.Y", "b", "b.X" };

    [TestMethod]
    public void Area_wildcards_are_no_longer_derived()
    {
        Assert.AreEqual(0, AreaWildcards.Derive([new Declared("a.X"), new Declared("a.Y")]).Count);
    }

    [TestMethod]
    public void The_area_of_a_code_is_still_its_first_segment()
    {
        Assert.AreEqual("fabrikam", AreaWildcards.AreaOf("fabrikam.Invoicing.Invoices"));
        Assert.IsNull(AreaWildcards.AreaOf("Default"));
        Assert.IsNull(AreaWildcards.AreaOf("fabrikam.*"));
        Assert.IsNull(AreaWildcards.AreaOf("*"));
    }

    [TestMethod]
    public void PermissionWildcards_answers_with_the_hierarchy()
    {
        var held = PermissionWildcards.Expand(new HashSet<string>(StringComparer.Ordinal) { "a.*" }, Catalog);

        CollectionAssert.AreEquivalent(new[] { "a", "a.X", "a.Y" }, held.ToArray());
        Assert.IsTrue(PermissionWildcards.Covers(held, "a.X"));
        Assert.IsFalse(PermissionWildcards.Covers(held, "b.X"));
        Assert.IsTrue(PermissionWildcards.IsPattern("a.*"));
        Assert.IsFalse(PermissionWildcards.IsPattern("a"));
    }

    [TestMethod]
    public void A_wildcard_declaration_still_says_it_is_one()
    {
        Assert.IsTrue(new Declared("*").IsPattern);
        Assert.IsTrue(new AreaWildcard("Compliance").IsPattern);
        Assert.IsFalse(new Declared("Compliance").IsPattern);
    }
}
