using kdyf.Authorization.Administration.Models;
using Microsoft.Extensions.Logging.Abstractions;

namespace kdyf.Authorization.Administration.Test;

/// <summary>
/// Finding people and bringing them into the access group: an invitation lands the person in the group, so
/// they can sign in with the base access until an administrator gives them a role.
/// </summary>
[TestClass]
public sealed class DirectoryAdminServiceTests
{
    private AccessFixture _f = null!;

    [TestInitialize]
    public void Setup() => _f = new AccessFixture();

    [TestCleanup]
    public void Cleanup() => _f.Dispose();

    private DirectoryAdminService<AdminTestContext> Directory() => new(
        _f.Db, _f.Entra, _f.Entra, new Persistence.EfAuditLog<AdminTestContext>(_f.Db),
        NullLogger<DirectoryAdminService<AdminTestContext>>.Instance);

    [TestMethod]
    public async Task The_search_says_who_is_in_the_group_and_their_roles()
    {
        var found = (await Directory().SearchAsync("@test", default)).Data;

        var reader = found.Single(u => u.ObjectId == People.Reader);
        Assert.IsTrue(reader.IsMember);
        CollectionAssert.AreEqual(new[] { "App.Reader" }, reader.Roles);
        Assert.IsFalse(found.Single(u => u.ObjectId == People.Newcomer).IsMember);
    }

    /// <summary>B2B creates the guest at once, so they join the group before they even redeem.</summary>
    [TestMethod]
    public async Task An_invited_guest_joins_the_group()
    {
        var result = await Directory().InviteAsync(new InviteRequest { Email = "Guest@Outside.test" }, _f.Actor(People.Admin), default);

        Assert.IsTrue(result.Validation.IsValid);
        Assert.IsTrue(result.Data.WasInvited);
        Assert.IsTrue(_f.Entra.IsMember(result.Data.User.ObjectId));
        CollectionAssert.AreEqual(new[] { "invite guest@outside.test", $"add {result.Data.User.ObjectId}" }, _f.Entra.Writes);
        Assert.AreEqual("directory.invited", _f.Audit().Single().Action);
    }

    /// <summary>Somebody already in the tenant is not invited twice: they are brought into the group.</summary>
    [TestMethod]
    public async Task Somebody_already_in_the_tenant_is_brought_into_the_group_not_invited()
    {
        var result = await Directory().InviteAsync(new InviteRequest { Email = "newcomer@test" }, _f.Actor(People.Admin), default);

        Assert.IsTrue(result.Validation.IsValid);
        Assert.IsFalse(result.Data.WasInvited);
        Assert.IsTrue(_f.Entra.IsMember(People.Newcomer));
        CollectionAssert.AreEqual(new[] { $"add {People.Newcomer}" }, _f.Entra.Writes);
        Assert.AreEqual("access.granted", _f.Audit().Single().Action);
    }

    [TestMethod]
    public async Task A_member_brought_in_again_changes_nothing()
    {
        var result = await Directory().InviteAsync(new InviteRequest { Email = "reader@test" }, _f.Actor(People.Admin), default);

        Assert.IsTrue(result.Validation.IsValid);
        Assert.AreEqual(0, _f.Entra.Writes.Count);
        Assert.AreEqual(0, _f.Audit().Count);
    }

    [TestMethod]
    public async Task Nobody_is_brought_in_while_simulating()
    {
        var result = await Directory().InviteAsync(new InviteRequest { Email = "newcomer@test" }, _f.Actor(People.Admin, simulatedBy: "x@test"), default);

        Assert.IsFalse(result.Validation.IsValid);
        Assert.AreEqual(0, _f.Entra.Writes.Count);
    }
}
