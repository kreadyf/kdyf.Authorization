using kdyf.Authorization.Administration.Models;
using kdyf.Authorization.Abstractions;
using kdyf.Authorization.EntityFrameworkCore.Entities;
using Microsoft.EntityFrameworkCore;

namespace kdyf.Authorization.Administration.Test;

/// <summary>
/// Personal access tokens: a credential worth exactly its owner's access (group and roles), and never a way
/// to be worth more.
/// </summary>
[TestClass]
public sealed class PatAdminServiceTests
{
    private AccessFixture _f = null!;

    [TestInitialize]
    public void Setup() => _f = new AccessFixture();

    [TestCleanup]
    public void Cleanup() => _f.Dispose();

    [TestMethod]
    public async Task A_person_creates_a_token_for_themselves_owned_by_their_object_id()
    {
        var created = await _f.Tokens().CreateAsync(new CreatePatRequest { Name = "ci" }, _f.Actor(People.TokenUser), default);

        Assert.IsTrue(created.Validation.IsValid, Errors(created));
        Assert.IsFalse(string.IsNullOrEmpty(created.Data.Token), "shown once, in clear");
        Assert.AreEqual(People.TokenUser, created.Data.OwnerObjectId);

        var row = _f.Db.Set<PersonalAccessToken>().AsNoTracking().Single();
        Assert.AreEqual(People.TokenUser, row.OwnerObjectId);
        CollectionAssert.AreNotEqual(System.Text.Encoding.UTF8.GetBytes(created.Data.Token), row.TokenHash, "only the hash is stored");
    }

    /// <summary>The audit line names the token by id and the creator by object id — and never carries the secret.</summary>
    [TestMethod]
    public async Task Creating_a_token_is_audited_without_the_secret()
    {
        var created = await _f.Tokens().CreateAsync(new CreatePatRequest { Name = "ci" }, _f.Actor(People.TokenUser), default);

        var entry = _f.Audit().Single();
        Assert.AreEqual("pat.created", entry.Action);
        Assert.AreEqual(People.TokenUser, entry.ActorObjectId);
        Assert.AreEqual(created.Data.PersonalAccessTokenId.ToString(), entry.TargetId);
        Assert.IsFalse(entry.Details!.Contains(created.Data.Token), "the plaintext token never reaches the log");
    }

    [TestMethod]
    public async Task Somebody_without_access_cannot_create_a_token_that_would_grant_nothing()
    {
        var result = await _f.Tokens().CreateAsync(new CreatePatRequest { Name = "ci" }, _f.Actor(People.Newcomer), default);

        Assert.IsFalse(result.Validation.IsValid);
    }

    [TestMethod]
    public async Task Only_an_administrator_creates_a_token_for_somebody_else()
    {
        var result = await _f.Tokens().CreateAsync(
            new CreatePatRequest { Name = "ci", OwnerObjectId = People.Reader }, _f.Actor(People.TokenUser), default);

        Assert.IsFalse(result.Validation.IsValid);
        Assert.AreEqual(0, _f.Db.Set<PersonalAccessToken>().Count());
    }

    /// <summary>
    /// The escalation this closes: a lesser administrator minting a token owned by somebody who holds
    /// more, and so holding a credential worth more than themselves.
    /// </summary>
    [TestMethod]
    public async Task No_token_is_created_for_an_owner_who_holds_more_than_the_administrator()
    {
        var result = await _f.Tokens().CreateAsync(
            new CreatePatRequest { Name = "backdoor", OwnerObjectId = People.Admin }, _f.Actor(People.Manager), default);

        Assert.IsFalse(result.Validation.IsValid);
        Assert.AreEqual(0, _f.Db.Set<PersonalAccessToken>().Count());
        Assert.AreEqual(0, _f.Audit().Count);
    }

    [TestMethod]
    public async Task An_administrator_creates_a_token_for_a_lesser_owner()
    {
        var result = await _f.Tokens().CreateAsync(
            new CreatePatRequest { Name = "integration", OwnerObjectId = People.Reader }, _f.Actor(People.Admin), default);

        Assert.IsTrue(result.Validation.IsValid, Errors(result));
        Assert.AreEqual("reader@test", result.Data.OwnerEmail);
        StringAssert.Contains(_f.Audit().Single().Details, "\"forAnotherUser\":true");
    }

    /// <summary>A token cannot mint tokens: a credential that copies itself outlives every revocation of the first.</summary>
    [TestMethod]
    public async Task A_token_cannot_create_tokens()
    {
        var token = new AdminActor(new UserIdentity(null, null), _f.Roles.ForMember(new[] { "App.Admin" }));

        var result = await _f.Tokens().CreateAsync(new CreatePatRequest { Name = "copy" }, token, default);

        Assert.IsFalse(result.Validation.IsValid);
    }

    [TestMethod]
    public async Task No_token_is_created_while_simulating()
    {
        var result = await _f.Tokens().CreateAsync(
            new CreatePatRequest { Name = "ci" }, _f.Actor(People.TokenUser, simulatedBy: "admin@test"), default);

        Assert.IsFalse(result.Validation.IsValid);
    }

    /// <summary>Somebody else's token answers exactly like a missing one: a different message would confirm the id.</summary>
    [TestMethod]
    public async Task Somebody_elses_token_cannot_be_touched_and_looks_like_it_does_not_exist()
    {
        var created = await _f.Tokens().CreateAsync(new CreatePatRequest { Name = "ci" }, _f.Actor(People.TokenUser), default);
        var id = created.Data.PersonalAccessTokenId;

        var other = await _f.Tokens().SetActiveAsync(id, false, _f.Actor(People.Reader), default);
        var missing = await _f.Tokens().SetActiveAsync(9999, false, _f.Actor(People.Reader), default);

        Assert.IsFalse(other.Validation.IsValid);
        Assert.AreEqual(missing.Validation.Fields["patId"].Errors.Single().Replace("9999", "#"),
            other.Validation.Fields["patId"].Errors.Single().Replace(id.ToString(), "#"));
    }

    [TestMethod]
    public async Task The_listing_says_when_an_owner_no_longer_has_access()
    {
        await _f.Tokens().CreateAsync(new CreatePatRequest { Name = "ci" }, _f.Actor(People.TokenUser), default);
        _f.Entra.Disable(People.TokenUser);

        var list = (await _f.Tokens().ListAsync(_f.Actor(People.Admin), default)).Data;

        Assert.IsFalse(list.Single().OwnerHasAccess, "active token, owner disabled in Entra: it grants nothing");
    }

    /// <summary>Out of the group, the owner holds nothing — and so does their token, roles or not.</summary>
    [TestMethod]
    public async Task A_token_is_worth_nothing_once_its_owner_leaves_the_group()
    {
        await _f.Tokens().CreateAsync(new CreatePatRequest { Name = "ci" }, _f.Actor(People.TokenUser), default);
        _f.Entra.LeaveGroup(People.TokenUser);

        var list = (await _f.Tokens().ListAsync(_f.Actor(People.Admin), default)).Data;

        Assert.IsFalse(list.Single().OwnerHasAccess);
        Assert.AreEqual(0, (await _f.PermissionStore().GetPermissionsAsync(new UserIdentity(People.TokenUser, null))).Count);
    }

    [TestMethod]
    public async Task A_person_lists_only_their_own_tokens_and_an_administrator_all()
    {
        await _f.Tokens().CreateAsync(new CreatePatRequest { Name = "mine" }, _f.Actor(People.TokenUser), default);
        await _f.Tokens().CreateAsync(new CreatePatRequest { Name = "theirs", OwnerObjectId = People.Reader }, _f.Actor(People.Admin), default);

        Assert.AreEqual(1, (await _f.Tokens().ListAsync(_f.Actor(People.TokenUser), default)).Data.Count);
        Assert.AreEqual(2, (await _f.Tokens().ListAsync(_f.Actor(People.Admin), default)).Data.Count);
    }

    private static string Errors(Validation.ValidationResult result) =>
        string.Join("; ", result.Validation.Fields.SelectMany(f => f.Value.Errors.Select(e => $"{f.Key}: {e}")));
}
