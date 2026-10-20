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

    /// <summary>
    /// An id typed in upper case is the same person: stored the way their roles are keyed, so the token finds its owner's
    /// cache entry and their own list of tokens shows it.
    /// </summary>
    [TestMethod]
    public async Task The_owner_id_is_stored_the_way_the_roles_are_keyed()
    {
        var result = await _f.Tokens().CreateAsync(
            new CreatePatRequest { Name = "integration", OwnerObjectId = People.Reader.ToUpperInvariant() }, _f.Actor(People.Admin), default);

        Assert.IsTrue(result.Validation.IsValid, Errors(result));
        Assert.AreEqual(People.Reader, result.Data.OwnerObjectId);
        Assert.AreEqual(People.Reader, _f.Db.Set<PersonalAccessToken>().AsNoTracking().Single().OwnerObjectId);
        Assert.AreEqual(1, (await _f.Tokens().ListAsync(_f.Actor(People.Reader), default)).Data.Count);
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

    /// <summary>
    /// A lesser administrator may switch off a full administrator's token (a leaked token is stopped at once), but not
    /// switch it back on nor delete it: either would act on a credential worth more than themselves.
    /// </summary>
    [TestMethod]
    public async Task A_lesser_administrator_can_stop_a_stronger_owners_token_but_not_revive_or_delete_it()
    {
        var created = await _f.Tokens().CreateAsync(new CreatePatRequest { Name = "admin ci" }, _f.Actor(People.Admin), default);
        var id = created.Data.PersonalAccessTokenId;

        var stopped = await _f.Tokens().SetActiveAsync(id, false, _f.Actor(People.Manager), default);
        var revived = await _f.Tokens().SetActiveAsync(id, true, _f.Actor(People.Manager), default);
        var deleted = await _f.Tokens().DeleteAsync(id, _f.Actor(People.Manager), default);

        Assert.IsTrue(stopped.Validation.IsValid, Errors(stopped));
        Assert.IsFalse(revived.Validation.IsValid, "switching it back on");
        Assert.IsFalse(deleted.Validation.IsValid, "deleting it");
        _f.Db.ChangeTracker.Clear();
        var token = _f.Db.Set<PersonalAccessToken>().AsNoTracking().Single(t => t.PersonalAccessTokenId == id);
        Assert.IsFalse(token.IsActive, "still off, still there");

        Assert.IsTrue((await _f.Tokens().SetActiveAsync(id, true, _f.Actor(People.Admin), default)).Validation.IsValid, "its owner may switch it back on");
    }

    /// <summary>A token an administrator stopped stays stopped until an administrator revives it; one its owner stopped, they revive.</summary>
    [TestMethod]
    public async Task An_owner_cannot_revive_a_token_an_administrator_stopped()
    {
        var created = await _f.Tokens().CreateAsync(new CreatePatRequest { Name = "ci" }, _f.Actor(People.Reader), default);
        var id = created.Data.PersonalAccessTokenId;

        await _f.Tokens().SetActiveAsync(id, false, _f.Actor(People.Admin), default);
        var byTheOwner = await _f.Tokens().SetActiveAsync(id, true, _f.Actor(People.Reader), default);
        var byAnAdministrator = await _f.Tokens().SetActiveAsync(id, true, _f.Actor(People.Admin), default);

        await _f.Tokens().SetActiveAsync(id, false, _f.Actor(People.Reader), default);
        var stoppedByThemselves = await _f.Tokens().SetActiveAsync(id, true, _f.Actor(People.Reader), default);

        Assert.IsFalse(byTheOwner.Validation.IsValid);
        Assert.IsTrue(byAnAdministrator.Validation.IsValid, Errors(byAnAdministrator));
        Assert.IsTrue(stoppedByThemselves.Validation.IsValid, Errors(stoppedByThemselves));
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

    /// <summary>The name fits its column (100): a longer one is a validation error, not a database failure.</summary>
    [TestMethod]
    public async Task A_name_longer_than_its_column_is_refused_before_the_database()
    {
        var result = await _f.Tokens().CreateAsync(new CreatePatRequest { Name = new string('x', 101) }, _f.Actor(People.TokenUser), default);

        Assert.IsFalse(result.Validation.IsValid);
        StringAssert.Contains(Errors(result), "name");
    }

    /// <summary>
    /// An application token (client credentials) carries the service principal's 'oid', yet it is not a person: its
    /// changes could be attributed to nobody, so it is refused them, as a personal access token is.
    /// </summary>
    [TestMethod]
    public async Task An_application_token_is_not_a_person_even_with_an_object_id()
    {
        var app = new System.Security.Claims.ClaimsPrincipal(new System.Security.Claims.ClaimsIdentity(new[]
        {
            new System.Security.Claims.Claim("oid", "6a1a2ce1-0000-0000-0000-0000000000ff"),
            new System.Security.Claims.Claim("idtyp", "app"),
        }, "Bearer"));
        var actor = await new HoldsAdministration().ResolveActorAsync(app,
            new kdyf.Authorization.Authorization.ClaimsUserIdentityResolver(new kdyf.Authorization.PermissionAuthorizationOptions()), null);

        Assert.IsFalse(actor.IsPerson);
        Assert.IsFalse((await _f.Tokens().CreateAsync(new CreatePatRequest { Name = "ci" }, actor, default)).Validation.IsValid);
    }

    private static string Errors(Validation.ValidationResult result) =>
        string.Join("; ", result.Validation.Fields.SelectMany(f => f.Value.Errors.Select(e => $"{f.Key}: {e}")));

    /// <summary>Whoever asks holds the administration: what an app role named after it would give an application token.</summary>
    private sealed class HoldsAdministration : kdyf.Authorization.Abstractions.IPrincipalPermissionResolver
    {
        public Task<IReadOnlySet<string>> ResolveAsync(System.Security.Claims.ClaimsPrincipal principal, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlySet<string>>(new HashSet<string>(StringComparer.Ordinal) { AccessFixture.AdministrationCode });
    }
}
