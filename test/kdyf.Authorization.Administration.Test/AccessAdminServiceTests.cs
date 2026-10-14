using System.Text.Json;
using kdyf.Authorization.Administration.Models;
using kdyf.Authorization.Abstractions;
using kdyf.Authorization.EntityFrameworkCore.Entities;

namespace kdyf.Authorization.Administration.Test;

/// <summary>
/// Changing who has access — membership of the Entra access group, and the roles in the database. What gets
/// through, what is refused, and what a change leaves behind: the group, the rows, the audit line, the cache,
/// the event.
/// </summary>
[TestClass]
public sealed class AccessAdminServiceTests
{
    private AccessFixture _f = null!;

    [TestInitialize]
    public void Setup() => _f = new AccessFixture();

    [TestCleanup]
    public void Cleanup() => _f.Dispose();

    // ── Giving access ────────────────────────────────────────────────────────

    /// <summary>The roles grant nothing outside the group: somebody new is added to it first.</summary>
    [TestMethod]
    public async Task Giving_roles_to_somebody_outside_the_group_adds_them_to_it_first()
    {
        var result = await _f.Access().SetRolesAsync(People.Newcomer, Roles("App.Editor"), _f.Actor(People.Admin), default);

        Assert.IsTrue(result.Validation.IsValid, Errors(result));
        CollectionAssert.AreEqual(new[] { $"add {People.Newcomer}" }, _f.Entra.Writes);
        CollectionAssert.AreEqual(new[] { "App.Editor" }, _f.RolesOf(People.Newcomer));
        Assert.IsTrue(result.Data.HasAccess);
        CollectionAssert.IsSubsetOf(new[] { "Default", "apitest.Edit" }, result.Data.Permissions, "the base access plus the role");
        Assert.AreEqual("access.granted", _f.Audit().Single().Action);
    }

    /// <summary>
    /// The audit line names the REAL administrator by their Entra object id, and records the delta — not the
    /// final state.
    /// </summary>
    [TestMethod]
    public async Task A_change_is_audited_with_the_administrators_object_id_and_the_delta()
    {
        await _f.Access().SetRolesAsync(People.Reader, Roles("App.Editor"), _f.Actor(People.Admin), default);

        var entry = _f.Audit().Single();
        Assert.AreEqual(People.Admin, entry.ActorObjectId);
        Assert.AreEqual("admin@test", entry.ActorEmail);
        Assert.AreEqual("access.roles.changed", entry.Action);
        Assert.AreEqual(People.Reader, entry.TargetId);
        Assert.AreEqual("reader@test", entry.TargetLabel);

        var details = JsonDocument.Parse(entry.Details!).RootElement;
        CollectionAssert.AreEqual(new[] { "App.Editor" }, details.GetProperty("added").EnumerateArray().Select(e => e.GetString()).ToArray());
        CollectionAssert.AreEqual(new[] { "App.Reader" }, details.GetProperty("removed").EnumerateArray().Select(e => e.GetString()).ToArray());
        Assert.AreEqual(0, _f.Entra.Writes.Count, "already a member: the group is not touched");
    }

    /// <summary>The change is effective at once on this instance, and published for open sessions.</summary>
    [TestMethod]
    public async Task A_change_invalidates_the_persons_cached_permissions_and_is_published()
    {
        await _f.Access().SetRolesAsync(People.Reader, Roles(), _f.Actor(People.Admin), default);

        CollectionAssert.Contains(_f.Cache.Invalidated, People.Reader);
        var change = _f.Notifier.Changes.Single();
        Assert.AreEqual(People.Reader, change.SubjectId);
        Assert.AreEqual(People.Admin, change.ActorObjectId);
        CollectionAssert.AreEqual(new[] { "App.Reader" }, change.Removed.ToArray());
    }

    /// <summary>The event is a courtesy: a notifier that fails neither undoes nor fails the change.</summary>
    [TestMethod]
    public async Task A_failing_notifier_does_not_fail_the_change()
    {
        _f.Notifier.Fail = true;

        var result = await _f.Access().SetRolesAsync(People.Newcomer, Roles("App.Reader"), _f.Actor(People.Admin), default);

        Assert.IsTrue(result.Validation.IsValid, Errors(result));
        Assert.AreEqual(1, _f.Audit().Count);
    }

    /// <summary>An empty list takes the roles away and leaves the person in the group, with the base access.</summary>
    [TestMethod]
    public async Task An_empty_list_leaves_the_base_access_only()
    {
        var result = await _f.Access().SetRolesAsync(People.Reader, Roles(), _f.Actor(People.Admin), default);

        Assert.IsTrue(result.Validation.IsValid, Errors(result));
        Assert.AreEqual(0, _f.RolesOf(People.Reader).Count);
        Assert.IsTrue(_f.Entra.IsMember(People.Reader));
        CollectionAssert.AreEqual(new[] { "Default" }, result.Data.Permissions);
    }

    [TestMethod]
    public async Task Sending_the_same_roles_changes_nothing_and_audits_nothing()
    {
        var result = await _f.Access().SetRolesAsync(People.Reader, Roles("App.Reader"), _f.Actor(People.Admin), default);

        Assert.IsTrue(result.Validation.IsValid);
        Assert.AreEqual(0, _f.Entra.Writes.Count);
        Assert.AreEqual(0, _f.Audit().Count);
    }

    /// <summary>The group goes first: if Graph refuses, no role is left waiting for somebody who has no access.</summary>
    [TestMethod]
    public async Task When_the_group_refuses_the_newcomer_no_role_is_given()
    {
        _f.Entra.FailOnWrite = 1;

        var result = await _f.Access().SetRolesAsync(People.Newcomer, Roles("App.Reader"), _f.Actor(People.Admin), default);

        Assert.IsFalse(result.Validation.IsValid);
        Assert.IsTrue(result.Validation.Fields.ContainsKey("directory"));
        Assert.AreEqual(0, _f.RolesOf(People.Newcomer).Count);
        Assert.AreEqual(0, _f.Audit().Count);
    }

    // ── Taking access away ───────────────────────────────────────────────────

    /// <summary>
    /// Deleting a person takes their roles AND takes them out of the group — without the group, their next
    /// sign-in would still let them in. Their Entra account is not touched.
    /// </summary>
    [TestMethod]
    public async Task Revoking_removes_the_roles_and_takes_the_person_out_of_the_group()
    {
        var result = await _f.Access().RevokeAsync(People.Reader, _f.Actor(People.Admin), default);

        Assert.IsTrue(result.Validation.IsValid, Errors(result));
        Assert.AreEqual(0, _f.RolesOf(People.Reader).Count);
        Assert.IsFalse(_f.Entra.IsMember(People.Reader));
        CollectionAssert.AreEqual(new[] { $"remove {People.Reader}" }, _f.Entra.Writes, "only the membership: the account stays");
        Assert.IsNotNull(await _f.Entra.GetUserAsync(People.Reader));

        var entry = _f.Audit().Single();
        Assert.AreEqual("access.revoked", entry.Action);
        StringAssert.Contains(entry.Details, "App.Reader");
        CollectionAssert.Contains(_f.Cache.Invalidated, People.Reader);
    }

    /// <summary>
    /// The roles go first, so a Graph failure leaves the person with the base access at most — and the
    /// administrator is told, not left believing it worked.
    /// </summary>
    [TestMethod]
    public async Task When_the_group_refuses_the_removal_the_roles_are_gone_and_it_is_reported()
    {
        _f.Entra.FailOnWrite = 1;

        var result = await _f.Access().RevokeAsync(People.Reader, _f.Actor(People.Admin), default);

        Assert.IsFalse(result.Validation.IsValid);
        StringAssert.Contains(result.Validation.Fields["directory"].Errors.Single(), "roles were removed");
        Assert.AreEqual(0, _f.RolesOf(People.Reader).Count);
        Assert.IsTrue(_f.Entra.IsMember(People.Reader));
        Assert.AreEqual(1, _f.Audit().Count, "what was done is audited");
    }

    /// <summary>Only the direct membership can be removed: somebody also in a nested group is still in.</summary>
    [TestMethod]
    public async Task Somebody_still_in_through_a_nested_group_is_reported()
    {
        _f.Entra.NestIn(People.Reader);

        var result = await _f.Access().RevokeAsync(People.Reader, _f.Actor(People.Admin), default);

        Assert.IsFalse(result.Validation.IsValid);
        StringAssert.Contains(result.Validation.Fields["directory"].Errors.Single(), "nested group");
        Assert.AreEqual(0, _f.RolesOf(People.Reader).Count);
    }

    /// <summary>An account deleted in Entra leaves its roles behind; they can still be cleared.</summary>
    [TestMethod]
    public async Task The_roles_of_somebody_deleted_from_Entra_can_be_cleared()
    {
        _f.Entra.Delete(People.Reader);

        var result = await _f.Access().RevokeAsync(People.Reader, _f.Actor(People.Admin), default);

        Assert.IsTrue(result.Validation.IsValid, Errors(result));
        Assert.AreEqual(0, _f.RolesOf(People.Reader).Count);
        Assert.AreEqual(0, _f.Entra.Writes.Count);
    }

    [TestMethod]
    public async Task A_lesser_administrator_cannot_revoke_somebody_holding_more_than_they_do()
    {
        var result = await _f.Access().RevokeAsync(People.Admin, _f.Actor(People.Manager), default);

        AssertRefusedWithoutTrace(result, "roles");
        Assert.IsTrue(_f.Entra.IsMember(People.Admin));
    }

    [TestMethod]
    public async Task The_last_administrator_cannot_be_revoked()
    {
        _f.Entra.Disable(People.Manager);

        var result = await _f.Access().RevokeAsync(People.Admin, _f.Outsider(), default);

        AssertRefusedWithoutTrace(result, "roles");
    }

    // ── Who may not change access at all ─────────────────────────────────────

    /// <summary>Four eyes: an administrator cannot grant themselves more, nor quietly take themselves out.</summary>
    [TestMethod]
    public async Task Nobody_changes_their_own_access()
    {
        var more = await _f.Access().SetRolesAsync(People.Manager, Roles("App.UserManager", "App.Editor"), _f.Actor(People.Manager), default);
        var out_ = await _f.Access().RevokeAsync(People.Manager, _f.Actor(People.Manager), default);

        AssertRefusedWithoutTrace(more, "objectId");
        AssertRefusedWithoutTrace(out_, "objectId");
    }

    /// <summary>
    /// While simulating, the principal is the borrowed one: a change would be attributed —and self-checked—
    /// against the wrong person. The HTTP layer refuses writes first; this is the second wall.
    /// </summary>
    [TestMethod]
    public async Task No_change_is_accepted_while_simulating()
    {
        var borrowed = _f.Actor(People.Admin, simulatedBy: "someone.else@test");

        var result = await _f.Access().SetRolesAsync(People.Reader, Roles("App.Editor"), borrowed, default);

        AssertRefusedWithoutTrace(result, "actor");
    }

    /// <summary>A personal access token has no subject id: the audit log could not name a person.</summary>
    [TestMethod]
    public async Task A_caller_that_is_not_a_person_cannot_change_access()
    {
        var token = new AdminActor(new UserIdentity(null, null), _f.Roles.ForMember(new[] { "App.Admin" }));

        var result = await _f.Access().SetRolesAsync(People.Reader, Roles("App.Editor"), token, default);

        AssertRefusedWithoutTrace(result, "actor");
    }

    // ── Nobody hands out more than they hold ─────────────────────────────────

    [TestMethod]
    public async Task A_lesser_administrator_cannot_grant_a_role_beyond_their_own()
    {
        var result = await _f.Access().SetRolesAsync(People.Newcomer, Roles("App.Editor"), _f.Actor(People.Manager), default);

        AssertRefusedWithoutTrace(result, "roles");
    }

    [TestMethod]
    public async Task A_lesser_administrator_cannot_grant_the_administrator_role()
    {
        var result = await _f.Access().SetRolesAsync(People.Newcomer, Roles("App.Admin"), _f.Actor(People.Manager), default);

        AssertRefusedWithoutTrace(result, "roles");
    }

    /// <summary>Removing counts as much as granting: otherwise a lesser administrator could demote a full one.</summary>
    [TestMethod]
    public async Task A_lesser_administrator_cannot_remove_a_role_beyond_their_own()
    {
        var result = await _f.Access().SetRolesAsync(People.Admin, Roles(), _f.Actor(People.Manager), default);

        AssertRefusedWithoutTrace(result, "roles");
        CollectionAssert.AreEqual(new[] { "App.Admin" }, _f.RolesOf(People.Admin));
    }

    [TestMethod]
    public async Task A_lesser_administrator_can_hand_out_what_they_hold()
    {
        var result = await _f.Access().SetRolesAsync(People.Newcomer, Roles("App.Reader"), _f.Actor(People.Manager), default);

        Assert.IsTrue(result.Validation.IsValid, Errors(result));
        Assert.AreEqual(People.Manager, _f.Audit().Single().ActorObjectId);
    }

    /// <summary>A role the lesser administrator cannot touch is sent back unchanged, and stays.</summary>
    [TestMethod]
    public async Task A_role_the_caller_cannot_touch_is_kept_when_sent_back_unchanged()
    {
        _f.Entra.Add(People.SecondAdmin, "second@test");
        _f.Db.Add(AccessFixture.Holds(People.SecondAdmin, "App.Editor"));
        _f.Db.SaveChanges();

        var result = await _f.Access().SetRolesAsync(People.SecondAdmin, Roles("App.Editor", "App.Reader"), _f.Actor(People.Manager), default);

        Assert.IsTrue(result.Validation.IsValid, Errors(result));
        CollectionAssert.AreEqual(new[] { "App.Editor", "App.Reader" }, _f.RolesOf(People.SecondAdmin));
        Assert.IsFalse(result.Data.Roles.Single(r => r.Value == "App.Editor").Assignable);
    }

    // ── Only real roles and real people ──────────────────────────────────────

    [TestMethod]
    public async Task A_role_that_does_not_exist_is_refused()
    {
        var result = await _f.Access().SetRolesAsync(People.Newcomer, Roles("App.Superuser"), _f.Actor(People.Admin), default);

        AssertRefusedWithoutTrace(result, "roles");
    }

    [TestMethod]
    public async Task An_object_id_that_is_not_a_guid_never_reaches_the_directory()
    {
        var result = await _f.Access().SetRolesAsync("abc' or 1 eq 1", Roles("App.Reader"), _f.Actor(People.Admin), default);

        AssertRefusedWithoutTrace(result, "objectId");
    }

    /// <summary>No role for somebody Entra does not know: nobody could ever sign in to use it.</summary>
    [TestMethod]
    public async Task Nobody_outside_the_directory_is_given_a_role()
    {
        var result = await _f.Access().SetRolesAsync(Guid.NewGuid().ToString(), Roles("App.Reader"), _f.Actor(People.Admin), default);

        AssertRefusedWithoutTrace(result, "objectId");
    }

    // ── The lockout guard ────────────────────────────────────────────────────

    /// <summary>
    /// The last enabled administrator in the group cannot be demoted. The actor here administers without being
    /// one of the fixture's people, which is exactly the case where "the caller is an admin, so one remains"
    /// would be wrong.
    /// </summary>
    [TestMethod]
    public async Task The_last_enabled_administrator_cannot_be_removed()
    {
        _f.Entra.Disable(People.Manager); // the user manager also administers; disabled, it does not count

        var result = await _f.Access().SetRolesAsync(People.Admin, Roles("App.Reader"), _f.Outsider(), default);

        AssertRefusedWithoutTrace(result, "roles");
    }

    /// <summary>An administrator's role outside the group grants nothing: it does not count either.</summary>
    [TestMethod]
    public async Task An_administrator_outside_the_group_does_not_count()
    {
        _f.Entra.LeaveGroup(People.Manager);

        var result = await _f.Access().SetRolesAsync(People.Admin, Roles("App.Reader"), _f.Outsider(), default);

        AssertRefusedWithoutTrace(result, "roles");
    }

    [TestMethod]
    public async Task An_administrator_can_be_removed_while_another_enabled_one_remains()
    {
        var result = await _f.Access().SetRolesAsync(People.Manager, Roles("App.Reader"), _f.Actor(People.Admin), default);

        Assert.IsTrue(result.Validation.IsValid, Errors(result));
    }

    // ── When Entra fails ─────────────────────────────────────────────────────

    [TestMethod]
    public async Task When_the_directory_cannot_be_read_nothing_is_changed()
    {
        _f.Entra.ReadsFail = true;

        var result = await _f.Access().SetRolesAsync(People.Reader, Roles("App.Editor"), _f.Actor(People.Admin), default);

        AssertRefusedWithoutTrace(result, "directory");
        CollectionAssert.AreEqual(new[] { "App.Reader" }, _f.RolesOf(People.Reader));
    }

    // ── Reads ────────────────────────────────────────────────────────────────

    [TestMethod]
    public async Task The_list_shows_every_member_and_flags_the_roles_the_caller_cannot_change()
    {
        var users = (await _f.Access().ListUsersAsync(_f.Actor(People.Manager), default)).Data;

        var admin = users.Single(u => u.ObjectId == People.Admin);
        Assert.IsFalse(admin.Roles.Single().Assignable, "shown — hiding it would misstate who can do what — but not offered");
        Assert.IsTrue(users.Single(u => u.ObjectId == People.Manager).IsSelf);
        Assert.IsFalse(users.Any(u => u.ObjectId == People.Newcomer), "not in the group, no roles: not listed");
    }

    [TestMethod]
    public async Task A_disabled_account_is_listed_with_no_permissions()
    {
        _f.Entra.Disable(People.Editor);

        var editor = (await _f.Access().ListUsersAsync(_f.Actor(People.Admin), default)).Data.Single(u => u.ObjectId == People.Editor);

        Assert.IsFalse(editor.AccountEnabled);
        Assert.IsFalse(editor.HasAccess);
        Assert.AreEqual(0, editor.Permissions.Count);
    }

    /// <summary>Taken out of the group in the Entra portal: still listed — with roles that grant nothing.</summary>
    [TestMethod]
    public async Task Somebody_taken_out_of_the_group_is_listed_without_access()
    {
        _f.Entra.LeaveGroup(People.Reader);

        var reader = (await _f.Access().ListUsersAsync(_f.Actor(People.Admin), default)).Data.Single(u => u.ObjectId == People.Reader);

        Assert.IsFalse(reader.IsMember);
        Assert.IsFalse(reader.HasAccess);
        Assert.AreEqual(0, reader.Permissions.Count);
        Assert.AreEqual("App.Reader", reader.Roles.Single().Value);
    }

    [TestMethod]
    public async Task Somebody_deleted_from_Entra_with_roles_left_is_listed_as_not_in_the_directory()
    {
        _f.Entra.Delete(People.Reader);

        var reader = (await _f.Access().ListUsersAsync(_f.Actor(People.Admin), default)).Data.Single(u => u.ObjectId == People.Reader);

        Assert.IsFalse(reader.InDirectory);
        Assert.IsFalse(reader.HasAccess);
    }

    /// <summary>Being in the group is the base access: a member with no role can sign in, and do nothing else.</summary>
    [TestMethod]
    public async Task A_member_with_no_role_holds_the_base_access()
    {
        _f.Entra.Add(People.SecondAdmin, "second@test");

        var member = (await _f.Access().ListUsersAsync(_f.Actor(People.Admin), default)).Data.Single(u => u.ObjectId == People.SecondAdmin);

        Assert.IsTrue(member.HasAccess);
        CollectionAssert.AreEqual(new[] { "Default" }, member.Permissions);
    }

    [TestMethod]
    public async Task The_roles_say_who_could_hand_them_out_and_how_many_hold_them()
    {
        var roles = (await _f.Access().ListRolesAsync(_f.Actor(People.Manager), default)).Data;

        Assert.IsTrue(roles.Single(r => r.Value == "App.Reader").Assignable);
        Assert.IsFalse(roles.Single(r => r.Value == "App.Admin").Assignable);
        Assert.AreEqual(1, roles.Single(r => r.Value == "App.Reader").UserCount);
        Assert.AreEqual("Reader", roles.Single(r => r.Value == "App.Reader").Name, "the name stored with the role");
    }

    [TestMethod]
    public async Task The_catalog_says_what_every_member_holds()
    {
        var permissions = (await _f.Access().ListPermissionsAsync(default)).Data;

        Assert.IsTrue(permissions.Single(p => p.PermissionCode == "Default").HeldByEveryMember);
        Assert.IsFalse(permissions.Single(p => p.PermissionCode == "apitest.Read").HeldByEveryMember);
    }

    // ── Roles: created, renamed and deleted here ─────────────────────────────

    [TestMethod]
    public async Task A_created_role_can_be_given_at_once_and_is_audited()
    {
        var created = await _f.Access().CreateRoleAsync(
            new CreateRoleRequest { Value = "App.Auditor", Name = "Auditor", Permissions = ["apitest.Read"] }, _f.Actor(People.Admin), default);
        var given = await _f.Access().SetRolesAsync(People.Newcomer, Roles("App.Auditor"), _f.Actor(People.Admin), default);

        Assert.IsTrue(created.Validation.IsValid, Errors(created));
        Assert.AreEqual("Auditor", created.Data.Name);
        CollectionAssert.AreEqual(new[] { "apitest.Read" }, _f.Grants("App.Auditor"));
        Assert.IsTrue(given.Validation.IsValid, Errors(given));

        var entry = _f.Audit().First();
        Assert.AreEqual("role.created", entry.Action);
        Assert.AreEqual("App.Auditor", entry.TargetId);
        Assert.AreEqual(People.Admin, entry.ActorObjectId);
    }

    /// <summary>'App.Reader' and 'app.reader' side by side is a mistake waiting to be picked from a dropdown.</summary>
    [TestMethod]
    public async Task A_role_value_is_unique_ignoring_case()
    {
        var result = await _f.Access().CreateRoleAsync(new CreateRoleRequest { Value = "app.reader" }, _f.Actor(People.Admin), default);

        AssertRefusedWithoutTrace(result, "value");
    }

    [TestMethod]
    [DataRow("")]
    [DataRow("1App")]
    [DataRow("App Reader")]
    [DataRow("App'--")]
    public async Task A_role_value_is_a_plain_identifier(string value)
    {
        var result = await _f.Access().CreateRoleAsync(new CreateRoleRequest { Value = value }, _f.Actor(People.Admin), default);

        AssertRefusedWithoutTrace(result, "value");
    }

    [TestMethod]
    public async Task Nobody_creates_a_role_granting_what_they_do_not_hold()
    {
        var result = await _f.Access().CreateRoleAsync(
            new CreateRoleRequest { Value = "App.Writer", Permissions = ["apitest.Edit"] }, _f.Actor(People.Manager), default);

        AssertRefusedWithoutTrace(result, "permissions");
        Assert.IsFalse(_f.Roles.Exists("App.Writer"));
    }

    [TestMethod]
    public async Task Renaming_a_role_keeps_its_value_and_what_it_grants()
    {
        var result = await _f.Access().UpdateRoleAsync("App.Reader",
            new UpdateRoleRequest { Name = "Readers", Description = "Read-only" }, _f.Actor(People.Admin), default);

        Assert.IsTrue(result.Validation.IsValid, Errors(result));
        Assert.AreEqual("Readers", result.Data.Name);
        CollectionAssert.AreEqual(new[] { "apitest.Read" }, _f.Grants("App.Reader"));
        CollectionAssert.AreEqual(new[] { "App.Reader" }, _f.RolesOf(People.Reader));
        Assert.AreEqual("role.updated", _f.Audit().Single().Action);
    }

    /// <summary>
    /// Taken away from each person first: every one of those changes passes four eyes and the lockout guard,
    /// which deleting the role would sweep past.
    /// </summary>
    [TestMethod]
    public async Task A_role_somebody_holds_cannot_be_deleted()
    {
        var result = await _f.Access().DeleteRoleAsync("App.Reader", _f.Actor(People.Admin), default);

        AssertRefusedWithoutTrace(result, "roleValue");
        Assert.IsTrue(_f.Roles.Exists("App.Reader"));
    }

    [TestMethod]
    public async Task A_role_nobody_holds_is_deleted_with_what_it_grants()
    {
        await _f.Access().SetRolesAsync(People.TokenUser, Roles(), _f.Actor(People.Admin), default);

        var result = await _f.Access().DeleteRoleAsync("App.TokenUser", _f.Actor(People.Admin), default);

        Assert.IsTrue(result.Validation.IsValid, Errors(result));
        Assert.IsFalse(_f.Roles.Exists("App.TokenUser"));
        Assert.AreEqual(0, _f.Grants("App.TokenUser").Count);
        var entry = _f.Audit().Last();
        Assert.AreEqual("role.deleted", entry.Action);
        StringAssert.Contains(entry.Details, "apitest.Tokens", "what it granted is in the audit log");
    }

    [TestMethod]
    public async Task Nobody_deletes_a_role_granting_more_than_they_hold()
    {
        await _f.Access().SetRolesAsync(People.Editor, Roles(), _f.Actor(People.Admin), default);
        var before = _f.Audit().Count;

        var result = await _f.Access().DeleteRoleAsync("App.Editor", _f.Actor(People.Manager), default);

        Assert.IsFalse(result.Validation.IsValid);
        Assert.IsTrue(_f.Roles.Exists("App.Editor"));
        Assert.AreEqual(before, _f.Audit().Count);
    }

    [TestMethod]
    public async Task No_role_is_created_while_simulating_or_with_a_token()
    {
        var simulating = await _f.Access().CreateRoleAsync(new CreateRoleRequest { Value = "App.X" }, _f.Actor(People.Admin, simulatedBy: "x@test"), default);
        var token = await _f.Access().CreateRoleAsync(new CreateRoleRequest { Value = "App.X" },
            new AdminActor(new UserIdentity(null, null), _f.Roles.ForMember(new[] { "App.Admin" })), default);

        Assert.IsFalse(simulating.Validation.IsValid);
        Assert.IsFalse(token.Validation.IsValid);
        Assert.IsFalse(_f.Roles.Exists("App.X"));
    }

    // ── What a role grants ───────────────────────────────────────────────────

    [TestMethod]
    public async Task Configuring_a_role_changes_what_everybody_holding_it_may_do()
    {
        var result = await _f.Access().SetRolePermissionsAsync("App.Reader",
            Permissions("apitest.Read", "apitest.Edit"), _f.Actor(People.Admin), default);

        Assert.IsTrue(result.Validation.IsValid, Errors(result));
        CollectionAssert.AreEqual(new[] { "apitest.Edit", "apitest.Read" }, _f.Grants("App.Reader"));
        Assert.IsTrue(_f.Roles.EffectivePermissions(new[] { "App.Reader" }).Contains("apitest.Edit"),
            "the next read of the map sees it: the service invalidated the cached one");
        CollectionAssert.Contains(_f.Cache.Invalidated, "*", "every cached person is dropped: the role is shared");
    }

    [TestMethod]
    public async Task A_role_change_is_audited_with_the_administrators_object_id_and_the_delta()
    {
        await _f.Access().SetRolePermissionsAsync("App.Editor", Permissions("apitest.Read"), _f.Actor(People.Admin), default);

        var entry = _f.Audit().Single();
        Assert.AreEqual("role.permissions.changed", entry.Action);
        Assert.AreEqual("role", entry.TargetType);
        Assert.AreEqual("App.Editor", entry.TargetId);
        Assert.AreEqual(People.Admin, entry.ActorObjectId);
        var details = JsonDocument.Parse(entry.Details!).RootElement;
        CollectionAssert.AreEqual(new[] { "apitest.Edit" }, details.GetProperty("removed").EnumerateArray().Select(e => e.GetString()).ToArray());
        Assert.AreEqual(0, details.GetProperty("added").GetArrayLength());
    }

    /// <summary>
    /// The escalation this closes: an administrator with a lesser role configuring a role to grant what they do
    /// not hold, then holding it themselves through somebody else — or simply handing it out.
    /// </summary>
    [TestMethod]
    public async Task Nobody_configures_a_role_to_grant_what_they_do_not_hold()
    {
        var result = await _f.Access().SetRolePermissionsAsync("App.Reader",
            Permissions("apitest.Read", "apitest.Edit"), _f.Actor(People.Manager), default);

        AssertRoleUnchanged(result, "permissions", "App.Reader", "apitest.Read");
    }

    /// <summary>The wildcard is everything: only whoever holds everything can grant it.</summary>
    [TestMethod]
    public async Task Nobody_grants_the_wildcard_without_holding_it()
    {
        var result = await _f.Access().SetRolePermissionsAsync("App.Reader", Permissions("*"), _f.Actor(People.Manager), default);

        AssertRoleUnchanged(result, "permissions", "App.Reader", "apitest.Read");
    }

    [TestMethod]
    public async Task Nobody_removes_from_a_role_what_they_do_not_hold()
    {
        var result = await _f.Access().SetRolePermissionsAsync("App.Editor", Permissions("apitest.Read"), _f.Actor(People.Manager), default);

        AssertRoleUnchanged(result, "permissions", "App.Editor", "apitest.Edit", "apitest.Read");
    }

    /// <summary>Four eyes: changing what your own role grants is changing your own access.</summary>
    [TestMethod]
    public async Task Nobody_changes_what_a_role_they_hold_grants()
    {
        var result = await _f.Access().SetRolePermissionsAsync("App.UserManager", Permissions("apitest.Admin"), _f.Actor(People.Manager), default);

        AssertRoleUnchanged(result, "roleValue", "App.UserManager", "apitest.Admin", "apitest.Read");
    }

    /// <summary>
    /// Editing a role can take the administration away from everybody holding it at once. With the only full
    /// administrator disabled, the user managers are the last ones who can administer.
    /// </summary>
    [TestMethod]
    public async Task No_role_change_leaves_nobody_able_to_administer()
    {
        _f.Entra.Disable(People.Admin);

        var result = await _f.Access().SetRolePermissionsAsync("App.UserManager", Permissions("apitest.Read"), _f.Outsider(), default);

        AssertRoleUnchanged(result, "roles", "App.UserManager", "apitest.Admin", "apitest.Read");
    }

    [TestMethod]
    public async Task A_permission_the_application_does_not_declare_is_refused()
    {
        var result = await _f.Access().SetRolePermissionsAsync("App.Reader",
            Permissions("apitest.Read", "apitest.Reed"), _f.Actor(People.Admin), default);

        AssertRoleUnchanged(result, "permissions", "App.Reader", "apitest.Read");
    }

    /// <summary>A role is created on purpose, with POST /roles — never by configuring a name into existence.</summary>
    [TestMethod]
    public async Task A_role_that_does_not_exist_cannot_be_configured()
    {
        var result = await _f.Access().SetRolePermissionsAsync("App.Superuser", Permissions("apitest.Read"), _f.Actor(People.Admin), default);

        Assert.IsFalse(result.Validation.IsValid);
        Assert.AreEqual(0, _f.Grants("App.Superuser").Count);
        Assert.AreEqual(0, _f.Audit().Count);
    }

    /// <summary>The change REPLACES the set: without the version check, a concurrent edit would be lost silently.</summary>
    [TestMethod]
    public async Task A_role_changed_since_it_was_read_is_not_overwritten()
    {
        var read = (await _f.Access().GetRoleAsync("App.Reader", _f.Actor(People.Admin), default)).Data;
        await _f.Access().SetRolePermissionsAsync("App.Reader", Permissions("apitest.Read", "apitest.Tokens"), _f.Actor(People.Admin), default);

        var stale = await _f.Access().SetRolePermissionsAsync("App.Reader",
            new SetRolePermissionsRequest { Permissions = ["apitest.Read", "apitest.Edit"], Version = read.Version },
            _f.Actor(People.Admin), default);

        Assert.IsFalse(stale.Validation.IsValid);
        Assert.IsTrue(stale.Validation.Fields.ContainsKey("version"));
        CollectionAssert.AreEqual(new[] { "apitest.Read", "apitest.Tokens" }, _f.Grants("App.Reader"));
    }

    [TestMethod]
    public async Task No_role_is_configured_while_simulating_or_with_a_token()
    {
        var simulating = await _f.Access().SetRolePermissionsAsync("App.Reader", Permissions(), _f.Actor(People.Admin, simulatedBy: "x@test"), default);
        var token = await _f.Access().SetRolePermissionsAsync("App.Reader", Permissions(),
            new AdminActor(new UserIdentity(null, null), _f.Roles.ForMember(new[] { "App.Admin" })), default);

        Assert.IsFalse(simulating.Validation.IsValid);
        Assert.IsFalse(token.Validation.IsValid);
        CollectionAssert.AreEqual(new[] { "apitest.Read" }, _f.Grants("App.Reader"));
    }

    [TestMethod]
    public async Task The_roles_say_which_ones_the_caller_may_edit()
    {
        var roles = (await _f.Access().ListRolesAsync(_f.Actor(People.Manager), default)).Data;

        Assert.IsTrue(roles.Single(r => r.Value == "App.Reader").Editable);
        Assert.IsFalse(roles.Single(r => r.Value == "App.UserManager").Editable, "their own role");
        Assert.IsFalse(roles.Single(r => r.Value == "App.Editor").Editable, "grants more than they hold");
    }

    // ── What is left behind ──────────────────────────────────────────────────

    [TestMethod]
    public async Task The_check_reports_what_is_left_behind()
    {
        _f.Db.Add(new Role { RoleValue = "App.Auditor", Name = "Auditor", CreatedAt = DateTime.UtcNow });   // grants nothing yet
        _f.Db.SaveChanges();
        _f.LeaveBehind("App.Reader", "apitest.Reed");                                                       // not declared
        _f.Entra.LeaveGroup(People.Editor);                                                                 // out of the group
        _f.Entra.Delete(People.TokenUser);                                                                  // deleted from Entra

        var report = (await _f.Access().CheckRoleConsistencyAsync(_f.Actor(People.Admin), default)).Data;

        CollectionAssert.AreEqual(new[] { "App.Auditor" }, report.UnconfiguredRoles);
        CollectionAssert.AreEqual(new[] { "apitest.Reed" }, report.UnknownPermissions.Single(u => u.Value == "App.Reader").Permissions);
        CollectionAssert.AreEqual(new[] { "apitest.Reed" }, report.UndeclaredCatalogPermissions);

        var editor = report.FormerMembers.Single(m => m.ObjectId == People.Editor);
        Assert.AreEqual("editor@test", editor.Label);
        Assert.IsTrue(editor.InDirectory);
        CollectionAssert.AreEqual(new[] { "App.Editor" }, editor.Roles);
        Assert.IsFalse(report.FormerMembers.Single(m => m.ObjectId == People.TokenUser).InDirectory);

        Assert.AreEqual(0, _f.Audit().Count, "a check changes nothing");
    }

    /// <summary>
    /// A permission class removed in an update leaves its code configured. The cleanup removes that code — and
    /// only that code — so a permission declared later with the same code does not silently reach the role.
    /// </summary>
    [TestMethod]
    public async Task Deleting_orphans_removes_codes_the_application_no_longer_declares()
    {
        _f.LeaveBehind("App.Reader", "apitest.Retired");

        var result = await _f.Access().DeleteOrphansAsync(_f.Actor(People.Admin), default);

        Assert.IsTrue(result.Validation.IsValid, Errors(result));
        var removed = result.Data.RemovedPermissions.Single();
        Assert.AreEqual("App.Reader", removed.Value);
        CollectionAssert.AreEqual(new[] { "apitest.Retired" }, removed.Permissions);
        CollectionAssert.AreEqual(new[] { "apitest.Read" }, _f.Grants("App.Reader"), "the declared codes stay");

        CollectionAssert.AreEqual(new[] { "apitest.Retired" }, result.Data.RemovedCatalogPermissions);
        CollectionAssert.DoesNotContain(_f.Catalog(), "apitest.Retired", "and so does its catalog row, once nothing grants it");

        var audit = _f.Audit();
        var grant = audit.Single(e => e.Action == "role.permissions.changed");
        Assert.AreEqual("App.Reader", grant.TargetId);
        StringAssert.Contains(grant.Details, "not declared by the application");
        Assert.AreEqual("apitest.Retired", audit.Single(e => e.Action == "permission.deleted").TargetId);
    }

    /// <summary>A catalog row nobody grants and no class declares is removed too: the catalog mirrors the code.</summary>
    [TestMethod]
    public async Task Deleting_orphans_removes_catalog_rows_no_class_declares()
    {
        _f.Db.Add(AccessFixture.CatalogRow("apitest.Gone"));
        _f.Db.SaveChanges();

        var result = await _f.Access().DeleteOrphansAsync(_f.Actor(People.Admin), default);

        CollectionAssert.AreEqual(new[] { "apitest.Gone" }, result.Data.RemovedCatalogPermissions);
        CollectionAssert.DoesNotContain(_f.Catalog(), "apitest.Gone");
        CollectionAssert.Contains(_f.Catalog(), "apitest.Read", "declared rows stay");
    }

    /// <summary>
    /// A declared permission the startup synchronisation could not write is refused with the reason — not
    /// left to the foreign key, which would answer with a database error.
    /// </summary>
    [TestMethod]
    public async Task A_permission_missing_from_the_catalog_cannot_be_granted()
    {
        _f.Db.Remove(_f.Db.Set<Permission>().Single(p => p.PermissionCode == "apitest.Simulate"));
        _f.Db.SaveChanges();

        var result = await _f.Access().SetRolePermissionsAsync("App.Reader", Permissions("apitest.Read", "apitest.Simulate"), _f.Actor(People.Admin), default);

        AssertRoleUnchanged(result, "permissions", "App.Reader", "apitest.Read");
        StringAssert.Contains(result.Validation.Fields["permissions"].Errors.Single(), "catalog");
    }

    /// <summary>
    /// Somebody taken out of the group in the Entra portal keeps their rows. The cleanup removes them — otherwise
    /// adding the person back to the group, for any reason, would silently bring the old roles back.
    /// </summary>
    [TestMethod]
    public async Task Deleting_orphans_removes_the_roles_of_former_members()
    {
        _f.Entra.LeaveGroup(People.Editor);

        var result = await _f.Access().DeleteOrphansAsync(_f.Actor(People.Admin), default);

        Assert.IsTrue(result.Validation.IsValid, Errors(result));
        Assert.AreEqual(People.Editor, result.Data.RemovedMembers.Single().ObjectId);
        Assert.AreEqual(0, _f.RolesOf(People.Editor).Count);
        CollectionAssert.AreEqual(new[] { "App.Reader" }, _f.RolesOf(People.Reader), "members keep theirs");

        var entry = _f.Audit().Single();
        Assert.AreEqual("access.roles.changed", entry.Action);
        Assert.AreEqual(People.Editor, entry.TargetId);
        StringAssert.Contains(entry.Details, "not a member of the access group");
    }

    [TestMethod]
    public async Task With_nothing_left_behind_nothing_is_deleted_or_audited()
    {
        var result = await _f.Access().DeleteOrphansAsync(_f.Actor(People.Admin), default);

        Assert.IsTrue(result.Validation.IsValid);
        Assert.AreEqual(0, result.Data.RemovedMembers.Count + result.Data.RemovedPermissions.Count);
        Assert.AreEqual(0, _f.Audit().Count);
    }

    /// <summary>If the group cannot be read, everybody would look like a former member. Nothing is deleted.</summary>
    [TestMethod]
    public async Task When_the_group_cannot_be_read_nothing_is_deleted()
    {
        _f.Entra.ReadsFail = true;

        var result = await _f.Access().DeleteOrphansAsync(_f.Actor(People.Admin), default);

        Assert.IsFalse(result.Validation.IsValid);
        CollectionAssert.AreEqual(new[] { "App.Reader" }, _f.RolesOf(People.Reader));
        Assert.AreEqual(0, _f.Audit().Count);
    }

    [TestMethod]
    public async Task Nothing_is_cleaned_up_while_simulating_or_with_a_token()
    {
        _f.Entra.LeaveGroup(People.Editor);

        var simulating = await _f.Access().DeleteOrphansAsync(_f.Actor(People.Admin, simulatedBy: "x@test"), default);
        var token = await _f.Access().DeleteOrphansAsync(
            new AdminActor(new UserIdentity(null, null), _f.Roles.ForMember(new[] { "App.Admin" })), default);

        Assert.IsFalse(simulating.Validation.IsValid);
        Assert.IsFalse(token.Validation.IsValid);
        CollectionAssert.AreEqual(new[] { "App.Editor" }, _f.RolesOf(People.Editor));
    }

    // ── Plumbing ─────────────────────────────────────────────────────────────

    private static SetRolePermissionsRequest Permissions(params string[] codes) => new() { Permissions = codes.ToList() };

    private void AssertRoleUnchanged(Validation.ValidationResult result, string field, string role, params string[] grants)
    {
        Assert.IsFalse(result.Validation.IsValid, "refused");
        Assert.IsTrue(result.Validation.Fields.ContainsKey(field), $"on '{field}', got: {string.Join(", ", result.Validation.Fields.Keys)}");
        CollectionAssert.AreEqual(grants.OrderBy(g => g, StringComparer.Ordinal).ToArray(), _f.Grants(role).OrderBy(g => g, StringComparer.Ordinal).ToArray(), "the role is unchanged");
        Assert.AreEqual(0, _f.Audit().Count, "nothing was audited");
    }

    private static SetRolesRequest Roles(params string[] roles) => new() { Roles = roles.ToList() };

    private void AssertRefusedWithoutTrace(Validation.ValidationResult result, string field)
    {
        Assert.IsFalse(result.Validation.IsValid, "refused");
        Assert.IsTrue(result.Validation.Fields.ContainsKey(field), $"on '{field}', got: {string.Join(", ", result.Validation.Fields.Keys)}");
        Assert.AreEqual(0, _f.Entra.Writes.Count, "nothing reached Entra");
        Assert.AreEqual(0, _f.Audit().Count, "nothing was audited");
        Assert.AreEqual(0, _f.Notifier.Changes.Count, "nothing was published");
    }

    private static string Errors(Validation.ValidationResult result) =>
        string.Join("; ", result.Validation.Fields.SelectMany(f => f.Value.Errors.Select(e => $"{f.Key}: {e}")));
}
