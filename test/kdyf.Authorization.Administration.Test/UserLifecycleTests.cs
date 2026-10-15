using System.Text.Json;
using kdyf.Authorization.Abstractions;
using kdyf.Authorization.Administration.Models;
using kdyf.Authorization.EntityFrameworkCore;
using kdyf.Authorization.EntityFrameworkCore.Entities;
using kdyf.Authorization.Roles;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;

namespace kdyf.Authorization.Administration.Test;

/// <summary>
/// What the packages gained for the applications that come from the legacy schema: suspending a person, their last
/// access, inviting with roles, and changing a role in one go.
/// </summary>
[TestClass]
public sealed class UserLifecycleTests
{
    private AccessFixture _f = null!;

    [TestInitialize]
    public void Setup() => _f = new AccessFixture();

    [TestCleanup]
    public void Cleanup() => _f.Dispose();

    private ServiceProvider Services(TimeProvider? time = null, TimeSpan? interval = null)
    {
        var services = new ServiceCollection();
        services.AddDbContext<AdminTestContext>(o => o.UseSqlite(_f.Db.Database.GetDbConnection()));
        services.AddSingleton(Options.Create(new AuthorizationStoreOptions { LastAccessInterval = interval ?? TimeSpan.FromMinutes(15) }));
        if (time is not null)
            services.AddSingleton(time);
        services.AddEfUserProfiles<AdminTestContext>();
        return services.BuildServiceProvider();
    }

    private EfUserProfileStore<AdminTestContext> Profiles(ServiceProvider services) =>
        services.CreateScope().ServiceProvider.GetRequiredService<EfUserProfileStore<AdminTestContext>>();

    /// <summary>The store the requests use, with the suspension read from the profiles.</summary>
    private IPermissionStore Store(ServiceProvider services)
    {
        var profiles = Profiles(services);
        return new MembershipPermissionStore(_f.Entra, new EfUserRoleSource<AdminTestContext>(_f.Db), _f.Provider,
            NullLogger<MembershipPermissionStore>.Instance, profiles, profiles);
    }

    private UserProfile? Profile(string objectId)
    {
        _f.Db.ChangeTracker.Clear();
        return _f.Db.Set<UserProfile>().AsNoTracking().SingleOrDefault(p => p.ObjectId == objectId);
    }

    // ── Suspension ───────────────────────────────────────────────────────────

    [TestMethod]
    public async Task A_suspended_person_holds_nothing_and_keeps_their_roles_for_later()
    {
        using var services = Services();
        Assert.IsTrue((await Store(services).GetPermissionsAsync(new UserIdentity(People.Editor, null))).Count > 0);

        var result = await _f.Access().SuspendAsync(People.Editor, _f.Actor(People.Admin), default);

        Assert.IsTrue(result.Validation.IsValid, Errors(result));
        Assert.IsTrue(result.Data.IsSuspended);
        Assert.IsFalse(result.Data.HasAccess);
        Assert.AreEqual(0, result.Data.Permissions.Count);
        Assert.AreEqual(0, (await Store(services).GetPermissionsAsync(new UserIdentity(People.Editor, null))).Count, "no permission, with a session or a token");
        CollectionAssert.AreEqual(new[] { "App.Editor" }, _f.RolesOf(People.Editor), "the roles stay");
        Assert.IsFalse(Profile(People.Editor)!.IsActive);
        Assert.AreEqual("editor@test", Profile(People.Editor)!.Email);

        var entry = _f.Audit().Single();
        Assert.AreEqual("access.suspended", entry.Action);
        Assert.AreEqual(People.Admin, entry.ActorObjectId);
        CollectionAssert.Contains(_f.Cache.Invalidated, People.Editor);
        Assert.AreEqual(0, _f.Entra.Writes.Count, "the group is not touched");
    }

    [TestMethod]
    public async Task Reactivating_gives_back_what_the_roles_grant()
    {
        using var services = Services();
        await _f.Access().SuspendAsync(People.Editor, _f.Actor(People.Admin), default);

        var result = await _f.Access().ReactivateAsync(People.Editor, _f.Actor(People.Admin), default);

        Assert.IsTrue(result.Validation.IsValid, Errors(result));
        Assert.IsFalse(result.Data.IsSuspended);
        CollectionAssert.IsSubsetOf(new[] { "apitest.Edit" }, (await Store(services).GetPermissionsAsync(new UserIdentity(People.Editor, null))).ToList());
        CollectionAssert.AreEqual(new[] { "access.suspended", "access.reactivated" }, _f.Audit().Select(e => e.Action).ToArray());
    }

    [TestMethod]
    public async Task Suspending_twice_is_one_change()
    {
        await _f.Access().SuspendAsync(People.Editor, _f.Actor(People.Admin), default);
        var again = await _f.Access().SuspendAsync(People.Editor, _f.Actor(People.Admin), default);

        Assert.IsTrue(again.Validation.IsValid);
        Assert.AreEqual(1, _f.Audit().Count);
    }

    [TestMethod]
    public async Task Nobody_suspends_themselves_nor_while_simulating()
    {
        var self = await _f.Access().SuspendAsync(People.Admin, _f.Actor(People.Admin), default);
        var simulating = await _f.Access().SuspendAsync(People.Editor, _f.Actor(People.Admin, simulatedBy: People.Manager), default);

        Assert.IsFalse(self.Validation.IsValid);
        Assert.IsFalse(simulating.Validation.IsValid);
        Assert.IsNull(Profile(People.Admin));
        Assert.IsNull(Profile(People.Editor));
    }

    /// <summary>Suspending takes away what the roles grant: nobody takes away more than they hold.</summary>
    [TestMethod]
    public async Task Nobody_suspends_somebody_holding_more_than_they_do()
    {
        var result = await _f.Access().SuspendAsync(People.Admin, _f.Actor(People.Manager), default);

        Assert.IsFalse(result.Validation.IsValid);
        StringAssert.Contains(Errors(result), "App.Admin");
        Assert.IsNull(Profile(People.Admin));
        Assert.AreEqual(0, _f.Audit().Count);
    }

    /// <summary>
    /// Admin and Manager both administer. Suspending one leaves the other; suspending the second would leave nobody,
    /// because a suspended administrator administers nothing.
    /// </summary>
    [TestMethod]
    public async Task The_last_administrator_cannot_be_suspended_and_a_suspended_one_does_not_count()
    {
        Assert.IsTrue((await _f.Access().SuspendAsync(People.Manager, _f.Outsider(), default)).Validation.IsValid, "Admin remains");

        var result = await _f.Access().SuspendAsync(People.Admin, _f.Outsider(), default);

        Assert.IsFalse(result.Validation.IsValid);
        StringAssert.Contains(Errors(result), "nobody able to administer");
        Assert.IsTrue(Profile(People.Admin) is null or { IsActive: true });
    }

    [TestMethod]
    public async Task Another_administrator_left_allows_the_suspension()
    {
        var result = await _f.Access().SuspendAsync(People.Admin, _f.Outsider(), default);

        Assert.IsTrue(result.Validation.IsValid, "Manager still administers: " + Errors(result));
    }

    [TestMethod]
    public async Task The_list_shows_who_is_suspended()
    {
        await _f.Access().SuspendAsync(People.Reader, _f.Actor(People.Admin), default);

        var users = (await _f.Access().ListUsersAsync(_f.Actor(People.Admin), default)).Data;

        var reader = users.Single(u => u.ObjectId == People.Reader);
        Assert.IsTrue(reader.IsSuspended);
        Assert.IsFalse(reader.HasAccess);
        Assert.IsFalse(users.Single(u => u.ObjectId == People.Editor).IsSuspended);
    }

    /// <summary>Nobody simulates a suspended person: their session would hold nothing.</summary>
    [TestMethod]
    public async Task A_suspended_person_is_not_a_simulation_target()
    {
        using var services = Services();
        var resolver = new MembershipSimulationTargetResolver(_f.Entra, new EfUserRoleSource<AdminTestContext>(_f.Db), _f.Provider, suspensions: Profiles(services));
        Assert.IsNotNull(await resolver.ResolveAsync("editor@test"));

        await _f.Access().SuspendAsync(People.Editor, _f.Actor(People.Admin), default);

        Assert.IsNull(await resolver.ResolveAsync("editor@test"));
    }

    // ── Last access ──────────────────────────────────────────────────────────

    [TestMethod]
    public async Task The_last_access_is_written_at_most_once_per_interval()
    {
        var time = new FakeTimeProvider(new DateTimeOffset(2026, 10, 15, 9, 0, 0, TimeSpan.Zero));
        using var services = Services(time, TimeSpan.FromMinutes(15));
        var reader = new UserIdentity(People.Reader, "Reader@Test");

        await Store(services).GetPermissionsAsync(reader);
        var first = Profile(People.Reader)!;
        Assert.AreEqual(time.GetUtcNow().UtcDateTime, first.LastLoginAt);
        Assert.IsTrue(first.IsActive, "being seen is not being suspended");
        Assert.AreEqual("reader@test", first.Email);

        time.Advance(TimeSpan.FromMinutes(10));
        await Store(services).GetPermissionsAsync(reader);
        Assert.AreEqual(first.LastLoginAt, Profile(People.Reader)!.LastLoginAt, "within the interval: not written");

        time.Advance(TimeSpan.FromMinutes(10));
        await Store(services).GetPermissionsAsync(reader);
        Assert.AreEqual(time.GetUtcNow().UtcDateTime, Profile(People.Reader)!.LastLoginAt);
    }

    [TestMethod]
    public async Task Somebody_without_access_is_not_recorded_as_seen()
    {
        using var services = Services();

        await Store(services).GetPermissionsAsync(new UserIdentity(People.Newcomer, "newcomer@test"));

        Assert.IsNull(Profile(People.Newcomer));
    }

    /// <summary>The recording is a courtesy: a failure to write it never denies anybody.</summary>
    [TestMethod]
    public async Task A_failure_to_record_the_last_access_does_not_deny()
    {
        var store = new MembershipPermissionStore(_f.Entra, new EfUserRoleSource<AdminTestContext>(_f.Db), _f.Provider,
            NullLogger<MembershipPermissionStore>.Instance, activity: new FailingRecorder());

        Assert.IsTrue((await store.GetPermissionsAsync(new UserIdentity(People.Reader, null))).Count > 0);
    }

    // ── Inviting with roles ──────────────────────────────────────────────────

    private DirectoryAdminService<AdminTestContext> Directory() => new(
        _f.Db, _f.Entra, _f.Entra, new Persistence.EfAuditLog<AdminTestContext>(_f.Db),
        NullLogger<DirectoryAdminService<AdminTestContext>>.Instance, access: _f.Access());

    [TestMethod]
    public async Task An_invitation_can_give_roles_in_the_same_operation()
    {
        var result = await Directory().InviteAsync(new InviteRequest { Email = "guest@outside.test", Roles = { "App.Reader" } }, _f.Actor(People.Admin), default);

        Assert.IsTrue(result.Validation.IsValid, Errors(result));
        var guest = result.Data.User.ObjectId;
        CollectionAssert.AreEqual(new[] { "App.Reader" }, _f.RolesOf(guest));
        CollectionAssert.AreEqual(new[] { "App.Reader" }, result.Data.User.Roles);
        var audit = _f.Audit();
        Assert.AreEqual("directory.invited", audit[0].Action);
        CollectionAssert.AreEqual(new[] { "App.Reader" }, JsonDocument.Parse(audit[0].Details!).RootElement.GetProperty("roles").EnumerateArray().Select(e => e.GetString()).ToArray());
        Assert.AreEqual("access.roles.changed", audit[1].Action);
    }

    /// <summary>A role the caller cannot give refuses the whole invitation, before anybody is invited.</summary>
    [TestMethod]
    public async Task An_invitation_with_a_role_beyond_the_caller_invites_nobody()
    {
        var result = await Directory().InviteAsync(new InviteRequest { Email = "guest@outside.test", Roles = { "App.Admin" } }, _f.Actor(People.Manager), default);

        Assert.IsFalse(result.Validation.IsValid);
        StringAssert.Contains(Errors(result), "App.Admin");
        Assert.AreEqual(0, _f.Entra.Writes.Count, "nobody was invited");
        Assert.AreEqual(0, _f.Audit().Count);
    }

    [TestMethod]
    public async Task An_invitation_with_a_role_that_does_not_exist_invites_nobody()
    {
        var result = await Directory().InviteAsync(new InviteRequest { Email = "guest@outside.test", Roles = { "App.Nope" } }, _f.Actor(People.Admin), default);

        Assert.IsFalse(result.Validation.IsValid);
        Assert.AreEqual(0, _f.Entra.Writes.Count);
    }

    /// <summary>Somebody already in the application keeps what they hold: the roles are added, never replaced.</summary>
    [TestMethod]
    public async Task Inviting_somebody_who_holds_roles_adds_to_them()
    {
        var result = await Directory().InviteAsync(new InviteRequest { Email = "reader@test", Roles = { "App.Editor" } }, _f.Actor(People.Admin), default);

        Assert.IsTrue(result.Validation.IsValid, Errors(result));
        Assert.IsFalse(result.Data.WasInvited);
        CollectionAssert.AreEqual(new[] { "App.Editor", "App.Reader" }, _f.RolesOf(People.Reader));
    }

    // ── A role in one go ─────────────────────────────────────────────────────

    [TestMethod]
    public async Task Name_description_and_permissions_change_together_in_one_audit_entry()
    {
        var read = (await _f.Access().GetRoleAsync("App.Reader", _f.Actor(People.Admin), default)).Data;

        var result = await _f.Access().UpdateRoleAsync("App.Reader",
            new UpdateRoleRequest { Name = "Readers", Description = "Read and edit", Permissions = new() { "apitest.Read", "apitest.Edit" }, Version = read.Version },
            _f.Actor(People.Admin), default);

        Assert.IsTrue(result.Validation.IsValid, Errors(result));
        Assert.AreEqual("Readers", result.Data.Name);
        CollectionAssert.AreEqual(new[] { "apitest.Edit", "apitest.Read" }, _f.Grants("App.Reader"));
        var entry = _f.Audit().Single();
        Assert.AreEqual("role.updated", entry.Action);
        var details = JsonDocument.Parse(entry.Details!).RootElement;
        Assert.AreEqual("Readers", details.GetProperty("name").GetProperty("to").GetString());
        CollectionAssert.AreEqual(new[] { "apitest.Edit" }, details.GetProperty("permissions").GetProperty("added").EnumerateArray().Select(e => e.GetString()).ToArray());
        CollectionAssert.Contains(_f.Cache.Invalidated, "*", "everybody holding it is affected");
    }

    /// <summary>A refused permission change leaves the name as it was too: all or nothing.</summary>
    [TestMethod]
    public async Task A_refused_permission_change_changes_nothing()
    {
        var result = await _f.Access().UpdateRoleAsync("App.Reader",
            new UpdateRoleRequest { Name = "Readers", Permissions = new() { "apitest.Read", "apitest.Admin" } },
            _f.Actor(People.Editor), default);

        Assert.IsFalse(result.Validation.IsValid);
        _f.Db.ChangeTracker.Clear();
        Assert.AreEqual("Reader", _f.Db.Set<Role>().AsNoTracking().Single(r => r.RoleValue == "App.Reader").Name);
        CollectionAssert.AreEqual(new[] { "apitest.Read" }, _f.Grants("App.Reader"));
        Assert.AreEqual(0, _f.Audit().Count);
    }

    /// <summary>The version covers the name too: an edit made on a stale read of either is refused.</summary>
    [TestMethod]
    public async Task A_stale_version_is_refused_even_when_only_the_name_changed_since()
    {
        var read = (await _f.Access().GetRoleAsync("App.Reader", _f.Actor(People.Admin), default)).Data;
        await _f.Access().UpdateRoleAsync("App.Reader", new UpdateRoleRequest { Name = "Renamed meanwhile" }, _f.Outsider(), default);

        var result = await _f.Access().UpdateRoleAsync("App.Reader",
            new UpdateRoleRequest { Name = "Mine", Permissions = new() { "apitest.Read", "apitest.Edit" }, Version = read.Version },
            _f.Actor(People.Admin), default);
        var permissionsOnly = await _f.Access().SetRolePermissionsAsync("App.Reader",
            new SetRolePermissionsRequest { Permissions = new() { "apitest.Read", "apitest.Edit" }, Version = read.Version },
            _f.Actor(People.Admin), default);

        Assert.IsFalse(result.Validation.IsValid);
        Assert.IsTrue(result.Validation.Fields.ContainsKey("version"));
        Assert.IsFalse(permissionsOnly.Validation.IsValid);
        CollectionAssert.AreEqual(new[] { "apitest.Read" }, _f.Grants("App.Reader"));
    }

    [TestMethod]
    public async Task A_rename_alone_still_works_as_before()
    {
        var result = await _f.Access().UpdateRoleAsync("App.Reader", new UpdateRoleRequest { Name = "Readers" }, _f.Actor(People.Admin), default);

        Assert.IsTrue(result.Validation.IsValid, Errors(result));
        Assert.AreEqual("role.updated", _f.Audit().Single().Action);
        CollectionAssert.AreEqual(new[] { "apitest.Read" }, _f.Grants("App.Reader"));
    }

    // ── Plumbing ─────────────────────────────────────────────────────────────

    private static SetRolesRequest Roles(params string[] roles) => new() { Roles = roles.ToList() };

    private static string Errors(Validation.ValidationResult result) =>
        string.Join("; ", result.Validation.Errors.Concat(result.Validation.Fields.SelectMany(f => f.Value.Errors.Select(e => $"{f.Key}: {e}"))));

    private sealed class FailingRecorder : IUserActivityRecorder
    {
        public Task RecordAsync(UserIdentity user, CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("the database is read-only");
    }
}
