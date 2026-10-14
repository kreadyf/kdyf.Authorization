using kdyf.Authorization.Administration.Abstractions;
using kdyf.Authorization.Administration.Persistence;
using kdyf.Authorization;
using kdyf.Authorization.Abstractions;
using kdyf.Authorization.EntityFrameworkCore;
using kdyf.Authorization.EntityFrameworkCore.Entities;
using kdyf.Authorization.Roles;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;

namespace kdyf.Authorization.Administration.Test;

/// <summary>People of the test tenant. Entra object ids are GUIDs, and the services check that they are.</summary>
internal static class People
{
    internal const string Admin = "00000000-0000-0000-0000-00000000000a";
    internal const string SecondAdmin = "00000000-0000-0000-0000-00000000000b";
    internal const string Manager = "00000000-0000-0000-0000-00000000000c";
    internal const string Editor = "00000000-0000-0000-0000-00000000000d";
    internal const string Reader = "00000000-0000-0000-0000-00000000000e";
    internal const string Newcomer = "00000000-0000-0000-0000-00000000000f";
    internal const string TokenUser = "00000000-0000-0000-0000-000000000010";
}

/// <summary>
/// One SQLite database (roles, who holds them, tokens and audit log), one in-memory Entra with its access
/// group, and the real permission catalog of this assembly, per test.
/// </summary>
/// <remarks>
/// Admin, Manager, Editor, Reader and TokenUser are in the group, each holding one role. Newcomer is in the
/// tenant, outside the group, with no role.
/// </remarks>
internal sealed class AccessFixture : IDisposable
{
    private readonly SqliteConnection _connection;

    internal AccessFixture()
    {
        _connection = new SqliteConnection("DataSource=:memory:");
        _connection.Open();
        Db = new AdminTestContext(new DbContextOptionsBuilder<AdminTestContext>().UseSqlite(_connection).Options);
        Db.Database.EnsureCreated();

        Declared = new DeclaredPermissions(PermissionDefinition.DiscoverIn(typeof(AccessFixture).Assembly));

        // What the startup synchronisation leaves: one catalog row per declared permission.
        Db.AddRange(Declared.Permissions.Select(p => CatalogRow(p.Code)));
        Db.AddRange(apitest.TestRoleConfiguration.Roles());
        Db.AddRange(apitest.TestRoleConfiguration.Rows());
        Db.AddRange(
            Holds(People.Admin, "App.Admin"),
            Holds(People.Manager, "App.UserManager"),
            Holds(People.Editor, "App.Editor"),
            Holds(People.Reader, "App.Reader"),
            Holds(People.TokenUser, "App.TokenUser"));
        Db.SaveChanges();
        Db.ChangeTracker.Clear();

        // The real sources over the real tables: a change the service saves is what the next read sees.
        Provider = RolePermissionMapProvider.ForSource(
            new EfRolePermissionSource<AdminTestContext>(Db), Declared, TimeSpan.FromMinutes(2), apitest.TestRoleConfiguration.MemberGrants);

        Entra = new FakeEntra()
            .Add(People.Admin, "admin@test")
            .Add(People.Manager, "manager@test")
            .Add(People.Editor, "editor@test")
            .Add(People.Reader, "reader@test")
            .Add(People.TokenUser, "tokens@test")
            .Add(People.Newcomer, "newcomer@test", member: false);
    }

    internal AdminTestContext Db { get; }
    internal DeclaredPermissions Declared { get; }
    internal RolePermissionMapProvider Provider { get; }
    internal FakeEntra Entra { get; }
    internal RecordingCache Cache { get; } = new();
    internal RecordingNotifier Notifier { get; } = new();

    /// <summary>What each role grants right now, as the service would read it.</summary>
    internal RolePermissionMap Roles => Provider.GetAsync().GetAwaiter().GetResult();

    internal static string AdministrationCode => new apitest.AdminPermission().Code;

    internal static UserRole Holds(string objectId, string role) => new() { ObjectId = objectId, RoleValue = role };

    internal static Permission CatalogRow(string code) => new() { PermissionCode = code, Name = code };

    /// <summary>
    /// A code configured for a role whose class no longer exists: its catalog row stays behind (the
    /// synchronisation never deletes), and so does the grant.
    /// </summary>
    internal void LeaveBehind(string role, string code)
    {
        Db.Add(CatalogRow(code));
        Db.Add(new RolePermission { RoleValue = role, PermissionCode = code });
        Db.SaveChanges();
        Db.ChangeTracker.Clear();
        Provider.Invalidate();
    }

    /// <summary>The catalog as stored.</summary>
    internal List<string> Catalog()
    {
        Db.ChangeTracker.Clear();
        return Db.Set<Permission>().AsNoTracking().Select(p => p.PermissionCode).OrderBy(c => c).ToList();
    }

    internal AccessAdminService<AdminTestContext> Access() => new(
        Db, Entra, Provider, Declared, Cache, new EfAuditLog<AdminTestContext>(Db), Notifier,
        NullLogger<AccessAdminService<AdminTestContext>>.Instance,
        new PermissionAuthorizationOptions { AdministrationPermissionCode = AdministrationCode });

    internal PatAdminService<AdminTestContext> Tokens() => new(
        Db, PermissionStore(), new EfAuditLog<AdminTestContext>(Db),
        new PermissionAuthorizationOptions { AdministrationPermissionCode = AdministrationCode }, Entra);

    internal IPermissionStore PermissionStore() =>
        new MembershipPermissionStore(Entra, new EfUserRoleSource<AdminTestContext>(Db), Provider, NullLogger<MembershipPermissionStore>.Instance);

    /// <summary>The rows of one role, as stored.</summary>
    internal List<string> Grants(string role)
    {
        Db.ChangeTracker.Clear();
        return Db.Set<RolePermission>().AsNoTracking().Where(r => r.RoleValue == role)
            .Select(r => r.PermissionCode).OrderBy(c => c).ToList();
    }

    /// <summary>The roles one person holds, as stored.</summary>
    internal List<string> RolesOf(string objectId)
    {
        Db.ChangeTracker.Clear();
        return Db.Set<UserRole>().AsNoTracking().Where(r => r.ObjectId == objectId)
            .Select(r => r.RoleValue).OrderBy(r => r).ToList();
    }

    /// <summary>The actor as the endpoints build it: identity from the token, permissions from the group and roles.</summary>
    internal AdminActor Actor(string objectId, string? simulatedBy = null) =>
        new(new UserIdentity(objectId, Email(objectId)),
            Entra.IsMember(objectId) ? Roles.ForMember(RolesOf(objectId)) : new HashSet<string>(), simulatedBy);

    /// <summary>An administrator who is not one of the fixture's people, holding everything.</summary>
    internal AdminActor Outsider() =>
        new(new UserIdentity(People.SecondAdmin, "outsider@test"), Roles.ForMember(new[] { "App.Admin" }));

    internal List<AuditLogEntry> Audit()
    {
        Db.ChangeTracker.Clear();
        return Db.Set<AuditLogEntry>().AsNoTracking().OrderBy(e => e.AuditLogId).ToList();
    }

    private static string Email(string objectId) => objectId switch
    {
        People.Admin => "admin@test",
        People.Manager => "manager@test",
        People.Editor => "editor@test",
        People.Reader => "reader@test",
        People.TokenUser => "tokens@test",
        _ => "someone@test"
    };

    public void Dispose()
    {
        Db.Dispose();
        _connection.Dispose();
    }
}

/// <summary>The consumer's context: both models on one context, as the package tells consumers.</summary>
internal sealed class AdminTestContext : DbContext
{
    public AdminTestContext(DbContextOptions<AdminTestContext> options) : base(options) { }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        modelBuilder.ApplyAuthorizationModel();
        modelBuilder.ApplyAdministrationModel();
    }
}

internal sealed class RecordingCache : IPermissionCache
{
    internal List<string?> Invalidated { get; } = new();

    public void Invalidate(UserIdentity user) => Invalidated.Add(user.SubjectId);

    public void InvalidateAll() => Invalidated.Add("*");
}

internal sealed class RecordingNotifier : IAccessChangeNotifier
{
    internal List<AccessChange> Changes { get; } = new();

    internal bool Fail { get; set; }

    public Task NotifyAsync(AccessChange change, CancellationToken cancellationToken = default)
    {
        if (Fail)
            throw new InvalidOperationException("SignalR is down");
        Changes.Add(change);
        return Task.CompletedTask;
    }
}
