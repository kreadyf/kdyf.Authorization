using kdyf.Authorization.EntityFrameworkCore.Entities;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace kdyf.Authorization.EntityFrameworkCore.Test;

/// <summary>The catalog, the roles and what each grants (<c>auth.Permission</c>, <c>auth.Role</c>, <c>auth.RolePermission</c>), and who holds which (<c>auth.UserRole</c>).</summary>
[TestClass]
public sealed class EfRoleSourcesTests : IDisposable
{
    private const string Ana = "0f1e2d3c-0000-0000-0000-00000000000a";

    private readonly SqliteConnection _connection;
    private readonly TestAuthContext _db;

    public EfRoleSourcesTests()
    {
        _connection = new SqliteConnection("DataSource=:memory:");
        _connection.Open();
        _db = new TestAuthContext(new DbContextOptionsBuilder<TestAuthContext>().UseSqlite(_connection).Options);
        _db.Database.EnsureCreated();
        _db.AddRange(Catalog("portal.Read"), Catalog("*"));
        _db.AddRange(Role("Portal.Reader"), Role("Portal.Admin"), Role("Portal.Auditor"));
        _db.AddRange(Row("Portal.Reader", "portal.Read"), Row("Portal.Admin", "*"));
        _db.SaveChanges();
        _db.ChangeTracker.Clear();
    }

    [TestMethod]
    public async Task Every_role_comes_back_with_its_codes_even_one_that_grants_nothing_yet()
    {
        var grants = await new EfRolePermissionSource<TestAuthContext>(_db).GetAllAsync();

        CollectionAssert.AreEqual(new[] { "portal.Read" }, grants["Portal.Reader"].ToArray());
        CollectionAssert.AreEqual(new[] { "*" }, grants["Portal.Admin"].ToArray());
        Assert.AreEqual(0, grants["Portal.Auditor"].Count, "it exists, and can be given");
        Assert.IsFalse(grants.ContainsKey("portal.admin"), "role values are compared exactly");
    }

    /// <summary>One permission per role once: the key is the pair.</summary>
    [TestMethod]
    public void A_role_cannot_grant_the_same_permission_twice()
    {
        _db.Add(Row("Portal.Reader", "portal.Read"));

        Assert.ThrowsException<DbUpdateException>(() => _db.SaveChanges());
    }

    /// <summary>A grant or a holder of a role that does not exist is refused by the database itself.</summary>
    [TestMethod]
    public void Nothing_points_at_a_role_that_does_not_exist()
    {
        _db.Add(Row("Portal.Ghost", "portal.Read"));
        Assert.ThrowsException<DbUpdateException>(() => _db.SaveChanges());
        _db.ChangeTracker.Clear();

        _db.Add(new UserRole { ObjectId = Ana, RoleValue = "Portal.Ghost" });
        Assert.ThrowsException<DbUpdateException>(() => _db.SaveChanges());
    }

    [TestMethod]
    public async Task A_persons_roles_are_read_by_their_object_id_in_any_case()
    {
        _db.AddRange(new UserRole { ObjectId = Ana, RoleValue = "Portal.Reader" }, new UserRole { ObjectId = Ana, RoleValue = "Portal.Auditor" });
        _db.SaveChanges();

        var roles = await new EfUserRoleSource<TestAuthContext>(_db).GetRolesAsync(Ana.ToUpperInvariant());

        CollectionAssert.AreEquivalent(new[] { "Portal.Reader", "Portal.Auditor" }, roles.ToArray());
    }

    [TestMethod]
    public async Task Somebody_with_no_row_holds_no_role() =>
        Assert.AreEqual(0, (await new EfUserRoleSource<TestAuthContext>(_db).GetRolesAsync(Ana)).Count);

    /// <summary>A role somebody holds cannot be deleted from under them: it is taken away person by person first.</summary>
    [TestMethod]
    public void A_role_somebody_holds_cannot_be_deleted()
    {
        _db.Add(new UserRole { ObjectId = Ana, RoleValue = "Portal.Reader" });
        _db.SaveChanges();
        _db.ChangeTracker.Clear();

        _db.Remove(_db.Set<Role>().Single(r => r.RoleValue == "Portal.Reader"));

        Assert.ThrowsException<DbUpdateException>(() => _db.SaveChanges());
    }

    /// <summary>Only a code of the catalog can be granted: the grant points at its row.</summary>
    [TestMethod]
    public void A_code_missing_from_the_catalog_cannot_be_granted()
    {
        _db.Add(Row("Portal.Reader", "portal.Edit"));

        Assert.ThrowsException<DbUpdateException>(() => _db.SaveChanges());
    }

    /// <summary>A catalog row a role grants cannot be deleted from under it.</summary>
    [TestMethod]
    public void A_granted_catalog_row_cannot_be_deleted()
    {
        _db.Remove(_db.Set<Permission>().Single(p => p.PermissionCode == "portal.Read"));

        Assert.ThrowsException<DbUpdateException>(() => _db.SaveChanges());
    }

    private static Permission Catalog(string code) => new() { PermissionCode = code, Name = code };

    private static Role Role(string value) => new() { RoleValue = value, Name = value, CreatedAt = DateTime.UtcNow };

    private static RolePermission Row(string role, string code) => new() { RoleValue = role, PermissionCode = code };

    public void Dispose()
    {
        _db.Dispose();
        _connection.Dispose();
    }
}
