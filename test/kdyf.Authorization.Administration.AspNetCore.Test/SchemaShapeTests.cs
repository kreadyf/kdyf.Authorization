using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using kdyf.Authorization.Administration.AspNetCore;
using kdyf.Authorization.EntityFrameworkCore;

namespace kdyf.Authorization.Administration.AspNetCore.Test;

/// <summary>
/// The tables EF creates are the shape the library's databases already have (version 1 of the schema): role values
/// and permission codes compared exactly on SQL Server, the audit log's action and target type as varchar.
/// </summary>
/// <remarks>
/// A database created from the model and one created from a host's script must not differ: a schema migration adopts
/// one by comparing it with the other, and a case-insensitive key would make 'Portal.Admin' and 'portal.admin' one role
/// while the code tells them apart.
/// </remarks>
[TestClass]
public sealed class SchemaShapeTests
{
    private const string Bin2 = "COLLATE Latin1_General_100_BIN2";

    [TestMethod]
    public void On_SQL_Server_role_values_and_permission_codes_are_compared_exactly()
    {
        var ddl = Script(o => o.UseSqlServer("Server=unused"));

        foreach (var table in new[] { "Role", "RolePermission", "UserRole" })
            StringAssert.Contains(Column(ddl, table, "roleValue"), $"varchar(100) {Bin2} NOT NULL", table);
        foreach (var table in new[] { "Permission", "RolePermission" })
            StringAssert.Contains(Column(ddl, table, "PermissionCode"), $"varchar(50) {Bin2} NOT NULL", table);

        // The object id is normalised to lower case before it is stored: no binary collation needed, and none in the
        // databases that exist.
        Assert.IsFalse(Column(ddl, "UserRole", "objectId").Contains("COLLATE"), Column(ddl, "UserRole", "objectId"));
    }

    [TestMethod]
    public void The_audit_logs_action_and_target_type_are_varchar()
    {
        var ddl = Script(o => o.UseSqlServer("Server=unused"));

        StringAssert.StartsWith(Column(ddl, "AuditLog", "action").Trim(), "[action] varchar(40) NOT NULL");
        StringAssert.StartsWith(Column(ddl, "AuditLog", "targetType").Trim(), "[targetType] varchar(20) NOT NULL");
    }

    /// <summary>SQLite compares binary already, and does not know SQL Server's collations: none is written.</summary>
    [TestMethod]
    public void Other_providers_get_no_collation()
    {
        var ddl = Script(o => o.UseSqlite("Data Source=:memory:"));

        Assert.IsFalse(ddl.Contains("COLLATE", StringComparison.Ordinal), ddl);
    }

    /// <summary>
    /// Two schemas in one process — the old and the new side by side during a migration — each get their own tables. EF
    /// caches one model per context type unless told otherwise, and the second would silently use the first's schema.
    /// </summary>
    [TestMethod]
    public void Each_schema_gets_its_own_model_in_the_same_process()
    {
        Assert.AreEqual("auth", SchemaOf("auth"));
        Assert.AreEqual("authz", SchemaOf("authz"));
        Assert.AreEqual("auth", SchemaOf("auth"));

        static string? SchemaOf(string schema)
        {
            var options = new DbContextOptionsBuilder<AdministrationDbContext>().UseSqlServer("Server=unused").Options;
            using var db = new AdministrationDbContext(options, Options.Create(new AuthorizationStoreOptions { Schema = schema }));
            return db.Model.FindEntityType(typeof(kdyf.Authorization.EntityFrameworkCore.Entities.Role))!.GetSchema();
        }
    }

    private static string Script(Action<DbContextOptionsBuilder> provider)
    {
        var builder = new DbContextOptionsBuilder<AdministrationDbContext>();
        provider(builder);
        using var db = new AdministrationDbContext(builder.Options, Options.Create(new AuthorizationStoreOptions()));
        return db.Database.GenerateCreateScript();
    }

    /// <summary>The line declaring <paramref name="column"/> in the CREATE TABLE of <paramref name="table"/>.</summary>
    private static string Column(string ddl, string table, string column)
    {
        var start = ddl.IndexOf($"CREATE TABLE [auth].[{table}] (", StringComparison.Ordinal);
        Assert.AreNotEqual(-1, start, $"no CREATE TABLE for {table}");
        var end = ddl.IndexOf(");", start, StringComparison.Ordinal);
        return ddl[start..end].Split('\n').Single(line => line.TrimStart().StartsWith($"[{column}] ", StringComparison.Ordinal));
    }
}
