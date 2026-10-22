using kdyf.Authorization.Migrations.Schema;
using Microsoft.Data.SqlClient;

namespace kdyf.Authorization.Migrations.Test;

/// <summary>
/// docs/auth-migrate-permission-hierarchy.sql against a real SQL Server, on the schema the package creates: what it
/// rewrites, what it keeps, and what it refuses.
/// </summary>
[TestClass]
public sealed class HierarchyScriptTests
{
    private static string Script(bool dryRun = false, bool checkConstraints = false)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "docs", "auth-migrate-permission-hierarchy.sql")))
            directory = directory.Parent;
        Assert.IsNotNull(directory, "docs/auth-migrate-permission-hierarchy.sql not found above the test output.");

        return File.ReadAllText(Path.Combine(directory.FullName, "docs", "auth-migrate-permission-hierarchy.sql"))
            .Replace("DECLARE @DryRun BIT = 1;", $"DECLARE @DryRun BIT = {(dryRun ? 1 : 0)};")
            .Replace("DECLARE @AddCheckConstraints BIT = 0;", $"DECLARE @AddCheckConstraints BIT = {(checkConstraints ? 1 : 0)};");
    }

    /// <summary>The package's schema, with a catalog and grants as 1.1.0 left them.</summary>
    private static async Task<TestDatabase> PrepareAsync(params string[] extra)
    {
        var db = await TestDatabase.CreateAsync();
        var report = await new SchemaMigrator(db.ConnectionString, new SchemaMigrationOptions()).ApplyAsync();
        Assert.AreEqual(SchemaRunResult.Succeeded, report.Result, report.Error);

        await db.ExecuteAsync($"""
            INSERT INTO auth.Permission (PermissionCode, name, description) VALUES
                ('*', N'Everything', N'Wildcard'), ('Default', N'Base', NULL),
                ('Orders.*', N'All Orders', NULL), ('Orders.Read', N'Read', NULL), ('Orders.Write', N'Write', NULL),
                ('Reports.Sales.Daily', N'Daily', NULL);
            INSERT INTO auth.Role (roleValue, name) VALUES ('admin', N'Admin'), ('orders', N'Orders'), ('reader', N'Reader'), ('both', N'Both');
            INSERT INTO auth.RolePermission (roleValue, PermissionCode) VALUES
                ('admin', '*'), ('admin', 'Default'),
                ('orders', 'Orders.*'),
                ('reader', 'Orders.Read');
            {string.Join(Environment.NewLine, extra)}
            """);
        return db;
    }

    private static async Task<List<string>> RowsAsync(TestDatabase db, string sql)
    {
        await using var connection = new SqlConnection(db.ConnectionString);
        await connection.OpenAsync();
        await using var command = new SqlCommand(sql, connection);
        await using var reader = await command.ExecuteReaderAsync();
        var rows = new List<string>();
        while (await reader.ReadAsync())
            rows.Add(string.Join("|", Enumerable.Range(0, reader.FieldCount).Select(i => reader.IsDBNull(i) ? "" : Convert.ToString(reader.GetValue(i)))));
        return rows;
    }

    private static Task<List<string>> GrantsAsync(TestDatabase db) =>
        RowsAsync(db, "SELECT roleValue, PermissionCode FROM auth.RolePermission ORDER BY roleValue, PermissionCode");

    [TestMethod]
    public async Task Wildcard_grants_become_their_nodes_and_the_wildcard_rows_go()
    {
        await using var db = await PrepareAsync();

        await db.ExecuteAsync(Script());

        CollectionAssert.AreEqual(
            new[] { "admin|", "admin|Default", "orders|Orders", "reader|Orders.Read" },
            await GrantsAsync(db));
        Assert.AreEqual(0, await db.ScalarAsync<int>("SELECT COUNT(*) FROM auth.Permission WHERE PermissionCode LIKE '%*%'"));
    }

    [TestMethod]
    public async Task Every_ancestor_and_the_root_get_a_catalog_row()
    {
        await using var db = await PrepareAsync();

        await db.ExecuteAsync(Script());

        CollectionAssert.AreEqual(
            new[] { "|Everything", "Default|Base", "Orders|Orders", "Orders.Read|Read", "Orders.Write|Write", "Reports|Reports", "Reports.Sales|Reports.Sales", "Reports.Sales.Daily|Daily" },
            await RowsAsync(db, "SELECT PermissionCode, name FROM auth.Permission ORDER BY PermissionCode"));
    }

    /// <summary>A label somebody gave a node already (by hand, or the 1.2.0 catalog sync) is kept.</summary>
    [TestMethod]
    public async Task An_existing_node_keeps_its_name()
    {
        await using var db = await PrepareAsync("INSERT INTO auth.Permission (PermissionCode, name) VALUES ('Orders', N'All of Orders');");

        await db.ExecuteAsync(Script());

        Assert.AreEqual("All of Orders", await db.ScalarAsync<string>("SELECT name FROM auth.Permission WHERE PermissionCode = 'Orders'"));
    }

    /// <summary>A role holding both the node and its old wildcard ends up with one row.</summary>
    [TestMethod]
    public async Task A_role_holding_the_node_and_its_wildcard_keeps_one_row()
    {
        await using var db = await PrepareAsync(
            "INSERT INTO auth.Permission (PermissionCode, name) VALUES ('Orders', N'Orders');",
            "INSERT INTO auth.RolePermission (roleValue, PermissionCode) VALUES ('both', 'Orders'), ('both', 'Orders.*');");

        await db.ExecuteAsync(Script());

        CollectionAssert.Contains(await GrantsAsync(db), "both|Orders");
        Assert.AreEqual(1, await db.ScalarAsync<int>("SELECT COUNT(*) FROM auth.RolePermission WHERE roleValue = 'both'"));
    }

    [TestMethod]
    public async Task A_dry_run_changes_nothing()
    {
        await using var db = await PrepareAsync();
        var before = await GrantsAsync(db);

        await db.ExecuteAsync(Script(dryRun: true));

        CollectionAssert.AreEqual(before, await GrantsAsync(db));
        Assert.AreEqual(2, await db.ScalarAsync<int>("SELECT COUNT(*) FROM auth.Permission WHERE PermissionCode LIKE '%*%'"));
    }

    [TestMethod]
    public async Task A_second_run_finds_nothing_to_do()
    {
        await using var db = await PrepareAsync();
        await db.ExecuteAsync(Script());
        var after = await GrantsAsync(db);

        await db.ExecuteAsync(Script());

        CollectionAssert.AreEqual(after, await GrantsAsync(db));
    }

    /// <summary>A typo must never become a broader grant: a malformed wildcard stops the script, and nothing changes.</summary>
    [TestMethod]
    [DataRow(".*")]
    [DataRow("a..*")]
    [DataRow("*.*")]
    [DataRow("Ord*ers")]
    public async Task A_malformed_wildcard_stops_everything(string code)
    {
        await using var db = await PrepareAsync($"INSERT INTO auth.Permission (PermissionCode, name) VALUES ('{code}', N'x');");
        var before = await GrantsAsync(db);

        var error = await Assert.ThrowsExceptionAsync<SqlException>(() => db.ExecuteAsync(Script()));

        StringAssert.Contains(error.Message, code);
        CollectionAssert.AreEqual(before, await GrantsAsync(db));
    }

    [TestMethod]
    public async Task The_check_constraints_are_optional()
    {
        await using var db = await PrepareAsync();

        await db.ExecuteAsync(Script(checkConstraints: true));

        await Assert.ThrowsExceptionAsync<SqlException>(() =>
            db.ExecuteAsync("INSERT INTO auth.Permission (PermissionCode, name) VALUES ('*', N'Everything');"));
    }
}
