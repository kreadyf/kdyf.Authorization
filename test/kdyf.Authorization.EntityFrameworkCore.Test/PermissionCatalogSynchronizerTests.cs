using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;

namespace kdyf.Authorization.EntityFrameworkCore.Test;

/// <summary>
/// What the synchronisation does to <c>auth.Permission</c>.
/// </summary>
/// <remarks>
/// Against a real relational engine (SQLite in memory) rather than a double: what is being tested is
/// an upsert over a table with a primary key, and an in-memory provider without keys would let
/// through exactly the mistakes that matter.
/// </remarks>
[TestClass]
public class PermissionCatalogSynchronizerTests
{
    // =====================================================================
    // Inserts
    // =====================================================================

    [TestMethod]
    public async Task Inserts_every_declaration_that_has_no_row()
    {
        using var fixture = new CatalogFixture();

        await fixture.SyncAsync(TestPermissions.All());

        CollectionAssert.AreEqual(
            new[] { "", "Default", "demo", "demo.Controlling", "demo.Invoices" },
            fixture.Rows().Select(r => r.PermissionCode).ToArray());
    }

    /// <summary>
    /// The nodes no class declares — the area and the root — get rows of their own: the foreign key of
    /// <c>auth.RolePermission</c> would otherwise stop a role from granting them.
    /// </summary>
    [TestMethod]
    public async Task Inserts_the_ancestors_and_the_root()
    {
        using var fixture = new CatalogFixture();

        await fixture.SyncAsync(new[] { TestPermissions.Controlling() });

        Assert.AreEqual("demo", fixture.Row("demo")!.Name);
        Assert.AreEqual("Everything", fixture.Row("")!.Name);
    }

    /// <summary>An implicit node owns no metadata: a label somebody gave its row stays.</summary>
    [TestMethod]
    public async Task Never_overwrites_the_label_of_an_implicit_node()
    {
        using var fixture = new CatalogFixture()
            .WithRows(CatalogFixture.RowFor("demo", "Demo, all of it", "Given by hand"));

        await fixture.SyncAsync(new[] { TestPermissions.Controlling() });

        Assert.AreEqual("Demo, all of it", fixture.Row("demo")!.Name);
        Assert.AreEqual("Given by hand", fixture.Row("demo")!.Description);
    }

    [TestMethod]
    public async Task Inserts_the_name_and_the_description_with_the_code()
    {
        using var fixture = new CatalogFixture();

        await fixture.SyncAsync(new[] { TestPermissions.Controlling() });

        var row = fixture.Row("demo.Controlling")!;
        Assert.AreEqual("Controlling", row.Name);
        Assert.AreEqual("The controlling screens", row.Description);
    }

    /// <summary>A wildcard class left over from before 1.2.0 gets no row: the node stands for the area.</summary>
    [TestMethod]
    public async Task A_wildcard_declaration_gets_no_row()
    {
        using var fixture = new CatalogFixture();

        await fixture.SyncAsync(new[] { TestPermissions.Wildcard() });

        Assert.IsNull(fixture.Row("demo.*"));
    }

    [TestMethod]
    public async Task Adds_only_what_is_missing_and_leaves_the_rest_alone()
    {
        using var fixture = new CatalogFixture()
            .WithRows(CatalogFixture.RowFor("demo.Controlling", "Controlling", "The controlling screens"));

        await fixture.SyncAsync(TestPermissions.All());

        Assert.AreEqual(5, fixture.Rows().Count);
    }

    // =====================================================================
    // Updates
    // =====================================================================

    [TestMethod]
    public async Task Updates_a_name_that_no_longer_matches_the_declaration()
    {
        using var fixture = new CatalogFixture()
            .WithRows(CatalogFixture.RowFor("demo.Controlling", "old name", "The controlling screens"));

        await fixture.SyncAsync(new[] { TestPermissions.Controlling() });

        Assert.AreEqual("Controlling", fixture.Row("demo.Controlling")!.Name);
    }

    [TestMethod]
    public async Task Updates_a_description_that_no_longer_matches_the_declaration()
    {
        using var fixture = new CatalogFixture()
            .WithRows(CatalogFixture.RowFor("demo.Controlling", "Controlling", "old description"));

        await fixture.SyncAsync(new[] { TestPermissions.Controlling() });

        Assert.AreEqual("The controlling screens", fixture.Row("demo.Controlling")!.Description);
    }

    /// <summary>A row with empty fields —as a minimal seed leaves it— gets filled in.</summary>
    [TestMethod]
    public async Task Fills_in_a_row_whose_name_and_description_are_null()
    {
        using var fixture = new CatalogFixture()
            .WithRows(CatalogFixture.RowFor("demo.Invoices", null, null));

        await fixture.SyncAsync(new[] { TestPermissions.Invoices() });

        var row = fixture.Row("demo.Invoices")!;
        Assert.AreEqual("Invoices", row.Name);
        Assert.AreEqual("Issue and void invoices", row.Description);
    }

    [TestMethod]
    public async Task Leaves_a_row_that_already_matches_untouched()
    {
        using var fixture = new CatalogFixture()
            .WithRows(Tree(CatalogFixture.RowFor("demo.Controlling", "Controlling", "The controlling screens")));

        await fixture.SyncAsync(new[] { TestPermissions.Controlling() });

        var row = fixture.Row("demo.Controlling")!;
        Assert.AreEqual("Controlling", row.Name);
        Assert.AreEqual("The controlling screens", row.Description);
        Assert.AreEqual(3, fixture.Rows().Count, "the row, its area and the root: nothing added");
    }

    /// <summary>The rows of the root and of <c>demo</c> next to <paramref name="row"/>: a catalog with nothing to add.</summary>
    private static Entities.Permission[] Tree(Entities.Permission row) =>
        [CatalogFixture.RowFor("", "Everything", null), CatalogFixture.RowFor("demo", "demo", null), row];

    // =====================================================================
    // What it does NOT do
    // =====================================================================

    /// <summary>
    /// A row that nobody declares any more may still be granted to a role, and the foreign key of
    /// <c>auth.RolePermission</c> has no cascade. It is reported and left alone.
    /// </summary>
    [TestMethod]
    public async Task Never_deletes_a_row_that_no_declaration_covers()
    {
        using var fixture = new CatalogFixture()
            .WithRows(CatalogFixture.RowFor("demo.Retired", "Retired", "The class no longer exists"));

        await fixture.SyncAsync(TestPermissions.All());

        Assert.IsNotNull(fixture.Row("demo.Retired"), "a row without a class cannot disappear on its own");
        Assert.AreEqual(6, fixture.Rows().Count);
    }

    /// <summary>
    /// The code is the primary key and the target of the foreign key: changing it is a migration, not
    /// a synchronisation. And under SQL Server's default collation the two rows are the same one,
    /// so inserting would violate the key. It fails loudly.
    /// </summary>
    [TestMethod]
    public async Task Refuses_a_declaration_that_differs_from_its_row_only_in_capitalisation()
    {
        using var fixture = new CatalogFixture()
            .WithRows(CatalogFixture.RowFor("Demo.Controlling", "Controlling", "The controlling screens"));

        var error = await Assert.ThrowsExceptionAsync<InvalidOperationException>(
            () => fixture.SyncAsync(new[] { TestPermissions.Controlling() }));

        StringAssert.Contains(error.Message, "demo.Controlling");
        StringAssert.Contains(error.Message, "Demo.Controlling");
        Assert.AreEqual(1, fixture.Rows().Count, "it must not have inserted a duplicate");
    }

    [TestMethod]
    public async Task Refuses_a_code_longer_than_the_column()
    {
        using var fixture = new CatalogFixture();

        var error = await Assert.ThrowsExceptionAsync<InvalidOperationException>(
            () => fixture.SyncAsync(new[] { TestPermissions.TooLong() }));

        StringAssert.Contains(error.Message, "50");
    }

    // =====================================================================
    // Environment and mode
    // =====================================================================

    /// <summary>
    /// In Production a diagnostic cannot prevent startup — but what can be written
    /// is written: the rest of the permissions have no reason to be left out because of one.
    /// </summary>
    [TestMethod]
    public async Task In_production_it_logs_the_problem_and_writes_what_it_can()
    {
        using var fixture = new CatalogFixture(environment: "Production")
            .WithRows(CatalogFixture.RowFor("Demo.Controlling", "Controlling", "The controlling screens"));

        await fixture.SyncAsync(TestPermissions.All());

        Assert.IsNotNull(fixture.Row("demo.Invoices"), "the others did have to get in");
        Assert.IsNull(fixture.Row("demo.Controlling"), "the conflicting one is skipped");
    }

    [TestMethod]
    public async Task Report_only_writes_nothing()
    {
        using var fixture = new CatalogFixture()
            .WithRows(CatalogFixture.RowFor("demo.Controlling", "old name", "old description"));

        await fixture.SyncAsync(TestPermissions.All(), reportOnly: true);

        Assert.AreEqual(1, fixture.Rows().Count, "it must not insert any");
        Assert.AreEqual("old name", fixture.Row("demo.Controlling")!.Name, "nor update");
    }

    // =====================================================================
    // Cache and idempotence
    // =====================================================================

    /// <summary>
    /// A new row changes what a node stands for, and the expanded sets are
    /// cached: an instance that is already serving has to drop them.
    /// </summary>
    [TestMethod]
    public async Task Drops_the_permission_cache_when_it_added_rows()
    {
        using var fixture = new CatalogFixture();

        await fixture.SyncAsync(TestPermissions.All());

        Assert.AreEqual(1, fixture.Cache.InvalidateAllCalls);
    }

    [TestMethod]
    public async Task Does_not_drop_the_cache_when_there_was_nothing_to_add()
    {
        using var fixture = new CatalogFixture()
            .WithRows(Tree(CatalogFixture.RowFor("demo.Controlling", "Controlling", "The controlling screens")));

        await fixture.SyncAsync(new[] { TestPermissions.Controlling() });

        Assert.AreEqual(0, fixture.Cache.InvalidateAllCalls);
    }

    /// <summary>
    /// Changing a name or a description does not change what anybody CAN do: they are descriptive
    /// columns. Dropping the cache over that would cost one query per active user in exchange for
    /// nothing.
    /// </summary>
    [TestMethod]
    public async Task Does_not_drop_the_cache_when_it_only_updated_a_name()
    {
        using var fixture = new CatalogFixture()
            .WithRows(Tree(CatalogFixture.RowFor("demo.Controlling", "old name", "The controlling screens")));

        await fixture.SyncAsync(new[] { TestPermissions.Controlling() });

        Assert.AreEqual("Controlling", fixture.Row("demo.Controlling")!.Name, "it did have to update");
        Assert.AreEqual(0, fixture.Cache.InvalidateAllCalls, "but not touch the cache");
    }

    /// <summary>Running it twice —two deployments, two restarts— must change nothing the second time.</summary>
    [TestMethod]
    public async Task Running_it_twice_changes_nothing_the_second_time()
    {
        using var fixture = new CatalogFixture();

        await fixture.SyncAsync(TestPermissions.All());
        var afterFirst = fixture.Rows().Select(r => $"{r.PermissionCode}|{r.Name}|{r.Description}").ToArray();

        await fixture.SyncAsync(TestPermissions.All());

        CollectionAssert.AreEqual(
            afterFirst,
            fixture.Rows().Select(r => $"{r.PermissionCode}|{r.Name}|{r.Description}").ToArray());
        Assert.AreEqual(1, fixture.Cache.InvalidateAllCalls, "the second one added nothing");
    }

    // =====================================================================
    // When the write does not land
    // =====================================================================

    /// <summary>
    /// The case that needs telling apart. The SAME DbUpdateException covers two opposite things: another
    /// replica that wrote the same thing a moment earlier —benign— and a REFUSED write, which in
    /// a carefully run production database is the most likely: the application user without INSERT.
    /// Guessing it from the exception is not possible; asking the table is.
    /// </summary>
    [TestMethod]
    public async Task A_refused_write_is_reported_and_not_taken_for_a_race()
    {
        using var fixture = new CatalogFixture();
        fixture.MakeReadOnly();

        var error = await Assert.ThrowsExceptionAsync<InvalidOperationException>(
            () => fixture.SyncAsync(TestPermissions.All()));

        StringAssert.Contains(error.Message, "still missing");
        StringAssert.Contains(error.Message, "INSERT", "and it says where to look");
        StringAssert.Contains(error.Message, "denies in silence", "and what happens if nobody looks");
    }

    /// <summary>
    /// The other write that can be refused: an UPDATE. Here no row is missing afterwards, so
    /// "everything is there" cannot be taken for "another replica wrote it first" — there was nothing to
    /// insert. Without this distinction the refusal was logged as a benign race and the log said
    /// "updated 1".
    /// </summary>
    [TestMethod]
    public async Task A_refused_update_is_reported_too()
    {
        using var fixture = new CatalogFixture()
            .WithRows(Tree(CatalogFixture.RowFor("demo.Controlling", "old name", null)));
        fixture.MakeReadOnly();

        var error = await Assert.ThrowsExceptionAsync<InvalidOperationException>(
            () => fixture.SyncAsync(new[] { TestPermissions.Controlling() }));

        StringAssert.Contains(error.Message, "UPDATE", "and it says where to look");
    }

    /// <summary>
    /// Two sources can declare the same code; DiscoverIn only watches one assembly. Adding
    /// two rows with the same key blew up in EF before reaching any handling: the host did not
    /// start, not even in Production.
    /// </summary>
    [TestMethod]
    public async Task A_code_declared_twice_is_reported_not_crashed_on()
    {
        using var fixture = new CatalogFixture();

        var error = await Assert.ThrowsExceptionAsync<InvalidOperationException>(
            () => fixture.SyncAsync(new[] { TestPermissions.Controlling(), TestPermissions.Controlling() }));

        StringAssert.Contains(error.Message, "more than once");
        StringAssert.Contains(error.Message, "demo.Controlling");
    }

    [TestMethod]
    public async Task In_production_a_code_declared_twice_is_written_once()
    {
        using var fixture = new CatalogFixture(environment: "Production");

        await fixture.SyncAsync(new[] { TestPermissions.Controlling(), TestPermissions.Controlling() });

        Assert.AreEqual(1, fixture.Rows().Count(r => r.PermissionCode == "demo.Controlling"));
    }

    /// <summary>And in Production it does not prevent startup: it logs it and carries on, like everything else here.</summary>
    [TestMethod]
    public async Task In_production_a_refused_write_is_logged_and_the_host_still_starts()
    {
        using var fixture = new CatalogFixture(environment: "Production");
        fixture.MakeReadOnly();

        await fixture.SyncAsync(TestPermissions.All());   // does not throw
    }

    // =====================================================================
    // Database
    // =====================================================================

    /// <summary>
    /// A database that is not up yet is not a wiring mistake. It is logged and the host starts:
    /// refusing to start over a diagnostic is worse than starting without it.
    /// </summary>
    [TestMethod]
    public async Task An_unreachable_database_does_not_stop_the_host()
    {
        var services = new ServiceCollection();
        services.AddDbContext<TestAuthContext>(o =>
            o.UseSqlite(new SqliteConnection("DataSource=/no/such/directory/auth.db")));
        using var provider = services.BuildServiceProvider();

        var options = new PermissionCatalogSyncOptions();
        options.Declarations.AddRange(TestPermissions.All());

        var sync = new PermissionCatalogSynchronizer<TestAuthContext>(
            provider, options, new TestEnvironment(),
            NullLogger<PermissionCatalogSynchronizer<TestAuthContext>>.Instance);

        await sync.StartAsync(CancellationToken.None);   // does not throw
    }

    [TestMethod]
    public async Task Without_declarations_it_does_nothing()
    {
        using var fixture = new CatalogFixture()
            .WithRows(CatalogFixture.RowFor("demo.Controlling", "Controlling", "The controlling screens"));

        await fixture.SyncAsync(Array.Empty<Abstractions.PermissionDefinition>());

        Assert.AreEqual(1, fixture.Rows().Count);
        Assert.AreEqual(0, fixture.Cache.InvalidateAllCalls);
    }

    // =====================================================================
    // From the declared permissions
    // =====================================================================

    /// <summary>
    /// How UseEntityFrameworkStore runs it: the rows come from the catalog authorization reads, so the nodes no class
    /// declares and no scan would find get their rows, and a role can grant them.
    /// </summary>
    [TestMethod]
    public async Task Writes_the_rows_of_the_declared_permissions_implicit_nodes_included()
    {
        var declared = new Roles.DeclaredPermissions([TestPermissions.Controlling(), TestPermissions.Invoices(), TestPermissions.NoArea()]);
        using var fixture = new CatalogFixture(declared: declared);

        await fixture.SyncFromDeclaredPermissionsAsync();

        CollectionAssert.AreEqual(
            new[] { "", "Default", "demo", "demo.Controlling", "demo.Invoices" },
            fixture.Rows().Select(r => r.PermissionCode).ToArray());
        Assert.AreEqual("demo", fixture.Row("demo")!.Name);
    }

    /// <summary>Composed without AddAssignedRoles there is no catalog to read: it scans, as it always did.</summary>
    [TestMethod]
    public async Task Without_declared_permissions_it_scans_the_assemblies()
    {
        using var fixture = new CatalogFixture();

        await fixture.SyncFromDeclaredPermissionsAsync(typeof(object).Assembly);   // declares nothing

        Assert.AreEqual(0, fixture.Rows().Count);
    }

    /// <summary>An explicit list still takes the place of everything else, as the tests here rely on.</summary>
    [TestMethod]
    public async Task An_explicit_list_takes_the_place_of_the_declared_permissions()
    {
        using var fixture = new CatalogFixture(declared: new Roles.DeclaredPermissions(TestPermissions.All()));

        await fixture.SyncAsync(new[] { TestPermissions.Controlling() });

        CollectionAssert.AreEqual(new[] { "", "demo", "demo.Controlling" }, fixture.Rows().Select(r => r.PermissionCode).ToArray());
    }
}
