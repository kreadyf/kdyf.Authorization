using kdyf.Authorization.Administration.AspNetCore;
using kdyf.Authorization.EntityFrameworkCore;
using kdyf.Authorization.Migrations.Schema;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace kdyf.Authorization.Migrations.Test;

/// <summary>
/// The versioned schema against a real SQL Server: each state the detector tells apart, what a run does with it, and
/// what it refuses to do.
/// </summary>
[TestClass]
public sealed class SchemaMigratorTests
{
    /// <summary>The steps of a schema without the profiles, which is the default: the six tables, indexed and granted.</summary>
    private static readonly int Steps = MigrationSteps.For(userProfiles: false).Count;

    private static SchemaMigrator Migrator(TestDatabase db, Action<SchemaMigrationOptions>? configure = null)
    {
        var options = new SchemaMigrationOptions();
        configure?.Invoke(options);
        return new SchemaMigrator(db.ConnectionString, options);
    }

    [TestMethod]
    public async Task An_empty_database_is_installed_at_the_required_version_and_verifies()
    {
        await using var db = await TestDatabase.CreateAsync();
        var migrator = Migrator(db);

        Assert.AreEqual(SchemaState.Empty, (await migrator.DetectAsync()).State);

        var report = await migrator.ApplyAsync();

        Assert.AreEqual(SchemaRunResult.Succeeded, report.Result, report.Error);
        Assert.AreEqual(SchemaMigrator.RequiredVersionFor(userProfiles: false), report.Version);
        Assert.AreEqual(0, await db.ScalarAsync<int>("SELECT COUNT(*) FROM sys.tables WHERE name = 'UserProfile'"), "the profiles are not part of the clean schema");
        var verification = await migrator.VerifyAsync();
        Assert.IsTrue(verification.Succeeded, string.Join(Environment.NewLine, verification.Issues));
        Assert.AreEqual(Steps, await db.ScalarAsync<int>("SELECT COUNT(*) FROM auth.SchemaVersion WHERE Status = 'Applied' AND Origin = 'installed'"));
        Assert.AreEqual("Succeeded", await db.ScalarAsync<string>("SELECT Result FROM auth.SchemaMigrationLog"));
    }

    [TestMethod]
    public async Task With_the_profiles_the_schema_goes_one_step_further()
    {
        await using var db = await TestDatabase.CreateAsync();
        var migrator = Migrator(db, o => o.UserProfiles = true);

        var report = await migrator.ApplyAsync();

        Assert.AreEqual(SchemaRunResult.Succeeded, report.Result, report.Error);
        Assert.AreEqual(SchemaMigrator.RequiredVersion, report.Version);
        Assert.AreEqual(1, await db.ScalarAsync<int>("SELECT COUNT(*) FROM sys.tables WHERE name = 'UserProfile'"));
        var verification = await migrator.VerifyAsync();
        Assert.IsTrue(verification.Succeeded, string.Join(Environment.NewLine, verification.Issues));
    }

    /// <summary>The profiles can be turned on later: the step is added to a schema that already runs.</summary>
    [TestMethod]
    public async Task The_profiles_are_added_later_to_a_schema_that_already_runs()
    {
        await using var db = await TestDatabase.CreateAsync();
        Assert.IsTrue((await Migrator(db).ApplyAsync()).Succeeded);

        var later = await Migrator(db, o => o.UserProfiles = true).ApplyAsync();

        Assert.AreEqual(SchemaRunResult.Succeeded, later.Result, later.Error);
        Assert.AreEqual(SchemaMigrator.RequiredVersion, later.Version);
        Assert.AreEqual(1, await db.ScalarAsync<int>("SELECT COUNT(*) FROM sys.tables WHERE name = 'UserProfile'"));
        Assert.IsTrue((await Migrator(db, o => o.UserProfiles = true).VerifyAsync()).Succeeded);
        Assert.IsTrue((await Migrator(db).VerifyAsync()).Succeeded, "a host without the profiles still verifies a schema that has them");
    }

    [TestMethod]
    public async Task Applying_twice_changes_nothing_the_second_time()
    {
        await using var db = await TestDatabase.CreateAsync();
        await Migrator(db).ApplyAsync();

        var second = await Migrator(db).ApplyAsync();

        Assert.AreEqual(SchemaRunResult.UpToDate, second.Result);
        Assert.AreEqual(Steps, await db.ScalarAsync<int>("SELECT COUNT(*) FROM auth.SchemaVersion"));
        Assert.AreEqual(1, await db.ScalarAsync<int>("SELECT COUNT(*) FROM auth.SchemaMigrationLog"));
    }

    [TestMethod]
    public async Task Another_schema_name_is_installed_side_by_side()
    {
        await using var db = await TestDatabase.CreateAsync();
        await Migrator(db).ApplyAsync();

        var report = await Migrator(db, o => o.Schema = "authz").ApplyAsync();

        Assert.AreEqual(SchemaRunResult.Succeeded, report.Result, report.Error);
        Assert.IsTrue((await Migrator(db, o => o.Schema = "authz").VerifyAsync()).Succeeded);
        Assert.IsTrue((await Migrator(db).VerifyAsync()).Succeeded);
        Assert.AreEqual(1, await db.ScalarAsync<int>("SELECT COUNT(*) FROM sys.database_principals WHERE name = 'kdyf_authz_runtime'"));
    }

    /// <summary>The EF model of the packages is the manifest of the required version: one cannot drift from the other.</summary>
    [TestMethod]
    public async Task The_tables_EF_creates_are_the_manifest()
    {
        await using var db = await TestDatabase.CreateAsync();
        var options = new DbContextOptionsBuilder<AdministrationDbContext>().UseSqlServer(db.ConnectionString).Options;
        await using (var context = new AdministrationDbContext(options, Options.Create(new AuthorizationStoreOptions())))
            await db.ExecuteAsync(context.Database.GenerateCreateScript());

        var detection = await Migrator(db).DetectAsync();
        var differences = SchemaComparer.CompareTables(detection.Snapshot, SchemaMigrator.RequiredVersion)
            .Where(d => d.Kind != DifferenceKind.Note)
            .ToList();

        Assert.AreEqual(0, differences.Count, string.Join(Environment.NewLine, differences));
    }

    [TestMethod]
    public async Task The_EF_model_and_the_steps_require_the_same_version() =>
        Assert.AreEqual(AuthorizationSchema.RequiredVersion, SchemaMigrator.RequiredVersion);

    [TestMethod]
    public async Task A_database_made_by_the_hosts_script_is_adopted_not_rebuilt()
    {
        await using var db = await TestDatabase.CreateAsync();
        await db.ExecuteAsync(Fixtures.HostScriptVersion1);
        await db.ExecuteAsync(Fixtures.Data);
        var migrator = Migrator(db, o => o.BackupConfirmed = true);

        Assert.AreEqual(SchemaState.Adoptable, (await migrator.DetectAsync()).State);
        var report = await migrator.ApplyAsync();

        Assert.AreEqual(SchemaRunResult.Succeeded, report.Result, report.Error);
        Assert.AreEqual("adopted", await db.ScalarAsync<string>("SELECT Origin FROM auth.SchemaVersion WHERE Version = 1"));
        Assert.IsTrue((await migrator.VerifyAsync()).Succeeded);
        Assert.AreEqual(2, await db.ScalarAsync<int>("SELECT COUNT(*) FROM auth.RolePermission"));
        Assert.AreEqual(1, await db.ScalarAsync<int>("SELECT COUNT(*) FROM auth.AuditLog"));
        Assert.AreEqual(1, await db.ScalarAsync<int>("SELECT COUNT(*) FROM sys.indexes WHERE name = 'IX_RolePermission_PermissionCode'"));
    }

    [TestMethod]
    public async Task A_database_with_data_is_not_touched_without_a_backup()
    {
        await using var db = await TestDatabase.CreateAsync();
        await db.ExecuteAsync(Fixtures.HostScriptVersion1);
        await db.ExecuteAsync(Fixtures.Data);

        var report = await Migrator(db).ApplyAsync();

        Assert.AreEqual(SchemaRunResult.Refused, report.Result);
        Assert.IsTrue(report.Plan.Issues.Any(i => i.Code == "backup"));
        Assert.IsNull(await db.ScalarAsync<object>("SELECT OBJECT_ID(N'auth.SchemaVersion')"));
    }

    [TestMethod]
    public async Task Keys_without_the_binary_collation_are_repaired_only_with_approval()
    {
        await using var db = await TestDatabase.CreateAsync();
        await db.ExecuteAsync(Fixtures.CaseInsensitiveVersion1);
        await db.ExecuteAsync(Fixtures.Data);

        Assert.AreEqual(SchemaState.NeedsCollationRepair, (await Migrator(db).DetectAsync()).State);
        var refused = await Migrator(db, o => o.BackupConfirmed = true).ApplyAsync();
        Assert.AreEqual(SchemaRunResult.Refused, refused.Result);
        Assert.IsTrue(refused.Plan.Issues.Any(i => i.Code == "collation-repair-approval"));

        var migrator = Migrator(db, o =>
        {
            o.BackupConfirmed = true;
            o.Approvals.Add(SchemaApprovals.CollationRepair);
        });
        var report = await migrator.ApplyAsync();

        Assert.AreEqual(SchemaRunResult.Succeeded, report.Result, report.Error);
        Assert.IsTrue((await migrator.VerifyAsync()).Succeeded);
        Assert.AreEqual("Latin1_General_100_BIN2",
            await db.ScalarAsync<string>("SELECT collation_name FROM sys.columns WHERE object_id = OBJECT_ID(N'auth.UserRole') AND name = 'roleValue'"));
        Assert.AreEqual(2, await db.ScalarAsync<int>("SELECT COUNT(*) FROM auth.RolePermission"));
    }

    /// <summary>A grant of 'portal.admin' to a role defined as 'Portal.Admin' held ignoring case; it would not after the repair.</summary>
    [TestMethod]
    public async Task References_that_only_match_ignoring_case_block_the_repair()
    {
        await using var db = await TestDatabase.CreateAsync();
        await db.ExecuteAsync(Fixtures.CaseInsensitiveVersion1);
        await db.ExecuteAsync(Fixtures.Data);
        await db.ExecuteAsync("INSERT INTO auth.UserRole (objectId, roleValue) VALUES ('0f1e2d3c-0000-0000-0000-000000000002', 'portal.admin');");

        var report = await Migrator(db, o =>
        {
            o.BackupConfirmed = true;
            o.Approvals.Add(SchemaApprovals.CollationRepair);
        }).ApplyAsync();

        Assert.AreEqual(SchemaRunResult.Refused, report.Result);
        StringAssert.Contains(report.Plan.Issues.Single(i => i.Code == "collation-case-mismatch").Message, "FK_UserRole_Role");
    }

    [TestMethod]
    public async Task The_legacy_schema_is_never_touched()
    {
        await using var db = await TestDatabase.CreateAsync();
        await db.ExecuteAsync(Fixtures.Legacy);

        var report = await Migrator(db, o => o.BackupConfirmed = true).ApplyAsync();

        Assert.AreEqual(SchemaState.Legacy, report.Plan.Detection.State);
        Assert.AreEqual(SchemaRunResult.Refused, report.Result);
        Assert.IsNull(await db.ScalarAsync<object>("SELECT OBJECT_ID(N'auth.SchemaVersion')"));
    }

    [TestMethod]
    public async Task Grants_keyed_by_role_without_a_role_table_are_not_supported()
    {
        await using var db = await TestDatabase.CreateAsync();
        await db.ExecuteAsync(Fixtures.RolesWithoutTable);

        Assert.AreEqual(SchemaState.Unsupported, (await Migrator(db).DetectAsync()).State);
    }

    [TestMethod]
    public async Task Another_shape_is_unknown_and_its_differences_are_reported()
    {
        await using var db = await TestDatabase.CreateAsync();
        await db.ExecuteAsync(Fixtures.HostScriptVersion1);
        await db.ExecuteAsync("ALTER TABLE auth.Role ADD tenant INT NOT NULL CONSTRAINT DF_Role_Tenant DEFAULT 0;");

        var detection = await Migrator(db).DetectAsync();

        Assert.AreEqual(SchemaState.Unknown, detection.State);
        Assert.IsTrue(detection.Differences.Any(d => d.Description.Contains("tenant")));
    }

    [TestMethod]
    public async Task A_failed_step_is_recorded_and_the_next_run_resumes_it()
    {
        await using var db = await TestDatabase.CreateAsync();
        var failing = new MigrationStep[] { new RuntimeRoleStep(), new TablesStep(), new FailingStep() };

        var failed = await new SchemaMigrator(db.ConnectionString, new SchemaMigrationOptions(), null, failing).ApplyAsync();

        Assert.AreEqual(SchemaRunResult.Failed, failed.Result);
        Assert.AreEqual(1, failed.Version);
        Assert.AreEqual("Failed", await db.ScalarAsync<string>("SELECT Status FROM auth.SchemaVersion WHERE Version = 2"));
        Assert.IsNull(await db.ScalarAsync<object>("SELECT OBJECT_ID(N'auth.ShouldNotExist')"), "the failed step was rolled back");

        var resumed = await Migrator(db).ApplyAsync();

        Assert.AreEqual(SchemaRunResult.Succeeded, resumed.Result, resumed.Error + string.Join(" ", resumed.Plan.Issues));
        Assert.IsTrue(resumed.Plan.Issues.Any(i => i.Code == "resume"));
        Assert.IsTrue((await Migrator(db).VerifyAsync()).Succeeded);
    }

    [TestMethod]
    public async Task Two_runs_at_once_apply_each_step_once()
    {
        await using var db = await TestDatabase.CreateAsync();

        var reports = await Task.WhenAll(Migrator(db).ApplyAsync(), Migrator(db).ApplyAsync());

        Assert.IsTrue(reports.All(r => r.Succeeded), string.Join(" ", reports.Select(r => r.Error)));
        Assert.AreEqual(1, reports.Count(r => r.Result == SchemaRunResult.Succeeded));
        Assert.AreEqual(Steps, await db.ScalarAsync<int>("SELECT COUNT(*) FROM auth.SchemaVersion"));
    }

    [TestMethod]
    public async Task The_script_does_what_apply_does_and_verify_confirms_it()
    {
        await using var db = await TestDatabase.CreateAsync();
        await db.ExecuteAsync(Fixtures.HostScriptVersion1);
        var migrator = Migrator(db);

        var script = await migrator.ScriptAsync();
        await db.ExecuteAsync(script);

        var verification = await migrator.VerifyAsync();
        Assert.IsTrue(verification.Succeeded, string.Join(Environment.NewLine, verification.Issues));
        Assert.AreEqual("adopted", await db.ScalarAsync<string>("SELECT Origin FROM auth.SchemaVersion WHERE Version = 1"));
        Assert.AreEqual("script", await db.ScalarAsync<string>("SELECT Origin FROM auth.SchemaVersion WHERE Version = 3"));
    }

    [TestMethod]
    public async Task A_change_by_hand_after_the_migration_fails_the_verification()
    {
        await using var db = await TestDatabase.CreateAsync();
        await Migrator(db).ApplyAsync();
        await db.ExecuteAsync("DROP INDEX IX_UserRole_Role ON auth.UserRole;");

        var verification = await Migrator(db).VerifyAsync();

        Assert.IsFalse(verification.Succeeded);
        Assert.IsTrue(verification.Issues.Any(i => i.Code == "drift" && i.Message.Contains("IX_UserRole_Role")));
    }

    [TestMethod]
    public async Task A_history_that_does_not_match_the_code_fails_the_verification()
    {
        await using var db = await TestDatabase.CreateAsync();
        await Migrator(db).ApplyAsync();
        await db.ExecuteAsync("UPDATE auth.SchemaVersion SET Checksum = REPLICATE('0', 64) WHERE Version = 1;");

        var verification = await Migrator(db).VerifyAsync();

        Assert.IsTrue(verification.Issues.Any(i => i.Code == "checksum"));
    }

    [TestMethod]
    public async Task The_application_user_joins_the_runtime_role_and_cannot_rewrite_the_audit_log()
    {
        await using var db = await TestDatabase.CreateAsync();
        await db.ExecuteAsync("CREATE USER app_user WITHOUT LOGIN;");

        var report = await Migrator(db, o => o.AppUser = "app_user").ApplyAsync();

        Assert.AreEqual(SchemaRunResult.Succeeded, report.Result, report.Error);
        Assert.IsTrue((await Migrator(db, o => o.AppUser = "app_user").VerifyAsync()).Succeeded);
        Assert.AreEqual(1, await db.ScalarAsync<int>("""
            EXECUTE AS USER = 'app_user';
            DECLARE @insert INT = HAS_PERMS_BY_NAME('auth.AuditLog', 'OBJECT', 'INSERT');
            DECLARE @delete INT = HAS_PERMS_BY_NAME('auth.AuditLog', 'OBJECT', 'DELETE');
            DECLARE @history INT = HAS_PERMS_BY_NAME('auth.SchemaVersion', 'OBJECT', 'UPDATE');
            REVERT;
            SELECT CASE WHEN @insert = 1 AND @delete = 0 AND @history = 0 THEN 1 ELSE 0 END;
            """));
    }

    [TestMethod]
    public async Task An_application_user_the_denies_do_not_bind_needs_approval()
    {
        await using var db = await TestDatabase.CreateAsync();
        await db.ExecuteAsync("CREATE USER app_owner WITHOUT LOGIN; ALTER ROLE db_owner ADD MEMBER app_owner;");

        var refused = await Migrator(db, o => o.AppUser = "app_owner").ApplyAsync();
        Assert.AreEqual(SchemaRunResult.Refused, refused.Result);
        Assert.IsTrue(refused.Plan.Issues.Any(i => i.Code == "privileged-app-user" && i.Severity == IssueSeverity.Blocker));

        var approved = await Migrator(db, o =>
        {
            o.AppUser = "app_owner";
            o.Approvals.Add(SchemaApprovals.PrivilegedAppUser);
        }).ApplyAsync();
        Assert.AreEqual(SchemaRunResult.Succeeded, approved.Result, approved.Error);
    }

    [TestMethod]
    public async Task The_cutover_is_recorded_once_on_a_verified_schema()
    {
        await using var db = await TestDatabase.CreateAsync();
        await Assert.ThrowsExceptionAsync<InvalidOperationException>(() => Migrator(db).MarkCutoverAsync());

        await Migrator(db).ApplyAsync();
        await Migrator(db).MarkCutoverAsync();
        await Migrator(db).MarkCutoverAsync();

        Assert.IsTrue((await Migrator(db).DetectAsync()).CutoverCompleted);
        Assert.AreEqual(1, await db.ScalarAsync<int>("SELECT COUNT(*) FROM auth.SchemaMarker"));
    }

    /// <summary>Applies the DDL, then fails: the transaction must leave nothing behind.</summary>
    private sealed class FailingStep : MigrationStep
    {
        public override int Version => 2;
        public override string Id => "0002-fails";
        public override string Description => "Fails after a DDL statement.";

        protected override string Template => """
            CREATE TABLE [{schema}].[ShouldNotExist] (Id INT NOT NULL);
            THROW 50000, 'Injected failure.', 1;
            """;
    }
}
