using kdyf.Authorization.Abstractions;
using kdyf.Authorization.Migrations.Legacy;
using kdyf.Authorization.Migrations.Schema;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.DependencyInjection;

namespace kdyf.Authorization.Migrations.Test;

/// <summary>
/// The legacy import against SQL Server: the legacy schema copied into a target of the new model, reconciled on every
/// run, verified row by row, and refused whole when something stands in the way.
/// </summary>
[TestClass]
public sealed class LegacyImportTests
{
    private const string Admin = "0f1e2d3c-0000-0000-0000-000000000001";
    private const string Reader = "0f1e2d3c-0000-0000-0000-000000000002";
    private const string Nothing = "0f1e2d3c-0000-0000-0000-000000000004";
    private const string Target = "authz";

    private static readonly PermissionDefinition[] Declared = { new EverythingPermission(), new DefaultPermission(), new OrdersRead() };

    private const string AuditData = """
        SET IDENTITY_INSERT auth.AuditLog ON;
        INSERT INTO auth.AuditLog (AuditLogId, actorUserId, actorEmail, action, targetType, targetId, targetLabel) VALUES
            (1, 1, 'admin@test', 'access.roles.changed', 'user', 2, 'reader@test'),
            (2, 1, 'admin@test', 'role.updated', 'role', 2, 'Order Reader'),
            (3, 3, 'service@test', 'pat.created', 'pat', 1, 'limited'),
            (4, NULL, 'system', 'role.updated', 'role', 99, 'gone');
        SET IDENTITY_INSERT auth.AuditLog OFF;
        """;

    /// <summary>The legacy schema (shape C, with the dirty data), the target installed, and the identities resolved now.</summary>
    private static async Task<TestDatabase> PrepareAsync(bool resolve = true)
    {
        var db = await TestDatabase.CreateAsync();
        await db.ExecuteAsync(LegacyFixtures.ShapeC);
        await db.ExecuteAsync(LegacyFixtures.Data);
        await db.ExecuteAsync(LegacyFixtures.TokenData);
        await db.ExecuteAsync(AuditData);
        await db.ExecuteAsync("INSERT INTO auth.RolePermission (RoleId, PermissionCode) VALUES (2, 'Orders.Write');"); // the host does not declare it
        var installed = await new SchemaMigrator(db.ConnectionString, new SchemaMigrationOptions { Schema = Target }).ApplyAsync();
        Assert.IsTrue(installed.Succeeded, installed.Error);
        if (resolve)
            await ResolveAsync(db);
        // The token of user 3 (no identity) stops validating: approved, with the count, as a person would.
        await ApproveAsync(db, new InvariantException(InvariantKinds.TokenCount, null, null, -1, "user 3 has no identity", "test"));
        return db;
    }

    private static async Task ApproveAsync(TestDatabase db, params InvariantException[] exceptions)
    {
        await using var connection = new SqlConnection(db.ConnectionString);
        await connection.OpenAsync();
        await using (var bootstrap = new SqlCommand(MigrationStore.BootstrapSql(Target), connection))
            await bootstrap.ExecuteNonQueryAsync();
        await InvariantExceptions.ReplaceAsync(connection, Target, exceptions, new string('0', 64), default);
    }

    /// <summary>Users 1, 2 and 4 resolve; user 3 (no object id, active, holding a role) does not.</summary>
    private static async Task ResolveAsync(TestDatabase db, DateTime? at = null)
    {
        var (_, report) = await LegacyInspector.InspectAsync(db.ConnectionString, "auth");
        var known = new Dictionary<int, string> { [1] = Admin, [2] = Reader, [4] = Nothing };
        var identities = report!.Data.Users.Select(u => new ResolvedIdentity(
            u.UserId, u.Email, u.ObjectId, known.GetValueOrDefault(u.UserId), "existing", known.ContainsKey(u.UserId) ? 1 : 0, "Member", true,
            known.ContainsKey(u.UserId) ? IdentityStatus.Ok : IdentityStatus.NotFound, IdentityResolver.RowVersion(u),
            u.IsActive, known.ContainsKey(u.UserId), at ?? DateTime.UtcNow)).ToList();
        await using var connection = new SqlConnection(db.ConnectionString);
        await connection.OpenAsync();
        await MigrationStore.SaveAsync(connection, Target, identities, default);
    }

    private static Task<LegacyImportReport> ImportAsync(
        TestDatabase db, bool apply = true, bool approveLosses = true, LegacyImportSettings? settings = null,
        IReadOnlyList<ILegacyImportHostStep>? steps = null, int batch = 5000, InvariantSettings? invariant = null) =>
        LegacyImporter.RunAsync(db.ConnectionString, new LegacyImportRequest
        {
            LegacySchema = "auth",
            TargetSchema = Target,
            Declared = Declared,
            Apply = apply,
            AuditBatchSize = batch,
            Invariant = invariant ?? new InvariantSettings(),
            HostSteps = steps ?? Array.Empty<ILegacyImportHostStep>(),
            Settings = new LegacyImportSettings
            {
                AutoProvisionedRole = settings?.AutoProvisionedRole,
                BootstrapTokenHash = settings?.BootstrapTokenHash,
                Approvals = approveLosses ? new HashSet<string> { LegacyImportApprovals.UnresolvedUsers } : new HashSet<string>(),
            },
        });

    private static async Task<List<string>> RowsAsync(TestDatabase db, string sql)
    {
        await using var connection = new SqlConnection(db.ConnectionString);
        await connection.OpenAsync();
        await using var command = new SqlCommand(sql, connection);
        var rows = new List<string>();
        await using var reader = await command.ExecuteReaderAsync();
        while (await reader.ReadAsync())
            rows.Add(string.Join("|", Enumerable.Range(0, reader.FieldCount).Select(i => reader.IsDBNull(i) ? "null" : Convert.ToString(reader.GetValue(i)))));
        return rows;
    }

    [TestMethod]
    public async Task The_legacy_schema_is_copied_into_the_new_model()
    {
        await using var db = await PrepareAsync();

        var report = await ImportAsync(db);

        Assert.IsTrue(report.Applied, LegacyImporter.ToText(report));
        CollectionAssert.AreEqual(new[] { "1|super-admin", "2|order-reader", "3|empty-role" }, await RowsAsync(db, "SELECT RoleId, roleValue FROM authz.LegacyRoleMap ORDER BY RoleId"));
        CollectionAssert.AreEqual(new[] { "order-reader|Orders.Read", "super-admin|*" },
            await RowsAsync(db, "SELECT roleValue, PermissionCode FROM authz.RolePermission ORDER BY roleValue"), "Orders.Write is not declared: not copied");
        CollectionAssert.AreEqual(new[] { $"{Admin}|order-reader", $"{Admin}|super-admin", $"{Reader}|order-reader", $"{Nothing}|empty-role" },
            await RowsAsync(db, "SELECT objectId, roleValue FROM authz.UserRole ORDER BY objectId, roleValue"));
        CollectionAssert.AreEqual(new[] { $"{Admin}|1|True", $"{Reader}|2|False", $"{Nothing}|4|True" },
            await RowsAsync(db, "SELECT objectId, legacyUserId, isActive FROM authz.UserProfile ORDER BY legacyUserId"), "the inactive user is suspended, with their role");
        CollectionAssert.AreEqual(new[] { $"1|{Admin}|True", "2|legacy:3|False" },
            await RowsAsync(db, "SELECT PersonalAccessTokenId, ownerObjectId, isActive FROM authz.PersonalAccessToken ORDER BY 1"), "an owner without identity: inactive");
        Assert.IsTrue(report.Issues.Any(i => i.Code == "code-undeclared" && i.Detail.Contains("Orders.Write")));
        Assert.IsTrue(report.Issues.Any(i => i.Code == "unresolved-user" && i.LegacyUserId == 3));
    }

    [TestMethod]
    public async Task The_audit_log_is_copied_with_the_new_keys_and_its_labels_untouched()
    {
        await using var db = await PrepareAsync();

        var report = await ImportAsync(db, batch: 1);

        Assert.AreEqual(4, report.AuditCopied);
        CollectionAssert.AreEqual(new[]
        {
            $"1|{Admin}|user|{Reader}|reader@test",
            $"2|{Admin}|role|order-reader|Order Reader",
            "3|legacy:3|pat|1|limited",
            "4|null|role|legacy:99|gone",
        }, await RowsAsync(db, "SELECT AuditLogId, actorObjectId, targetType, targetId, targetLabel FROM authz.AuditLog ORDER BY AuditLogId"));
        Assert.AreEqual(5, await db.ScalarAsync<int>("INSERT INTO authz.AuditLog (actorEmail, action, targetType, targetLabel) VALUES ('x', 'a', 't', 'l'); SELECT CAST(SCOPE_IDENTITY() AS INT);"),
            "the identity continues after the copied ids");
    }

    [TestMethod]
    public async Task The_dry_run_counts_everything_and_changes_nothing()
    {
        await using var db = await PrepareAsync();

        var report = await ImportAsync(db, apply: false);

        Assert.IsFalse(report.Applied);
        Assert.AreEqual(3, report.Changes["Role"].Inserted);
        Assert.AreEqual(4, report.Changes["UserRole"].Inserted);
        Assert.AreEqual(4, report.AuditCopied, "pending");
        Assert.AreEqual(0, await db.ScalarAsync<int>("SELECT COUNT(*) FROM authz.Role"));
        Assert.AreEqual(0, await db.ScalarAsync<int>("SELECT COUNT(*) FROM authz.AuditLog"));
    }

    [TestMethod]
    public async Task Importing_again_changes_nothing()
    {
        await using var db = await PrepareAsync();
        await ImportAsync(db);

        var again = await ImportAsync(db);

        Assert.IsTrue(again.Changes.Where(c => c.Key != "UserRole").All(c => c.Value == (0, 0, 0)), LegacyImporter.ToText(again));
        Assert.AreEqual(again.Changes["UserRole"].Inserted, again.Changes["UserRole"].Deleted, "recomputed: the same rows");
        Assert.AreEqual(0, again.AuditCopied);
    }

    /// <summary>The test the plan makes mandatory: a revocation in the legacy schema between two imports is revoked in the target.</summary>
    [TestMethod]
    public async Task What_is_revoked_in_the_legacy_schema_between_two_imports_is_revoked_in_the_target()
    {
        await using var db = await PrepareAsync();
        await ImportAsync(db);

        await db.ExecuteAsync("""
            DELETE FROM auth.UserRole WHERE UserId = 1 AND RoleId = 1;           -- a role taken away
            UPDATE auth.PersonalAccessToken SET isActive = 0 WHERE name = 'limited'; -- a token deactivated
            DELETE FROM auth.RolePermission WHERE RoleId = 2;                      -- what a role grants, taken away
            DELETE FROM auth.UserRole WHERE RoleId = 3; DELETE FROM auth.Role WHERE RoleId = 3; -- a role deleted
            INSERT INTO auth.AuditLog (actorUserId, actorEmail, action, targetType, targetId, targetLabel) VALUES (1, 'admin@test', 'access.revoked', 'user', 1, 'admin@test');
            """);
        var report = await ImportAsync(db);

        Assert.IsTrue(report.Applied, LegacyImporter.ToText(report));
        CollectionAssert.AreEqual(new[] { $"{Admin}|order-reader", $"{Reader}|order-reader" }, await RowsAsync(db, "SELECT objectId, roleValue FROM authz.UserRole ORDER BY 1, 2"));
        Assert.AreEqual(0, await db.ScalarAsync<int>("SELECT COUNT(*) FROM authz.RolePermission WHERE roleValue = 'order-reader'"));
        Assert.AreEqual(0, await db.ScalarAsync<int>("SELECT COUNT(*) FROM authz.Role WHERE roleValue = 'empty-role'"));
        Assert.AreEqual(1, await db.ScalarAsync<int>("SELECT COUNT(*) FROM authz.LegacyRoleMap WHERE roleValue = 'empty-role'"), "the map is never rewritten");
        Assert.IsFalse(await db.ScalarAsync<bool>("SELECT isActive FROM authz.PersonalAccessToken WHERE PersonalAccessTokenId = 1"));
        Assert.AreEqual(1, report.AuditCopied);
    }

    [TestMethod]
    public async Task A_user_who_would_lose_their_access_needs_an_approval_and_nothing_is_written_without_it()
    {
        await using var db = await PrepareAsync();

        var report = await ImportAsync(db, approveLosses: false);

        Assert.IsTrue(report.HasBlockers);
        StringAssert.Contains(report.Issues.Single(i => i.Severity == IssueSeverity.Blocker && i.Code == "unresolved-user").Detail, LegacyImportApprovals.UnresolvedUsers);
        Assert.AreEqual(0, await db.ScalarAsync<int>("SELECT COUNT(*) FROM authz.Role"));
    }

    [TestMethod]
    public async Task Identities_resolved_too_long_ago_or_before_a_change_are_refused()
    {
        await using var db = await PrepareAsync(resolve: false);
        await ResolveAsync(db, DateTime.UtcNow.AddHours(-13));

        var stale = await ImportAsync(db);
        await ResolveAsync(db);
        await db.ExecuteAsync("UPDATE auth.[User] SET isActive = 0 WHERE UserId = 1;");
        var changed = await ImportAsync(db);

        Assert.IsTrue(stale.Issues.Any(i => i.Code == "identities" && i.Detail.Contains("13")));
        Assert.IsTrue(changed.Issues.Any(i => i.Code == "identities" && i.Detail.Contains("changed")));
    }

    [TestMethod]
    public async Task Without_resolved_identities_nothing_is_imported()
    {
        await using var db = await PrepareAsync(resolve: false);

        var report = await ImportAsync(db);

        StringAssert.Contains(report.Issues.Single(i => i.Code == "identities").Detail, "kdyf-auth resolve");
    }

    [TestMethod]
    public async Task A_target_that_is_not_installed_or_was_cut_over_is_refused()
    {
        await using var db = await TestDatabase.CreateAsync();
        await db.ExecuteAsync(LegacyFixtures.ShapeC);

        var notInstalled = await ImportAsync(db);
        await new SchemaMigrator(db.ConnectionString, new SchemaMigrationOptions { Schema = Target }).ApplyAsync();
        await new SchemaMigrator(db.ConnectionString, new SchemaMigrationOptions { Schema = Target }).MarkCutoverAsync();
        var cutOver = await ImportAsync(db);

        Assert.IsTrue(notInstalled.Issues.Any(i => i.Code == "target-not-ready"));
        Assert.IsTrue(cutOver.Issues.Any(i => i.Code == "cutover-completed"));
    }

    [TestMethod]
    public async Task The_auto_provisioned_role_and_the_bootstrap_token_are_not_carried_over_alive()
    {
        await using var db = await PrepareAsync();
        await ApproveAsync(db, new InvariantException(InvariantKinds.TokenCount, null, null, -2, "bootstrap and ownerless tokens", "test"));

        var report = await ImportAsync(db, settings: new LegacyImportSettings
        {
            AutoProvisionedRole = "empty role",
            BootstrapTokenHash = "0101010101010101010101010101010101010101010101010101010101010101",
        });

        Assert.IsTrue(report.Applied, LegacyImporter.ToText(report));
        Assert.AreEqual(0, await db.ScalarAsync<int>("SELECT COUNT(*) FROM authz.Role WHERE roleValue = 'empty-role'"));
        Assert.AreEqual(0, await db.ScalarAsync<int>($"SELECT COUNT(*) FROM authz.UserRole WHERE objectId = '{Nothing}'"));
        Assert.IsFalse(await db.ScalarAsync<bool>("SELECT isActive FROM authz.PersonalAccessToken WHERE PersonalAccessTokenId = 1"));
    }

    [TestMethod]
    public async Task A_host_step_runs_in_the_same_transaction_and_its_failure_undoes_everything()
    {
        await using var db = await PrepareAsync();
        var step = new RecordingStep();

        await ImportAsync(db, steps: new[] { step });
        await Assert.ThrowsExceptionAsync<InvalidOperationException>(() => ImportAsync(db, steps: new ILegacyImportHostStep[] { new FailingStep() }));

        Assert.AreEqual("super-admin", step.RoleMap![1]);
        Assert.AreEqual(Admin, step.UserMap![1]);
        Assert.AreEqual(3, await db.ScalarAsync<int>("SELECT COUNT(*) FROM authz.Role"), "the failed run left the previous copy");
    }

    /// <summary>
    /// Nobody gains, on the real copy: the base access of members (Default) would be new for everybody, so the import is
    /// refused and writes nothing, until a person approves it with the exceptions command.
    /// </summary>
    [TestMethod]
    public async Task A_gain_refuses_the_import_until_its_exception_is_approved_through_the_command()
    {
        await using var db = await PrepareAsync();
        var invariant = new InvariantSettings { MemberGrants = new[] { "Default" } };

        var refused = await ImportAsync(db, invariant: invariant);
        Assert.IsTrue(refused.Issues.Any(i => i.Code == "gain" && i.Severity == IssueSeverity.Blocker && i.Detail.Contains("'Default'")), LegacyImporter.ToText(refused));
        Assert.AreEqual(0, await db.ScalarAsync<int>("SELECT COUNT(*) FROM authz.Role"), "nothing written");

        var file = Path.Combine(Path.GetTempPath(), $"exceptions-{Guid.NewGuid():N}.json");
        try
        {
            await File.WriteAllTextAsync(file, """
                { "exceptions": [
                  { "kind": "member-base-access", "reason": "Members of the new gate get the base access" },
                  { "kind": "token-count", "value": -1, "reason": "user 3 has no identity" } ] }
                """);
            var output = new StringWriter();
            var services = new Microsoft.Extensions.DependencyInjection.ServiceCollection()
                .AddSingleton<ILegacyDirectory>(new NoDirectory()).AddSingleton<IMembershipSource>(new NoDirectory())
                .AddKdyfAuthorizationLegacyImport(o => o.LegacyGroupId = Guid.NewGuid().ToString())
                .BuildServiceProvider();
            var code = await SchemaCommandLine.RunAsync(new[] { "exceptions", "import", file, "--approver", "carlos" }, db.ConnectionString, Target, output, services);
            Assert.AreEqual(SchemaCommandLine.Ok, code, output.ToString());
        }
        finally
        {
            File.Delete(file);
        }

        var approved = await ImportAsync(db, invariant: invariant);
        Assert.IsTrue(approved.Applied, LegacyImporter.ToText(approved));
        Assert.AreEqual("carlos", await db.ScalarAsync<string>("SELECT TOP 1 ApprovedBy FROM authz.MigrationException"));
    }

    // ── The cutover and after ────────────────────────────────────────────────

    /// <summary>Imported, the reductions accepted, the go/no-go green, and cut over.</summary>
    private static async Task<TestDatabase> CutOverAsync()
    {
        var db = await PrepareAsync();
        Assert.IsTrue((await ImportAsync(db)).Applied);
        var dryRun = await ImportAsync(db, apply: false);
        await LegacyCutover.AcceptReductionsAsync(db.ConnectionString, Target, dryRun.Invariant!, "carlos", default);
        var checks = await LegacyCutover.CheckAsync(db.ConnectionString, Target, dryRun, default);
        Assert.IsTrue(checks.All(c => c.Passed), string.Join("\n", checks));
        await LegacyCutover.CutoverAsync(db.ConnectionString, Target, "carlos", TimeSpan.FromHours(48), default);
        return db;
    }

    [TestMethod]
    public async Task The_go_no_go_wants_the_reductions_accepted_and_the_copy_in_sync()
    {
        await using var db = await PrepareAsync();
        await ImportAsync(db);

        var dryRun = await ImportAsync(db, apply: false);
        var notAccepted = await LegacyCutover.CheckAsync(db.ConnectionString, Target, dryRun, default);
        await LegacyCutover.AcceptReductionsAsync(db.ConnectionString, Target, dryRun.Invariant!, "carlos", default);
        await db.ExecuteAsync("DELETE FROM auth.UserRole WHERE UserId = 1 AND RoleId = 2;");
        var changedSince = await LegacyCutover.CheckAsync(db.ConnectionString, Target, await ImportAsync(db, apply: false), default);

        Assert.IsFalse(notAccepted.Single(c => c.Name == "reductions accepted").Passed);
        Assert.IsTrue(notAccepted.Single(c => c.Name == "in sync with the legacy schema").Passed);
        Assert.IsFalse(changedSince.Single(c => c.Name == "in sync with the legacy schema").Passed, "a change since the last apply");
    }

    /// <summary>A different list of reductions needs a new acceptance: the one given was for another list.</summary>
    [TestMethod]
    public async Task An_acceptance_holds_for_the_list_it_accepted_only()
    {
        await using var db = await PrepareAsync();
        await ImportAsync(db);
        await LegacyCutover.AcceptReductionsAsync(db.ConnectionString, Target, (await ImportAsync(db, apply: false)).Invariant!, "carlos", default);

        await db.ExecuteAsync("DELETE FROM auth.RolePermission WHERE RoleId = 2 AND PermissionCode = 'Orders.Read';");
        await ImportAsync(db);
        var checks = await LegacyCutover.CheckAsync(db.ConnectionString, Target, await ImportAsync(db, apply: false), default);

        Assert.IsFalse(checks.Single(c => c.Name == "reductions accepted").Passed);
    }

    [TestMethod]
    public async Task After_the_cutover_the_import_never_runs_again()
    {
        await using var db = await CutOverAsync();

        var report = await ImportAsync(db);

        Assert.IsTrue(report.Issues.Any(i => i.Code == "cutover-completed"));
    }

    /// <summary>
    /// The rollback window: what an administrator revoked in the new application goes back to the legacy one, so going back
    /// does not undo it. What was granted does not, and the tokens the import copied inactive on purpose stay as they were.
    /// </summary>
    [TestMethod]
    public async Task Rollback_sync_takes_back_the_revocations_and_nothing_else()
    {
        await using var db = await CutOverAsync();
        await db.ExecuteAsync($"""
            DELETE FROM authz.UserRole WHERE objectId = '{Admin}' AND roleValue = 'super-admin';            -- a role taken away
            UPDATE authz.UserProfile SET isActive = 0 WHERE objectId = '{Nothing}';                         -- somebody suspended
            DELETE FROM authz.RolePermission WHERE roleValue = 'order-reader' AND PermissionCode = 'Orders.Read'; -- a permission taken away
            INSERT INTO authz.UserRole (objectId, roleValue) VALUES ('{Reader}', 'super-admin');               -- a grant: never taken back
            UPDATE authz.PersonalAccessToken SET isActive = 0 WHERE PersonalAccessTokenId = 1;
            INSERT INTO authz.AuditLog (actorObjectId, actorEmail, action, targetType, targetId, targetLabel) VALUES ('{Admin}', 'admin@test', 'pat.deactivated', 'pat', '1', 'limited');
            """);

        var plan = await LegacyCutover.RollbackSyncAsync(db.ConnectionString, "auth", Target, apply: false, default);
        Assert.AreEqual(1, plan.Single(c => c.Table == "UserRole").Count);
        Assert.AreEqual(1, await db.ScalarAsync<int>("SELECT COUNT(*) FROM auth.UserRole WHERE UserId = 1 AND RoleId = 1"), "the dry run changed nothing");

        var applied = await LegacyCutover.RollbackSyncAsync(db.ConnectionString, "auth", Target, apply: true, default);

        CollectionAssert.AreEqual(new[] { 1, 1, 1, 1 }, applied.Select(c => c.Count).ToArray(), string.Join(" ", applied));
        Assert.AreEqual(0, await db.ScalarAsync<int>("SELECT COUNT(*) FROM auth.UserRole WHERE UserId = 1 AND RoleId = 1"));
        Assert.AreEqual(0, await db.ScalarAsync<int>("SELECT COUNT(*) FROM auth.UserRole WHERE UserId = 2 AND RoleId = 1"), "the grant is not taken back");
        Assert.IsFalse(await db.ScalarAsync<bool>("SELECT isActive FROM auth.[User] WHERE UserId = 4"));
        Assert.AreEqual(0, await db.ScalarAsync<int>("SELECT COUNT(*) FROM auth.RolePermission WHERE RoleId = 2 AND PermissionCode = 'Orders.Read'"));
        Assert.AreEqual(1, await db.ScalarAsync<int>("SELECT COUNT(*) FROM auth.RolePermission WHERE RoleId = 2 AND PermissionCode = 'Orders.Write'"), "undeclared: never copied, never taken back");
        Assert.IsFalse(await db.ScalarAsync<bool>("SELECT isActive FROM auth.PersonalAccessToken WHERE name = 'limited'"));
        Assert.IsTrue(await db.ScalarAsync<bool>("SELECT isActive FROM auth.PersonalAccessToken WHERE name = 'service'"), "copied inactive on purpose: left as it is");

        var again = await LegacyCutover.RollbackSyncAsync(db.ConnectionString, "auth", Target, apply: true, default);
        Assert.IsTrue(again.All(c => c.Count == 0), "repeatable");
    }

    [TestMethod]
    public async Task Rollback_sync_before_the_cutover_is_refused()
    {
        await using var db = await PrepareAsync();

        await Assert.ThrowsExceptionAsync<InvalidOperationException>(() => LegacyCutover.RollbackSyncAsync(db.ConnectionString, "auth", Target, true, default));
    }

    [TestMethod]
    public async Task The_contraction_waits_for_the_window_renames_and_only_then_drops()
    {
        await using var db = await CutOverAsync();

        await Assert.ThrowsExceptionAsync<InvalidOperationException>(() => LegacyCutover.ContractAsync(db.ConnectionString, "auth", Target, false, DateTime.UtcNow, default));
        await Assert.ThrowsExceptionAsync<InvalidOperationException>(() => LegacyCutover.ContractAsync(db.ConnectionString, "auth", Target, true, DateTime.UtcNow.AddDays(3), default));

        var later = DateTime.UtcNow.AddDays(3);
        var renamed = await LegacyCutover.ContractAsync(db.ConnectionString, "auth", Target, false, later, default);
        var schema = $"auth_legacy_{later:yyyyMMdd}";

        StringAssert.Contains(renamed, schema);
        Assert.AreEqual(0, await db.ScalarAsync<int>("SELECT COUNT(*) FROM sys.tables WHERE schema_id = SCHEMA_ID('auth')"));
        Assert.AreEqual(7, await db.ScalarAsync<int>($"SELECT COUNT(*) FROM sys.tables WHERE schema_id = SCHEMA_ID('{schema}')"));
        Assert.AreEqual(4, await db.ScalarAsync<int>($"SELECT COUNT(*) FROM [{schema}].[User]"), "the data moved with the tables");

        await LegacyCutover.ContractAsync(db.ConnectionString, schema, Target, true, later, default);
        Assert.IsNull(await db.ScalarAsync<object>($"SELECT SCHEMA_ID('{schema}')"));
        Assert.AreEqual(3, await db.ScalarAsync<int>("SELECT COUNT(*) FROM authz.Role"), "the target is untouched");
    }

    private sealed class NoDirectory : ILegacyDirectory, IMembershipSource
    {
        public Task<DirectoryPerson?> GetAsync(string objectId, CancellationToken cancellationToken = default) => Task.FromResult<DirectoryPerson?>(null);
        public Task<IReadOnlyList<DirectoryPerson>> FindExactAsync(string email, CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<DirectoryPerson>>(Array.Empty<DirectoryPerson>());
        public Task<bool> InLegacyGroupAsync(string objectId, CancellationToken cancellationToken = default) => Task.FromResult(false);
        public Task<Membership?> GetMembershipAsync(string subjectId, CancellationToken cancellationToken = default) => Task.FromResult<Membership?>(null);
        public Task<DirectoryIdentity?> FindByEmailAsync(string email, CancellationToken cancellationToken = default) => Task.FromResult<DirectoryIdentity?>(null);
    }

    private sealed class RecordingStep : ILegacyImportHostStep
    {
        public string Id => "record";
        public IReadOnlyDictionary<int, string>? RoleMap { get; private set; }
        public IReadOnlyDictionary<int, string>? UserMap { get; private set; }

        public Task ApplyAsync(LegacyImportContext context, CancellationToken cancellationToken)
        {
            (RoleMap, UserMap) = (context.RoleMap, context.UserMap);
            return Task.CompletedTask;
        }
    }

    private sealed class FailingStep : ILegacyImportHostStep
    {
        public string Id => "fail";

        public async Task ApplyAsync(LegacyImportContext context, CancellationToken cancellationToken)
        {
            await using var command = context.Connection.CreateCommand();
            command.Transaction = context.Transaction;
            command.CommandText = $"DELETE FROM [{context.TargetSchema}].[UserRole]";
            await command.ExecuteNonQueryAsync(cancellationToken);
            throw new InvalidOperationException("vault.EntryAccess has a role id with no mapping");
        }
    }

    private sealed class EverythingPermission : PermissionDefinition
    {
        public EverythingPermission() : base(CodeShape.Verbatim, "*", "Everything") { }
    }

    private sealed class DefaultPermission : PermissionDefinition
    {
        public DefaultPermission() : base(CodeShape.Verbatim, "Default", "Base access") { }
    }

    private sealed class OrdersRead : PermissionDefinition
    {
        public OrdersRead() : base(CodeShape.Verbatim, "Orders.Read", "Read orders") { }
    }
}
