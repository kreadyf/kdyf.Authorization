using kdyf.Authorization.Abstractions;
using kdyf.Authorization.Migrations.Legacy;
using kdyf.Authorization.Migrations.Schema;
using Microsoft.Data.SqlClient;

namespace kdyf.Authorization.Migrations.Test;

/// <summary>
/// The bank of dirty data (plan, phase 5.7): one synthetic legacy database per case, run through the whole chain — report,
/// resolution against an in-memory Entra, import with the invariant — and each ends either in success with the expected
/// result, or in a blocker with its message and the target exactly as it was. Never in between.
/// </summary>
[TestClass]
public sealed class DirtyDataBankTests
{
    private const string Target = "authz";
    private const string Admin = "0f1e2d3c-0000-0000-0000-0000000000a1";
    private const string Admin2 = "0f1e2d3c-0000-0000-0000-0000000000a2";
    private const string Ana = "0f1e2d3c-0000-0000-0000-0000000000b1";
    private const string Ben = "0f1e2d3c-0000-0000-0000-0000000000b2";
    private const string Guest = "0f1e2d3c-0000-0000-0000-0000000000c1";

    private static readonly PermissionDefinition[] Declared =
        { new Code("*"), new Code("Default"), new Code("Orders.*"), new Code("Orders.Read"), new Code("Orders.Write"), new Code("Admin") };

    /// <summary>
    /// The legacy shape a database created by EF has (no unique e-mail or object id, no foreign keys): where the dirt that
    /// the final script's constraints prevent can exist.
    /// </summary>
    private static string ShapeEf => LegacyFixtures.ShapeC + """

        GO
        ALTER TABLE auth.UserRole DROP CONSTRAINT FK_UserRole_User, FK_UserRole_Role;
        ALTER TABLE auth.RolePermission DROP CONSTRAINT FK_RolePermission_Role, FK_RolePermission_Permission;
        ALTER TABLE auth.Role DROP CONSTRAINT UQ_Role_Name;
        ALTER TABLE auth.[User] DROP CONSTRAINT UQ_User_Email;
        DROP INDEX IX_User_ObjectId ON auth.[User];
        """;

    /// <summary>Two administrators (the minimum) holding role 1 ('*'), and Ana reading orders (role 2).</summary>
    private const string Base = """
        INSERT INTO auth.Permission (PermissionCode) VALUES ('*'), ('Default'), ('Orders.*'), ('Orders.Read'), ('Orders.Write'), ('Admin');
        SET IDENTITY_INSERT auth.Role ON;
        INSERT INTO auth.Role (RoleId, name) VALUES (1, 'Admins'), (2, 'Order Readers');
        SET IDENTITY_INSERT auth.Role OFF;
        INSERT INTO auth.RolePermission (RoleId, PermissionCode) VALUES (1, '*'), (2, 'Orders.Read');
        SET IDENTITY_INSERT auth.[User] ON;
        INSERT INTO auth.[User] (UserId, email, objectId, isActive) VALUES
            (1, 'admin@test', '0f1e2d3c-0000-0000-0000-0000000000a1', 1),
            (2, 'admin2@test', '0f1e2d3c-0000-0000-0000-0000000000a2', 1),
            (3, 'ana@test', '0f1e2d3c-0000-0000-0000-0000000000b1', 1);
        SET IDENTITY_INSERT auth.[User] OFF;
        INSERT INTO auth.UserRole (UserId, RoleId) VALUES (1, 1), (2, 1), (3, 2);
        """;

    private static TestDirectory Tenant() => new TestDirectory()
        .Person(Admin, "admin@test").Person(Admin2, "admin2@test").Person(Ana, "ana@test").Person(Ben, "ben@test");

    // ── The cases ────────────────────────────────────────────────────────────

    [TestMethod]
    public async Task Clean_data_is_imported() =>
        await RunAsync(ShapeEf, "", Tenant(), Expect.Success, async db =>
            Assert.AreEqual(3, await db.ScalarAsync<int>("SELECT COUNT(*) FROM authz.UserRole")));

    /// <summary>No object id, but exactly one person with that UPN: resolved, imported.</summary>
    [TestMethod]
    public async Task A_user_without_object_id_found_by_upn_is_imported() =>
        await RunAsync(ShapeEf, "INSERT INTO auth.[User] (email, objectId) VALUES ('ben@test', NULL); INSERT INTO auth.UserRole VALUES (4, 2);",
            Tenant(), Expect.Success, async db =>
                Assert.AreEqual("order-readers", await db.ScalarAsync<string>($"SELECT roleValue FROM authz.UserRole WHERE objectId = '{Ben}'")));

    /// <summary>No object id and nobody in Entra: they would lose their access. Refused, then imported with the loss approved.</summary>
    [TestMethod]
    public async Task A_user_nobody_matches_blocks_until_the_loss_is_approved()
    {
        const string Dirt = "INSERT INTO auth.[User] (email, objectId) VALUES ('gone@test', NULL); INSERT INTO auth.UserRole VALUES (4, 2);";
        await RunAsync(ShapeEf, Dirt, Tenant(), Expect.Blocked("unresolved-user"));
        await RunAsync(ShapeEf, Dirt, Tenant(), Expect.Success, approveLosses: true);
    }

    /// <summary>Two people share the address: never one of them at random.</summary>
    [TestMethod]
    public async Task An_ambiguous_user_blocks() =>
        await RunAsync(ShapeEf, "INSERT INTO auth.[User] (email, objectId) VALUES ('twin@test', NULL); INSERT INTO auth.UserRole VALUES (4, 2);",
            Tenant().Person("0f1e2d3c-0000-0000-0000-0000000000d1", "twin1@test", mail: "twin@test").Person("0f1e2d3c-0000-0000-0000-0000000000d2", "twin2@test", mail: "twin@test"),
            Expect.Blocked("unresolved-user", "ambiguous"));

    /// <summary>A guest is imported only once a person approves the identity.</summary>
    [TestMethod]
    public async Task A_guest_blocks_until_approved()
    {
        const string Dirt = "INSERT INTO auth.[User] (email, objectId) VALUES ('guest@outside.test', '0f1e2d3c-0000-0000-0000-0000000000c1'); INSERT INTO auth.UserRole VALUES (4, 2);";
        var tenant = Tenant().Person(Guest, "guest_outside.test#EXT#@test", mail: "guest@outside.test", userType: "Guest");
        await RunAsync(ShapeEf, Dirt, tenant, Expect.Blocked("unresolved-user", "guest"));
        await RunAsync(ShapeEf, Dirt, tenant, Expect.Success, approveIdentities: new[] { 4 });
    }

    /// <summary>Two legacy users on one object id: merging their roles would widen each.</summary>
    [TestMethod]
    public async Task Two_users_with_one_object_id_block() =>
        await RunAsync(ShapeEf, "INSERT INTO auth.[User] (email, objectId) VALUES ('ana.old@test', '0F1E2D3C-0000-0000-0000-0000000000B1'); INSERT INTO auth.UserRole VALUES (4, 1);",
            Tenant(), Expect.Blocked("duplicate-object-id"));

    /// <summary>One address, two object ids: the import stops.</summary>
    [TestMethod]
    public async Task One_email_with_two_object_ids_blocks() =>
        await RunAsync(ShapeEf, "INSERT INTO auth.[User] (email, objectId) VALUES ('ANA@test', '0f1e2d3c-0000-0000-0000-0000000000b2');",
            Tenant(), Expect.Blocked("duplicate-email"));

    /// <summary>A legacy host's 'MFA Viewer' and 'MfaViewer': two roles, two values, never merged.</summary>
    [TestMethod]
    public async Task Two_roles_with_almost_the_same_name_stay_two() =>
        await RunAsync(ShapeEf, """
            SET IDENTITY_INSERT auth.Role ON; INSERT INTO auth.Role (RoleId, name) VALUES (3, 'MFA Viewer'), (4, 'MFA viewer'); SET IDENTITY_INSERT auth.Role OFF;
            """, Tenant(), Expect.Success, async db =>
                CollectionAssert.AreEqual(new[] { "3|mfa-viewer", "4|mfa-viewer-4" }, await RowsAsync(db, "SELECT RoleId, roleValue FROM authz.LegacyRoleMap WHERE RoleId > 2 ORDER BY RoleId")));

    /// <summary>Rows pointing at users or roles that do not exist: reported, not copied, nothing breaks.</summary>
    [TestMethod]
    public async Task Orphan_rows_are_left_behind() =>
        await RunAsync(ShapeEf, "INSERT INTO auth.UserRole VALUES (99, 1), (3, 99); INSERT INTO auth.RolePermission VALUES (99, 'Orders.Read');",
            Tenant(), Expect.Success, async db =>
                Assert.AreEqual(3, await db.ScalarAsync<int>("SELECT COUNT(*) FROM authz.UserRole")));

    /// <summary>Wildcards are copied as they are, and compared expanded on both sides: no gain, no loss.</summary>
    [TestMethod]
    public async Task Wildcards_are_copied_as_their_nodes() =>
        await RunAsync(ShapeEf, "INSERT INTO auth.RolePermission VALUES (2, 'Orders.*');", Tenant(), Expect.Success, async db =>
            CollectionAssert.AreEqual(new[] { "Orders", "Orders.Read" }, await RowsAsync(db, "SELECT PermissionCode FROM authz.RolePermission WHERE roleValue = 'order-readers' ORDER BY 1")));

    /// <summary>Shape B: a token limited to one of its owner's roles is copied inactive (it would hold more); its count is approved.</summary>
    [TestMethod]
    public async Task A_token_limited_to_roles_is_copied_inactive() =>
        await RunAsync(LegacyFixtures.ShapeB, """
            INSERT INTO auth.UserRole VALUES (3, 1);
            INSERT INTO auth.PersonalAccessToken (name, tokenHash, userId) VALUES ('limited', 0x0303030303030303030303030303030303030303030303030303030303030303, 3);
            INSERT INTO auth.PersonalAccessTokenRole VALUES (1, 2);
            """, Tenant(), Expect.Success, async db =>
                Assert.IsFalse(await db.ScalarAsync<bool>("SELECT isActive FROM authz.PersonalAccessToken")),
            exceptions: new[] { new InvariantException(InvariantKinds.TokenCount, null, null, -1, "limited token", "bank") });

    /// <summary>The bootstrap token whose hash was published: copied inactive.</summary>
    [TestMethod]
    public async Task The_bootstrap_token_is_copied_inactive() =>
        await RunAsync(ShapeEf, "INSERT INTO auth.PersonalAccessToken (name, tokenHash, userId) VALUES ('Bootstrap admin token', 0x0404040404040404040404040404040404040404040404040404040404040404, 1);",
            Tenant(), Expect.Success, async db =>
                Assert.IsFalse(await db.ScalarAsync<bool>("SELECT isActive FROM authz.PersonalAccessToken")),
            exceptions: new[] { new InvariantException(InvariantKinds.TokenCount, null, null, -1, "bootstrap", "bank") },
            bootstrapHash: "0404040404040404040404040404040404040404040404040404040404040404");

    /// <summary>An inactive user is a suspended person, with their roles: nothing is lost if they are reactivated.</summary>
    [TestMethod]
    public async Task An_inactive_user_is_imported_suspended() =>
        await RunAsync(ShapeEf, "UPDATE auth.[User] SET isActive = 0 WHERE UserId = 3;", Tenant(), Expect.Success, async db =>
        {
            Assert.IsFalse(await db.ScalarAsync<bool>($"SELECT isActive FROM authz.UserProfile WHERE objectId = '{Ana}'"));
            Assert.AreEqual(1, await db.ScalarAsync<int>($"SELECT COUNT(*) FROM authz.UserRole WHERE objectId = '{Ana}'"));
        });

    /// <summary>Somebody outside the legacy gate but inside the new one would gain their roles: refused.</summary>
    [TestMethod]
    public async Task Somebody_the_new_gate_lets_in_blocks() =>
        await RunAsync(ShapeEf, "", Tenant().OutsideLegacyGroup(Ana), Expect.Blocked("gain"));

    /// <summary>A user added in the legacy schema after the resolution: the identities no longer describe the users.</summary>
    [TestMethod]
    public async Task A_user_added_after_the_resolution_blocks() =>
        await RunAsync(ShapeEf, "", Tenant(), Expect.Blocked("identities", "added"),
            afterResolve: "INSERT INTO auth.[User] (email, objectId) VALUES ('late@test', '0f1e2d3c-0000-0000-0000-0000000000b2');");

    [TestMethod]
    public async Task A_stale_snapshot_blocks() =>
        await RunAsync(ShapeEf, "", Tenant(), Expect.Blocked("identities", "ago"), resolvedAt: DateTime.UtcNow.AddHours(-13));

    /// <summary>
    /// The audit copy fails half-way (a trigger stands in for a DENY on the target's audit log): the core transaction is
    /// committed whole, the batches copied stay, and the next run resumes where it stopped — nothing duplicated.
    /// </summary>
    [TestMethod]
    public async Task An_audit_copy_that_fails_half_way_resumes()
    {
        await using var db = await TestDatabase.CreateAsync();
        await PrepareAsync(db, ShapeEf, """
            SET IDENTITY_INSERT auth.AuditLog ON;
            INSERT INTO auth.AuditLog (AuditLogId, actorUserId, actorEmail, action, targetType, targetId, targetLabel)
            VALUES (1, 1, 'a', 'x', 'user', 3, 'l'), (2, 1, 'a', 'x', 'user', 3, 'l'), (3, 1, 'a', 'x', 'user', 3, 'l');
            SET IDENTITY_INSERT auth.AuditLog OFF;
            """, Tenant());
        await db.ExecuteAsync("CREATE TRIGGER authz.FailOnThird ON authz.AuditLog AFTER INSERT AS IF EXISTS (SELECT 1 FROM inserted WHERE AuditLogId = 3) THROW 50001, 'denied', 1;");

        await Assert.ThrowsExceptionAsync<SqlException>(() => ImportAsync(db, batch: 1));
        Assert.AreEqual(2, await db.ScalarAsync<int>("SELECT COUNT(*) FROM authz.AuditLog"), "two batches committed, the third rolled back");
        Assert.AreEqual(3, await db.ScalarAsync<int>("SELECT COUNT(*) FROM authz.UserRole"), "the core transaction committed whole");

        await db.ExecuteAsync("DROP TRIGGER authz.FailOnThird;");
        var resumed = await ImportAsync(db, batch: 1);

        Assert.AreEqual(1, resumed.AuditCopied);
        Assert.AreEqual(3, await db.ScalarAsync<int>("SELECT COUNT(DISTINCT AuditLogId) FROM authz.AuditLog"));
    }

    // ── The machinery ────────────────────────────────────────────────────────

    private sealed record Expect(bool Blocks, string? Code, string? Text)
    {
        public static readonly Expect Success = new(false, null, null);
        public static Expect Blocked(string code, string? text = null) => new(true, code, text);
    }

    private static async Task RunAsync(
        string shape, string dirt, TestDirectory tenant, Expect expect, Func<TestDatabase, Task>? then = null,
        bool approveLosses = false, int[]? approveIdentities = null, InvariantException[]? exceptions = null, string? bootstrapHash = null,
        string? afterResolve = null, DateTime? resolvedAt = null)
    {
        await using var db = await TestDatabase.CreateAsync();
        await PrepareAsync(db, shape, dirt, tenant, approveIdentities, exceptions, resolvedAt);
        if (afterResolve is not null)
            await db.ExecuteAsync(afterResolve);

        var before = await FingerprintAsync(db);
        var report = await ImportAsync(db, approveLosses, bootstrapHash);
        var text = LegacyImporter.ToText(report);

        if (expect.Blocks)
        {
            Assert.IsFalse(report.Applied, text);
            var blocker = report.Issues.FirstOrDefault(i => i.Severity == IssueSeverity.Blocker && i.Code == expect.Code);
            Assert.IsNotNull(blocker, $"expected a '{expect.Code}' blocker:\n{text}");
            if (expect.Text is not null)
                StringAssert.Contains(blocker.Detail, expect.Text, text);
            Assert.AreEqual(before, await FingerprintAsync(db), "refused: the target is exactly as it was");
            return;
        }

        Assert.IsTrue(report.Applied, text);
        var again = await ImportAsync(db, approveLosses, bootstrapHash);
        Assert.IsTrue(again.Changes.Where(c => c.Key != "UserRole").All(c => c.Value == (0, 0, 0)), "repeatable:\n" + LegacyImporter.ToText(again));
        if (then is not null)
            await then(db);
    }

    private static async Task PrepareAsync(
        TestDatabase db, string shape, string dirt, TestDirectory tenant, int[]? approveIdentities = null, InvariantException[]? exceptions = null, DateTime? resolvedAt = null)
    {
        await db.ExecuteAsync(shape);
        await db.ExecuteAsync(Base);
        if (dirt.Length > 0)
            await db.ExecuteAsync(dirt);
        Assert.IsTrue((await new SchemaMigrator(db.ConnectionString, new SchemaMigrationOptions { Schema = Target, UserProfiles = true }).ApplyAsync()).Succeeded);

        var (_, report) = await LegacyInspector.InspectAsync(db.ConnectionString, "auth");
        var resolver = new IdentityResolver(tenant, tenant, new LegacyImportOptions { Gate = LegacyGate.Group, LegacyGroupId = Guid.NewGuid().ToString() },
            resolvedAt is null ? null : new FixedTime(resolvedAt.Value));
        var identities = (await resolver.ResolveAsync(report!.Data.Users))
            .Select(i => approveIdentities?.Contains(i.LegacyUserId) == true ? i with { ApprovedBy = "bank", ApprovedAt = DateTime.UtcNow } : i)
            .ToList();

        await using var connection = new SqlConnection(db.ConnectionString);
        await connection.OpenAsync();
        await MigrationStore.SaveAsync(connection, Target, identities, default);
        await InvariantExceptions.ReplaceAsync(connection, Target, exceptions ?? Array.Empty<InvariantException>(), new string('0', 64), default);
    }

    private static Task<LegacyImportReport> ImportAsync(TestDatabase db, bool approveLosses = false, string? bootstrapHash = null, int batch = 5000) =>
        LegacyImporter.RunAsync(db.ConnectionString, new LegacyImportRequest
        {
            LegacySchema = "auth",
            TargetSchema = Target,
            Declared = Declared,
            Apply = true,
            AuditBatchSize = batch,
            Invariant = new InvariantSettings { AdministrationCode = "Admin", ExactCodes = new[] { "Admin" }, MinAdministrators = 2, TokensExemptFromGate = true },
            Settings = new LegacyImportSettings
            {
                BootstrapTokenHash = bootstrapHash,
                Approvals = approveLosses ? new HashSet<string> { LegacyImportApprovals.UnresolvedUsers } : new HashSet<string>(),
            },
        });

    /// <summary>Every table of the target, counted and checksummed: equal before and after means untouched.</summary>
    private static async Task<string> FingerprintAsync(TestDatabase db)
    {
        var rows = await RowsAsync(db, $"""
            DECLARE @sql NVARCHAR(MAX) = N'';
            SELECT @sql += CASE WHEN @sql = N'' THEN N'' ELSE N' UNION ALL ' END
                + N'SELECT ''' + t.name + N''', COUNT(*), ISNULL(CHECKSUM_AGG(BINARY_CHECKSUM(*)), 0) FROM [{Target}].' + QUOTENAME(t.name)
            FROM sys.tables t WHERE t.schema_id = SCHEMA_ID('{Target}') AND t.name NOT IN ('SchemaMigrationLog', 'MigrationIssue');
            EXEC (@sql + N' ORDER BY 1');
            """);
        return string.Join(";", rows);
    }

    private static async Task<List<string>> RowsAsync(TestDatabase db, string sql)
    {
        await using var connection = new SqlConnection(db.ConnectionString);
        await connection.OpenAsync();
        await using var command = new SqlCommand(sql, connection);
        var rows = new List<string>();
        await using var reader = await command.ExecuteReaderAsync();
        while (await reader.ReadAsync())
            rows.Add(string.Join("|", Enumerable.Range(0, reader.FieldCount).Select(i => Convert.ToString(reader.GetValue(i)))));
        return rows;
    }

    private sealed class Code : PermissionDefinition
    {
        public Code(string code) : base(CodeShape.Verbatim, code, code) { }
    }

    private sealed class FixedTime(DateTime at) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => new(DateTime.SpecifyKind(at, DateTimeKind.Utc));
    }

    /// <summary>Entra in memory: people, who is in the legacy group (everybody, unless said), and the new gate (everybody).</summary>
    private sealed class TestDirectory : ILegacyDirectory, IMembershipSource
    {
        private readonly List<DirectoryPerson> _people = new();
        private readonly HashSet<string> _outsideLegacy = new(StringComparer.OrdinalIgnoreCase);

        public TestDirectory Person(string objectId, string upn, string? mail = null, string userType = "Member")
        {
            _people.Add(new DirectoryPerson(objectId, upn, mail ?? upn, userType, true));
            return this;
        }

        public TestDirectory OutsideLegacyGroup(string objectId)
        {
            _outsideLegacy.Add(objectId);
            return this;
        }

        public Task<DirectoryPerson?> GetAsync(string objectId, CancellationToken cancellationToken = default) =>
            Task.FromResult(_people.FirstOrDefault(p => string.Equals(p.ObjectId, objectId, StringComparison.OrdinalIgnoreCase)));

        public Task<IReadOnlyList<DirectoryPerson>> FindExactAsync(string email, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<DirectoryPerson>>(_people.Where(p =>
                string.Equals(p.UserPrincipalName, email, StringComparison.OrdinalIgnoreCase) || string.Equals(p.Mail, email, StringComparison.OrdinalIgnoreCase)).ToList());

        public Task<bool> InLegacyGroupAsync(string objectId, CancellationToken cancellationToken = default) =>
            Task.FromResult(_people.Any(p => string.Equals(p.ObjectId, objectId, StringComparison.OrdinalIgnoreCase)) && !_outsideLegacy.Contains(objectId));

        public Task<Membership?> GetMembershipAsync(string subjectId, CancellationToken cancellationToken = default) =>
            Task.FromResult(_people.Any(p => string.Equals(p.ObjectId, subjectId, StringComparison.OrdinalIgnoreCase)) ? new Membership(true, true) : null);

        public Task<DirectoryIdentity?> FindByEmailAsync(string email, CancellationToken cancellationToken = default) => Task.FromResult<DirectoryIdentity?>(null);
    }
}
