using System.Data.Common;
using System.Text;
using System.Text.Json;
using kdyf.Authorization.Abstractions;
using kdyf.Authorization.Migrations.Schema;
using Microsoft.Data.SqlClient;

namespace kdyf.Authorization.Migrations.Legacy
{
    /// <summary>
    /// A step of the HOST inside the import's transaction, after the import's own: what only the host knows, such as
    /// a host's own <c>vault.EntryAccess</c>, which points at legacy role ids. It sees the maps; it must not touch the
    /// import's tables, and it is repeatable (it runs on every apply).
    /// </summary>
    public interface ILegacyImportHostStep
    {
        /// <summary>Stable id, for the report.</summary>
        string Id { get; }

        Task ApplyAsync(LegacyImportContext context, CancellationToken cancellationToken);
    }

    /// <summary>What a host step gets: the connection and transaction of the import, the schemas and the maps.</summary>
    public sealed class LegacyImportContext
    {
        public required DbConnection Connection { get; init; }
        public required DbTransaction Transaction { get; init; }
        public required string LegacySchema { get; init; }
        public required string TargetSchema { get; init; }
        public required IReadOnlyDictionary<int, string> RoleMap { get; init; }
        public required IReadOnlyDictionary<int, string> UserMap { get; init; }
    }

    /// <summary>What the import is asked to do.</summary>
    public sealed class LegacyImportRequest
    {
        public required string LegacySchema { get; init; }
        public required string TargetSchema { get; init; }
        public required IReadOnlyList<PermissionDefinition> Declared { get; init; }
        public LegacyImportSettings Settings { get; init; } = new();
        public IReadOnlyList<ILegacyImportHostStep> HostSteps { get; init; } = Array.Empty<ILegacyImportHostStep>();
        public TimeSpan MaxSnapshotAge { get; init; } = TimeSpan.FromHours(12);

        /// <summary>False: the dry run. The same reconciliation runs, is counted, and is rolled back.</summary>
        public bool Apply { get; init; }

        public int AuditBatchSize { get; init; } = 5000;

        /// <summary>How the invariant (nobody gains) is checked for this application.</summary>
        public InvariantSettings Invariant { get; init; } = new();
    }

    /// <summary>What an import run did, or would do.</summary>
    public sealed class LegacyImportReport
    {
        public required bool Applied { get; init; }
        public required IReadOnlyList<ImportIssue> Issues { get; init; }

        /// <summary>Per table: inserted, updated, deleted.</summary>
        public required IReadOnlyDictionary<string, (int Inserted, int Updated, int Deleted)> Changes { get; init; }

        public int AuditCopied { get; init; }
        public LegacyImportPlan? Plan { get; init; }
        public InvariantReport? Invariant { get; init; }

        public bool HasBlockers => Issues.Any(i => i.Severity == IssueSeverity.Blocker);
    }

    /// <summary>
    /// Copies a legacy kdyf.auth.* schema into a target schema of the new model, side by side, reconciling everything
    /// each time (inserts, updates and deletes): it can run again and again until the cutover. The legacy schema is only
    /// read.
    /// </summary>
    /// <remarks>
    /// Roles, grants, profiles, who holds which role, tokens and the host's steps go in ONE transaction, verified row by row
    /// (EXCEPT, both ways) before the commit: the target is either the previous copy or the new one, never between. The
    /// audit log is copied after, in batches by id, each its own transaction, resuming where the last stopped.
    /// </remarks>
    public static class LegacyImporter
    {
        public static async Task<LegacyImportReport> RunAsync(
            string connectionString, LegacyImportRequest request, CancellationToken cancellationToken = default)
        {
            var target = request.TargetSchema;
            var issues = new List<ImportIssue>();

            // Step 0: the target is a verified schema of this version, and has not been cut over.
            var verification = await new SchemaMigrator(connectionString, new SchemaMigrationOptions { Schema = target }).VerifyAsync(cancellationToken);
            foreach (var issue in verification.Issues)
                issues.Add(new(IssueSeverity.Blocker, "target-not-ready", null, $"{issue.Message} Run 'kdyf-auth apply --schema {target}' first."));
            if (verification.Detection.CutoverCompleted)
                issues.Add(new(IssueSeverity.Blocker, "cutover-completed", null, $"[{target}] was cut over: the legacy import never runs on it again."));
            if (issues.Count > 0)
                return Refused(issues);

            await using var connection = new SqlConnection(connectionString);
            await connection.OpenAsync(cancellationToken);
            await LockAsync(connection, target, cancellationToken);

            var (shape, report) = await LegacyInspector.InspectAsync(connectionString, request.LegacySchema, request.Settings.RoleValueOverrides, cancellationToken);
            if (report is null)
                return Refused(new[] { new ImportIssue(IssueSeverity.Blocker, "legacy-shape", null, $"Legacy shape {shape.Label}: {shape.Description}") });

            var identities = await MigrationStore.LoadAsync(connection, target, cancellationToken);
            foreach (var problem in IdentityFreshness.Problems(report.Data.Users, identities, DateTime.UtcNow, request.MaxSnapshotAge))
                issues.Add(new(IssueSeverity.Blocker, "identities", null, problem));

            var mapped = await MappedRolesAsync(connection, target, cancellationToken);
            var declared = request.Declared.Select(p => p.Code).ToHashSet(StringComparer.Ordinal);
            var plan = LegacyImportPlan.Build(report.Data, report, identities, declared, mapped, request.Settings, DateTime.UtcNow);
            issues.AddRange(plan.Issues);

            // Step 10 (meaning): nobody gains. On the plan, before anything is written; the copy is then verified to equal it.
            // Only on a plan without blockers: what it would decide is not known until they are resolved.
            if (issues.Any(i => i.Severity == IssueSeverity.Blocker))
                return new LegacyImportReport { Applied = false, Issues = issues, Changes = new Dictionary<string, (int, int, int)>(), Plan = plan };
            var exceptions = await InvariantExceptions.LoadAsync(connection, target, cancellationToken);
            var invariant = AccessInvariant.Check(report.Data, identities, plan, declared, request.Invariant, exceptions, DateTime.UtcNow);
            issues.AddRange(invariant.Issues);
            if (issues.Any(i => i.Severity == IssueSeverity.Blocker))
                return new LegacyImportReport { Applied = false, Issues = issues, Changes = new Dictionary<string, (int, int, int)>(), Plan = plan, Invariant = invariant };

            // Step 1–8, in one transaction: committed by apply, rolled back by the dry run.
            await ExecuteAsync(connection, null, MigrationStore.BootstrapSql(target) + ImportTablesSql(target), cancellationToken);
            var runId = Guid.NewGuid();
            var changes = new Dictionary<string, (int, int, int)>();
            await using (var transaction = (SqlTransaction)await connection.BeginTransactionAsync(cancellationToken))
            {
                await LoadDesiredAsync(connection, transaction, plan, cancellationToken);
                await ReconcileAsync(connection, transaction, target, request.Declared, changes, cancellationToken);

                foreach (var step in request.HostSteps)
                    await step.ApplyAsync(new LegacyImportContext
                    {
                        Connection = connection, Transaction = transaction, LegacySchema = report.Data.Schema, TargetSchema = target,
                        RoleMap = plan.RoleMap, UserMap = plan.UserMap,
                    }, cancellationToken);

                // Step 10 (structure): what the target holds is exactly the plan, row by row, both ways.
                var differences = await DifferencesAsync(connection, transaction, target, cancellationToken);
                if (differences.Count > 0)
                    throw new InvalidOperationException("The copy does not match the plan; nothing was changed: " + string.Join(" ", differences));

                await RecordIssuesAsync(connection, transaction, target, runId, plan.Issues.Concat(invariant.Issues)
                    .Concat(invariant.Reductions.Select(r => new ImportIssue(IssueSeverity.Info, "reduction", r.Key, "loses " + string.Join(", ", r.Value)))), cancellationToken);

                if (request.Apply)
                    await transaction.CommitAsync(cancellationToken);
                else
                    await transaction.RollbackAsync(cancellationToken);
            }

            // Step 7: the audit log, in batches, only when applying; counted otherwise.
            var audit = report.Data.AuditLogCount == 0 ? 0
                : request.Apply ? await CopyAuditAsync(connection, report.Data.Schema, target, request.AuditBatchSize, cancellationToken)
                : await PendingAuditAsync(connection, report.Data.Schema, target, cancellationToken);

            // Step 9: identities follow the ids copied explicitly.
            if (request.Apply)
            {
                await ExecuteAsync(connection, null,
                    $"DBCC CHECKIDENT (N'[{target}].[PersonalAccessToken]', RESEED) WITH NO_INFOMSGS; DBCC CHECKIDENT (N'[{target}].[AuditLog]', RESEED) WITH NO_INFOMSGS;",
                    cancellationToken);
                await LogAsync(connection, target, runId, plan, changes, audit, cancellationToken);
            }

            return new LegacyImportReport { Applied = request.Apply, Issues = issues, Changes = changes, AuditCopied = audit, Plan = plan, Invariant = invariant };
        }

        private static LegacyImportReport Refused(IEnumerable<ImportIssue> issues) =>
            new() { Applied = false, Issues = issues.ToList(), Changes = new Dictionary<string, (int, int, int)>() };

        /// <summary>The permanent map of legacy role ids, and the record of what each run decided.</summary>
        private static string ImportTablesSql(string schema) => $"""

            IF OBJECT_ID(N'[{schema}].[LegacyRoleMap]') IS NULL
            CREATE TABLE [{schema}].[LegacyRoleMap] (
                RoleId    INT          NOT NULL CONSTRAINT PK_LegacyRoleMap PRIMARY KEY,
                roleValue VARCHAR(100) COLLATE Latin1_General_100_BIN2 NOT NULL CONSTRAINT UQ_LegacyRoleMap_RoleValue UNIQUE,
                mappedAt  DATETIME2    NOT NULL CONSTRAINT DF_LegacyRoleMap_MappedAt DEFAULT SYSUTCDATETIME()
            );

            IF OBJECT_ID(N'[{schema}].[MigrationIssue]') IS NULL
            CREATE TABLE [{schema}].[MigrationIssue] (
                IssueId      INT IDENTITY(1,1) NOT NULL CONSTRAINT PK_MigrationIssue PRIMARY KEY,
                RunId        UNIQUEIDENTIFIER NOT NULL,
                Severity     VARCHAR(10)      NOT NULL,
                Code         VARCHAR(50)      NOT NULL,
                LegacyUserId INT              NULL,
                Detail       NVARCHAR(1000)   NOT NULL
            );

            DECLARE @runtime sysname = N'kdyf_{schema}_runtime';
            IF DATABASE_PRINCIPAL_ID(@runtime) IS NOT NULL
                EXEC(N'GRANT SELECT ON [{schema}].[LegacyRoleMap] TO ' + @runtime + N';
                       DENY INSERT, UPDATE, DELETE ON [{schema}].[LegacyRoleMap] TO ' + @runtime + N';
                       DENY SELECT, INSERT, UPDATE, DELETE ON [{schema}].[MigrationIssue] TO ' + @runtime + N';');
            """;

        private static async Task<IReadOnlyDictionary<int, string>> MappedRolesAsync(DbConnection connection, string schema, CancellationToken cancellationToken)
        {
            var map = new Dictionary<int, string>();
            await using var command = connection.CreateCommand();
            command.CommandText = $"IF OBJECT_ID(N'[{schema}].[LegacyRoleMap]') IS NOT NULL SELECT RoleId, roleValue FROM [{schema}].[LegacyRoleMap]";
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
                map[reader.GetInt32(0)] = reader.GetString(1);
            return map;
        }

        /// <summary>The plan in temporary tables of this session: the reconciliation and the verification read them.</summary>
        private static async Task LoadDesiredAsync(SqlConnection connection, SqlTransaction transaction, LegacyImportPlan plan, CancellationToken cancellationToken)
        {
            await ExecuteAsync(connection, transaction, $"""
                CREATE TABLE #Role (RoleId INT NOT NULL PRIMARY KEY, roleValue VARCHAR(100) COLLATE {SchemaManifest.Bin2} NOT NULL, name NVARCHAR(200) COLLATE DATABASE_DEFAULT NOT NULL, description NVARCHAR(500) COLLATE DATABASE_DEFAULT NULL);
                CREATE TABLE #Grant (roleValue VARCHAR(100) COLLATE {SchemaManifest.Bin2} NOT NULL, PermissionCode VARCHAR(50) COLLATE {SchemaManifest.Bin2} NOT NULL);
                CREATE TABLE #Profile (objectId VARCHAR(50) COLLATE DATABASE_DEFAULT NOT NULL, legacyUserId INT NOT NULL, email NVARCHAR(256) COLLATE DATABASE_DEFAULT NOT NULL,
                    displayName NVARCHAR(200) COLLATE DATABASE_DEFAULT NULL, isActive BIT NOT NULL, createdAt DATETIME2 NOT NULL);
                CREATE TABLE #UserRole (objectId VARCHAR(50) COLLATE DATABASE_DEFAULT NOT NULL, roleValue VARCHAR(100) COLLATE {SchemaManifest.Bin2} NOT NULL);
                CREATE TABLE #Token (legacyId INT NOT NULL, tokenHash VARBINARY(32) NOT NULL, name NVARCHAR(100) COLLATE DATABASE_DEFAULT NOT NULL,
                    tokenPrefix NVARCHAR(12) COLLATE DATABASE_DEFAULT NULL, ownerObjectId NVARCHAR(50) COLLATE DATABASE_DEFAULT NOT NULL,
                    ownerLabel NVARCHAR(256) COLLATE DATABASE_DEFAULT NOT NULL, isActive BIT NOT NULL, expiresAt DATETIME2 NULL, createdAt DATETIME2 NOT NULL, lastUsedAt DATETIME2 NULL);
                CREATE TABLE #UserMap (UserId INT NOT NULL PRIMARY KEY, objectId VARCHAR(50) COLLATE DATABASE_DEFAULT NOT NULL);
                """, cancellationToken);

            foreach (var r in plan.Roles)
                await ExecuteAsync(connection, transaction, "INSERT INTO #Role VALUES (@id, @value, @name, @description)", cancellationToken,
                    ("@id", r.LegacyRoleId), ("@value", r.RoleValue), ("@name", r.Name), ("@description", r.Description));
            foreach (var g in plan.Grants)
                await ExecuteAsync(connection, transaction, "INSERT INTO #Grant VALUES (@value, @code)", cancellationToken, ("@value", g.RoleValue), ("@code", g.PermissionCode));
            foreach (var p in plan.Profiles)
                await ExecuteAsync(connection, transaction, "INSERT INTO #Profile VALUES (@oid, @id, @email, @name, @active, @created)", cancellationToken,
                    ("@oid", p.ObjectId), ("@id", p.LegacyUserId), ("@email", p.Email), ("@name", p.DisplayName), ("@active", p.IsActive), ("@created", p.CreatedAt));
            foreach (var u in plan.UserRoles)
                await ExecuteAsync(connection, transaction, "INSERT INTO #UserRole VALUES (@oid, @value)", cancellationToken, ("@oid", u.ObjectId), ("@value", u.RoleValue));
            foreach (var t in plan.Tokens)
                await ExecuteAsync(connection, transaction, "INSERT INTO #Token VALUES (@id, @hash, @name, @prefix, @owner, @label, @active, @expires, @created, @used)", cancellationToken,
                    ("@id", t.LegacyId), ("@hash", t.TokenHash), ("@name", t.Name), ("@prefix", t.TokenPrefix), ("@owner", t.OwnerObjectId), ("@label", t.OwnerLabel),
                    ("@active", t.IsActive), ("@expires", t.ExpiresAt), ("@created", t.CreatedAt), ("@used", t.LastUsedAt));
            foreach (var (userId, objectId) in plan.UserMap)
                await ExecuteAsync(connection, transaction, "INSERT INTO #UserMap VALUES (@id, @oid)", cancellationToken, ("@id", userId), ("@oid", objectId));
        }

        /// <summary>Steps 1–6: the target brought to the plan. Before the cutover the target holds only what the import wrote.</summary>
        private static async Task ReconcileAsync(
            SqlConnection connection, SqlTransaction transaction, string s, IReadOnlyList<PermissionDefinition> declared,
            Dictionary<string, (int, int, int)> changes, CancellationToken cancellationToken)
        {
            // 1. The catalog: what the host declares, as its synchronizer would write it (inserted, names updated, never deleted).
            var catalogInserted = 0;
            var catalogUpdated = 0;
            foreach (var permission in declared)
            {
                var affected = await ScalarAsync(connection, transaction, $"""
                    IF NOT EXISTS (SELECT 1 FROM [{s}].[Permission] WHERE PermissionCode = @code)
                    BEGIN INSERT INTO [{s}].[Permission] (PermissionCode, name, description) VALUES (@code, @name, @description); SELECT 1; END
                    ELSE IF EXISTS (SELECT 1 FROM [{s}].[Permission] WHERE PermissionCode = @code AND (ISNULL(name, N'') <> ISNULL(@name, N'') OR ISNULL(description, N'') <> ISNULL(@description, N'')))
                    BEGIN UPDATE [{s}].[Permission] SET name = @name, description = @description WHERE PermissionCode = @code; SELECT 2; END
                    ELSE SELECT 0;
                    """, cancellationToken, ("@code", permission.Code), ("@name", permission.Name), ("@description", permission.Description));
                if (affected == 1) catalogInserted++;
                if (affected == 2) catalogUpdated++;
            }
            changes["Permission"] = (catalogInserted, catalogUpdated, 0);

            // 2. Roles and the permanent map. A role copied once keeps its value; one gone from the legacy schema goes here too.
            var mapped = await CountAsync(connection, transaction, $"INSERT INTO [{s}].[LegacyRoleMap] (RoleId, roleValue) SELECT r.RoleId, r.roleValue FROM #Role r WHERE NOT EXISTS (SELECT 1 FROM [{s}].[LegacyRoleMap] m WHERE m.RoleId = r.RoleId)", cancellationToken);
            var userRolesDeleted = await CountAsync(connection, transaction, $"DELETE FROM [{s}].[UserRole]", cancellationToken);
            var rolesDeleted = await CountAsync(connection, transaction,
                $"DELETE t FROM [{s}].[Role] t WHERE t.roleValue IN (SELECT roleValue FROM [{s}].[LegacyRoleMap]) AND NOT EXISTS (SELECT 1 FROM #Role r WHERE r.roleValue = t.roleValue)", cancellationToken);
            var rolesUpdated = await CountAsync(connection, transaction,
                $"UPDATE t SET name = r.name, description = r.description FROM [{s}].[Role] t JOIN #Role r ON r.roleValue = t.roleValue WHERE t.name <> r.name OR ISNULL(t.description, N'') <> ISNULL(r.description, N'')", cancellationToken);
            var rolesInserted = await CountAsync(connection, transaction,
                $"INSERT INTO [{s}].[Role] (roleValue, name, description, createdAt) SELECT r.roleValue, r.name, r.description, SYSUTCDATETIME() FROM #Role r WHERE NOT EXISTS (SELECT 1 FROM [{s}].[Role] t WHERE t.roleValue = r.roleValue)", cancellationToken);
            changes["Role"] = (rolesInserted, rolesUpdated, rolesDeleted);
            changes["LegacyRoleMap"] = (mapped, 0, 0);

            // 3. What the roles grant, as the legacy roles granted it: never compacted, never expanded.
            var grantsDeleted = await CountAsync(connection, transaction,
                $"DELETE t FROM [{s}].[RolePermission] t WHERE t.roleValue IN (SELECT roleValue FROM [{s}].[LegacyRoleMap]) AND NOT EXISTS (SELECT 1 FROM #Grant g WHERE g.roleValue = t.roleValue AND g.PermissionCode = t.PermissionCode)", cancellationToken);
            var grantsInserted = await CountAsync(connection, transaction,
                $"INSERT INTO [{s}].[RolePermission] (roleValue, PermissionCode) SELECT g.roleValue, g.PermissionCode FROM #Grant g WHERE NOT EXISTS (SELECT 1 FROM [{s}].[RolePermission] t WHERE t.roleValue = g.roleValue AND t.PermissionCode = g.PermissionCode)", cancellationToken);
            changes["RolePermission"] = (grantsInserted, 0, grantsDeleted);

            // 4. The profiles of the legacy users, recomputed: an inactive user is a suspended person, with their roles.
            var profilesDeleted = await CountAsync(connection, transaction,
                $"DELETE t FROM [{s}].[UserProfile] t WHERE t.legacyUserId IS NOT NULL AND NOT EXISTS (SELECT 1 FROM #Profile p WHERE p.objectId = t.objectId)", cancellationToken);
            var profilesUpdated = await CountAsync(connection, transaction, $"""
                UPDATE t SET legacyUserId = p.legacyUserId, email = p.email, displayName = p.displayName, isActive = p.isActive
                FROM [{s}].[UserProfile] t JOIN #Profile p ON p.objectId = t.objectId
                WHERE ISNULL(t.legacyUserId, -1) <> p.legacyUserId OR ISNULL(t.email, N'') <> p.email OR ISNULL(t.displayName, N'') <> ISNULL(p.displayName, N'') OR t.isActive <> p.isActive
                """, cancellationToken);
            var profilesInserted = await CountAsync(connection, transaction,
                $"INSERT INTO [{s}].[UserProfile] (objectId, legacyUserId, email, displayName, isActive, createdAt) SELECT p.objectId, p.legacyUserId, p.email, p.displayName, p.isActive, p.createdAt FROM #Profile p WHERE NOT EXISTS (SELECT 1 FROM [{s}].[UserProfile] t WHERE t.objectId = p.objectId)", cancellationToken);
            changes["UserProfile"] = (profilesInserted, profilesUpdated, profilesDeleted);

            // 5. Who holds which role, recomputed from scratch.
            var userRolesInserted = await CountAsync(connection, transaction, $"INSERT INTO [{s}].[UserRole] (objectId, roleValue) SELECT objectId, roleValue FROM #UserRole", cancellationToken);
            changes["UserRole"] = (userRolesInserted, 0, userRolesDeleted);

            // 6. Tokens, by their hash: a token deleted in the legacy schema goes; the legacy id is kept where it is free.
            var tokensDeleted = await CountAsync(connection, transaction,
                $"DELETE t FROM [{s}].[PersonalAccessToken] t WHERE NOT EXISTS (SELECT 1 FROM #Token k WHERE k.tokenHash = t.tokenHash)", cancellationToken);
            var tokensUpdated = await CountAsync(connection, transaction, $"""
                UPDATE t SET name = k.name, tokenPrefix = k.tokenPrefix, ownerObjectId = k.ownerObjectId, ownerLabel = k.ownerLabel, isActive = k.isActive,
                             expiresAt = k.expiresAt, lastUsedAt = k.lastUsedAt
                FROM [{s}].[PersonalAccessToken] t JOIN #Token k ON k.tokenHash = t.tokenHash
                WHERE t.name <> k.name OR ISNULL(t.tokenPrefix, N'') <> ISNULL(k.tokenPrefix, N'') OR t.ownerObjectId <> k.ownerObjectId OR t.ownerLabel <> k.ownerLabel
                   OR t.isActive <> k.isActive OR ISNULL(t.expiresAt, '0001-01-01') <> ISNULL(k.expiresAt, '0001-01-01') OR ISNULL(t.lastUsedAt, '0001-01-01') <> ISNULL(k.lastUsedAt, '0001-01-01')
                """, cancellationToken);
            var tokensWithId = await ScalarAsync(connection, transaction, $"""
                DECLARE @n INT;
                SET IDENTITY_INSERT [{s}].[PersonalAccessToken] ON;
                INSERT INTO [{s}].[PersonalAccessToken] (PersonalAccessTokenId, name, tokenHash, tokenPrefix, ownerObjectId, ownerLabel, isActive, expiresAt, createdAt, lastUsedAt)
                SELECT k.legacyId, k.name, k.tokenHash, k.tokenPrefix, k.ownerObjectId, k.ownerLabel, k.isActive, k.expiresAt, k.createdAt, k.lastUsedAt FROM #Token k
                WHERE NOT EXISTS (SELECT 1 FROM [{s}].[PersonalAccessToken] t WHERE t.tokenHash = k.tokenHash)
                  AND NOT EXISTS (SELECT 1 FROM [{s}].[PersonalAccessToken] t WHERE t.PersonalAccessTokenId = k.legacyId);
                SET @n = @@ROWCOUNT;
                SET IDENTITY_INSERT [{s}].[PersonalAccessToken] OFF;
                SELECT @n;
                """, cancellationToken);
            var tokensNewId = await CountAsync(connection, transaction, $"""
                INSERT INTO [{s}].[PersonalAccessToken] (name, tokenHash, tokenPrefix, ownerObjectId, ownerLabel, isActive, expiresAt, createdAt, lastUsedAt)
                SELECT k.name, k.tokenHash, k.tokenPrefix, k.ownerObjectId, k.ownerLabel, k.isActive, k.expiresAt, k.createdAt, k.lastUsedAt FROM #Token k
                WHERE NOT EXISTS (SELECT 1 FROM [{s}].[PersonalAccessToken] t WHERE t.tokenHash = k.tokenHash)
                """, cancellationToken);
            changes["PersonalAccessToken"] = (tokensWithId + tokensNewId, tokensUpdated, tokensDeleted);
        }

        /// <summary>Every row that differs between the plan and the target, both ways. Empty when the copy is exact.</summary>
        private static async Task<IReadOnlyList<string>> DifferencesAsync(SqlConnection connection, SqlTransaction transaction, string s, CancellationToken cancellationToken)
        {
            var checks = new (string What, string Expected, string Actual)[]
            {
                ("Role", "SELECT roleValue, name, ISNULL(description, N'') AS description FROM #Role",
                    $"SELECT roleValue, name, ISNULL(description, N'') AS description FROM [{s}].[Role] WHERE roleValue IN (SELECT roleValue FROM [{s}].[LegacyRoleMap])"),
                ("LegacyRoleMap", "SELECT RoleId, roleValue FROM #Role", $"SELECT m.RoleId, m.roleValue FROM [{s}].[LegacyRoleMap] m WHERE m.RoleId IN (SELECT RoleId FROM #Role)"),
                ("RolePermission", "SELECT roleValue, PermissionCode FROM #Grant",
                    $"SELECT roleValue, PermissionCode FROM [{s}].[RolePermission] WHERE roleValue IN (SELECT roleValue FROM [{s}].[LegacyRoleMap])"),
                ("UserProfile", "SELECT objectId, legacyUserId, isActive FROM #Profile",
                    $"SELECT objectId, legacyUserId, isActive FROM [{s}].[UserProfile] WHERE legacyUserId IS NOT NULL"),
                ("UserRole", "SELECT objectId, roleValue FROM #UserRole", $"SELECT objectId, roleValue FROM [{s}].[UserRole]"),
                ("PersonalAccessToken", "SELECT tokenHash, ownerObjectId, isActive FROM #Token", $"SELECT tokenHash, ownerObjectId, isActive FROM [{s}].[PersonalAccessToken]"),
            };

            var differences = new List<string>();
            foreach (var (what, expected, actual) in checks)
            {
                var missing = await ScalarAsync(connection, transaction, $"SELECT COUNT(*) FROM ({expected} EXCEPT {actual}) d", cancellationToken);
                var extra = await ScalarAsync(connection, transaction, $"SELECT COUNT(*) FROM ({actual} EXCEPT {expected}) d", cancellationToken);
                if (missing + extra > 0)
                    differences.Add($"{what}: {missing} expected row(s) missing, {extra} unexpected.");
            }
            return differences;
        }

        private static async Task RecordIssuesAsync(
            SqlConnection connection, SqlTransaction transaction, string s, Guid runId, IEnumerable<ImportIssue> issues, CancellationToken cancellationToken)
        {
            await ExecuteAsync(connection, transaction, $"DELETE FROM [{s}].[MigrationIssue]", cancellationToken);
            foreach (var issue in issues)
                await ExecuteAsync(connection, transaction,
                    $"INSERT INTO [{s}].[MigrationIssue] (RunId, Severity, Code, LegacyUserId, Detail) VALUES (@run, @severity, @code, @user, @detail)", cancellationToken,
                    ("@run", runId), ("@severity", issue.Severity.ToString()), ("@code", issue.Code), ("@user", issue.LegacyUserId),
                    ("@detail", issue.Detail.Length > 1000 ? issue.Detail[..1000] : issue.Detail));
        }

        /// <summary>
        /// The audit log after the last id copied, in batches, each its own transaction: an interruption loses nothing and
        /// the next run resumes. Who acted and on whom are translated to the new keys; what cannot be stays legacy:{id}.
        /// The actor's e-mail and the target's label are never rewritten.
        /// </summary>
        private static async Task<int> CopyAuditAsync(SqlConnection connection, string legacy, string s, int batchSize, CancellationToken cancellationToken)
        {
            var copied = 0;
            while (true)
            {
                await using var transaction = (SqlTransaction)await connection.BeginTransactionAsync(cancellationToken);
                var batch = await ScalarAsync(connection, transaction, $"""
                    DECLARE @n INT;
                    DECLARE @last BIGINT = (SELECT ISNULL(MAX(AuditLogId), 0) FROM [{s}].[AuditLog]);
                    SET IDENTITY_INSERT [{s}].[AuditLog] ON;
                    INSERT INTO [{s}].[AuditLog] (AuditLogId, occurredAt, actorObjectId, actorEmail, action, targetType, targetId, targetLabel, details)
                    SELECT TOP ({batchSize}) a.AuditLogId, a.occurredAt,
                        CASE WHEN a.actorUserId IS NULL THEN NULL ELSE COALESCE(actor.objectId, CONCAT('legacy:', a.actorUserId)) END,
                        a.actorEmail, LEFT(a.action, 40), LEFT(a.targetType, 20),
                        CASE WHEN a.targetId IS NULL THEN NULL
                             WHEN a.targetType = 'user' THEN COALESCE(target.objectId, CONCAT('legacy:', a.targetId))
                             WHEN a.targetType = 'role' THEN COALESCE(role.roleValue, CONCAT('legacy:', a.targetId))
                             WHEN a.targetType = 'pat' THEN CONVERT(NVARCHAR(100), a.targetId)
                             ELSE CONCAT('legacy:', a.targetId) END,
                        a.targetLabel, a.details
                    FROM [{legacy}].[AuditLog] a
                    LEFT JOIN #UserMap actor ON actor.UserId = a.actorUserId
                    LEFT JOIN #UserMap target ON target.UserId = a.targetId AND a.targetType = 'user'
                    LEFT JOIN [{s}].[LegacyRoleMap] role ON role.RoleId = a.targetId AND a.targetType = 'role'
                    WHERE a.AuditLogId > @last
                    ORDER BY a.AuditLogId;
                    SET @n = @@ROWCOUNT;
                    SET IDENTITY_INSERT [{s}].[AuditLog] OFF;
                    SELECT @n;
                    """, cancellationToken);
                await transaction.CommitAsync(cancellationToken);
                copied += batch;
                if (batch < batchSize)
                    return copied;
            }
        }

        private static async Task<int> PendingAuditAsync(SqlConnection connection, string legacy, string s, CancellationToken cancellationToken) =>
            await ScalarAsync(connection, null,
                $"SELECT COUNT(*) FROM [{legacy}].[AuditLog] WHERE AuditLogId > (SELECT ISNULL(MAX(AuditLogId), 0) FROM [{s}].[AuditLog])", cancellationToken);

        private static async Task LogAsync(
            SqlConnection connection, string s, Guid runId, LegacyImportPlan plan, IReadOnlyDictionary<string, (int, int, int)> changes, int audit, CancellationToken cancellationToken)
        {
            var report = JsonSerializer.Serialize(new
            {
                changes = changes.ToDictionary(c => c.Key, c => new { inserted = c.Value.Item1, updated = c.Value.Item2, deleted = c.Value.Item3 }),
                audit,
                issues = plan.Issues.Select(i => i.ToString()),
            });
            await ExecuteAsync(connection, null, $"""
                INSERT INTO [{s}].[{SchemaHistory.LogTable}] (RunId, StartedAt, EndedAt, Machine, PackageVersion, Mode, Result, Report)
                VALUES (@run, SYSUTCDATETIME(), SYSUTCDATETIME(), @machine, @version, 'import', 'Succeeded', @report)
                """, cancellationToken, ("@run", runId), ("@machine", Environment.MachineName), ("@version", SchemaMigrator.PackageVersion), ("@report", report));
        }

        private static async Task LockAsync(SqlConnection connection, string schema, CancellationToken cancellationToken)
        {
            var result = await ScalarAsync(connection, null, """
                DECLARE @r INT; EXEC @r = sp_getapplock @Resource = @resource, @LockMode = 'Exclusive', @LockOwner = 'Session', @LockTimeout = 60000; SELECT @r;
                """, cancellationToken, ("@resource", $"kdyf.authorization.schema:{schema}"));
            if (result < 0)
                throw new TimeoutException($"Another migration or import of [{schema}] is running.");
        }

        private static async Task<int> CountAsync(DbConnection connection, DbTransaction? transaction, string sql, CancellationToken cancellationToken) =>
            await ScalarAsync(connection, transaction, sql + "; SELECT @@ROWCOUNT;", cancellationToken);

        private static async Task<int> ScalarAsync(
            DbConnection connection, DbTransaction? transaction, string sql, CancellationToken cancellationToken, params (string Name, object? Value)[] parameters)
        {
            await using var command = Command(connection, transaction, sql, parameters);
            return Convert.ToInt32(await command.ExecuteScalarAsync(cancellationToken));
        }

        private static async Task ExecuteAsync(
            DbConnection connection, DbTransaction? transaction, string sql, CancellationToken cancellationToken, params (string Name, object? Value)[] parameters)
        {
            await using var command = Command(connection, transaction, sql, parameters);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        private static DbCommand Command(DbConnection connection, DbTransaction? transaction, string sql, (string Name, object? Value)[] parameters)
        {
            var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = sql;
            command.CommandTimeout = 600;
            foreach (var (name, value) in parameters)
            {
                var parameter = command.CreateParameter();
                parameter.ParameterName = name;
                parameter.Value = value ?? DBNull.Value;
                command.Parameters.Add(parameter);
            }
            return command;
        }

        /// <summary>The report, for a person: counts per table and the issues, people by legacy id.</summary>
        public static string ToText(LegacyImportReport report)
        {
            var text = new StringBuilder();
            foreach (var (table, (inserted, updated, deleted)) in report.Changes)
                text.AppendLine($"  {table,-20} +{inserted} ~{updated} -{deleted}");
            if (report.Changes.Count > 0)
                text.AppendLine($"  {"AuditLog",-20} +{report.AuditCopied}{(report.Applied ? "" : " (pending)")}");
            foreach (var issue in report.Issues.OrderBy(i => i.Severity == IssueSeverity.Blocker ? 0 : i.Severity == IssueSeverity.Warning ? 1 : 2))
                text.AppendLine(issue.ToString());
            if (report.Invariant is { } invariant)
            {
                text.AppendLine($"  Tokens that validate: {invariant.TokensBefore} before, {invariant.TokensAfter} after. Administrators after: {invariant.AdministratorsAfter}.");
                foreach (var (user, codes) in invariant.Reductions)
                    text.AppendLine($"  user {user} loses: {string.Join(", ", codes)}");
            }
            text.AppendLine(report.HasBlockers ? "Refused: nothing was changed."
                : report.Applied ? "Imported." : "Dry run: nothing was changed. Run 'kdyf-auth import apply' to import.");
            return text.ToString();
        }
    }
}
