using System.Data.Common;
using System.Reflection;
using System.Text;
using System.Text.Json;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace kdyf.Authorization.Migrations.Schema
{
    /// <summary>
    /// Brings the schema of the authorization tables to the version the packages require, the way Umbraco does: detects
    /// what the database holds from its catalog, and applies, verifies and records each missing step. SQL Server only.
    /// </summary>
    /// <remarks>
    /// <para>One run at a time per schema (<c>sp_getapplock</c>); the history is read after taking the lock.</para>
    /// <para>Each step runs in its own transaction with its verification and its history row: the version is written
    /// only if the schema equals the manifest of that version. A failed step is recorded as failed and the next run
    /// resumes it. There is no automatic down.</para>
    /// <para>An existing database in the shape of version 1 is adopted (stamped), never rebuilt. The legacy kdyf.auth.*
    /// schema is never touched: it is imported into another schema.</para>
    /// </remarks>
    public sealed class SchemaMigrator
    {
        private readonly string _connectionString;
        private readonly SchemaMigrationOptions _options;
        private readonly ILogger _logger;
        private readonly IReadOnlyList<MigrationStep> _steps;

        public SchemaMigrator(string connectionString, SchemaMigrationOptions? options = null, ILogger? logger = null)
            : this(connectionString, options ?? new SchemaMigrationOptions(), logger, MigrationSteps.All)
        {
        }

        internal SchemaMigrator(string connectionString, SchemaMigrationOptions options, ILogger? logger, IReadOnlyList<MigrationStep> steps)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);
            options.Validate();
            _connectionString = connectionString;
            _options = options;
            _logger = logger ?? NullLogger.Instance;
            _steps = steps;
        }

        /// <summary>The version the packages require: the last step.</summary>
        public static int RequiredVersion => MigrationSteps.All[^1].Version;

        private int TargetVersion => _steps[^1].Version;

        private string Schema => _options.Schema;

        private string Role => _options.RuntimeRole;

        internal static string PackageVersion =>
            typeof(SchemaMigrator).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0]
            ?? typeof(SchemaMigrator).Assembly.GetName().Version?.ToString() ?? "unknown";

        /// <summary>What state the schema is in. Read-only.</summary>
        public async Task<SchemaDetection> DetectAsync(CancellationToken cancellationToken = default)
        {
            await using var connection = await OpenAsync(cancellationToken);
            return await SchemaDetector.DetectAsync(connection, null, Schema, Role, cancellationToken);
        }

        /// <summary>The dry run: what would be applied and what stands in the way. Writes nothing.</summary>
        public async Task<SchemaMigrationPlan> PlanAsync(CancellationToken cancellationToken = default)
        {
            await using var connection = await OpenAsync(cancellationToken);
            var detection = await SchemaDetector.DetectAsync(connection, null, Schema, Role, cancellationToken);
            return await PlanAsync(connection, detection, cancellationToken);
        }

        /// <summary>Applies the plan, step by step, each verified before it is recorded.</summary>
        public async Task<SchemaMigrationReport> ApplyAsync(CancellationToken cancellationToken = default)
        {
            var runId = Guid.NewGuid();
            await using var connection = await OpenAsync(cancellationToken);
            await AcquireLockAsync(connection, cancellationToken);
            try
            {
                var detection = await SchemaDetector.DetectAsync(connection, null, Schema, Role, cancellationToken);
                var plan = await PlanAsync(connection, detection, cancellationToken);

                if (plan.HasBlockers)
                {
                    foreach (var issue in plan.Issues.Where(i => i.Severity == IssueSeverity.Blocker))
                        _logger.LogError("Schema {Schema}: {Issue}", Schema, issue);
                    return new SchemaMigrationReport(runId, SchemaRunResult.Refused, plan, Array.Empty<PlannedAction>(), detection.Version, null);
                }

                if (plan.UpToDate)
                {
                    _logger.LogInformation("Schema {Schema}: at version {Version}, nothing to do.", Schema, detection.Version);
                    return new SchemaMigrationReport(runId, SchemaRunResult.UpToDate, plan, Array.Empty<PlannedAction>(), detection.Version, null);
                }

                var done = new List<PlannedAction>();
                if (plan.Actions.Any(a => a.Kind == PlannedActionKind.CreateHistory))
                {
                    await ExecuteAsync(connection, null, SchemaHistory.BootstrapSql(Schema), cancellationToken);
                    done.Add(plan.Actions.First(a => a.Kind == PlannedActionKind.CreateHistory));
                }

                await StartLogAsync(connection, runId, "apply", cancellationToken);

                var result = SchemaRunResult.Succeeded;
                string? error = null;
                try
                {
                    foreach (var action in plan.Actions.Where(a => a.Kind != PlannedActionKind.CreateHistory))
                    {
                        await RunAsync(connection, runId, action, cancellationToken);
                        done.Add(action);
                        _logger.LogInformation("Schema {Schema}: {Action}", Schema, action);
                    }
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    result = SchemaRunResult.Failed;
                    error = ex.Message;
                    _logger.LogError(ex, "Schema {Schema}: the run failed. The step is recorded as failed; the next run resumes it.", Schema);
                }

                var after = await SchemaDetector.DetectAsync(connection, null, Schema, Role, cancellationToken);
                var report = new SchemaMigrationReport(runId, result, plan, done, after.Version, error);
                await EndLogAsync(connection, report, cancellationToken);
                return report;
            }
            finally
            {
                await ReleaseLockAsync(connection);
            }
        }

        /// <summary>
        /// The SQL a DBA runs instead of <see cref="ApplyAsync"/>: the same steps and history rows, computed now. It cannot
        /// verify itself: run <see cref="VerifyAsync"/> afterwards, always.
        /// </summary>
        public async Task<string> ScriptAsync(CancellationToken cancellationToken = default)
        {
            await using var connection = await OpenAsync(cancellationToken);
            var detection = await SchemaDetector.DetectAsync(connection, null, Schema, Role, cancellationToken);
            var plan = await PlanAsync(connection, detection, cancellationToken);

            // The backup is the job of whoever runs the script.
            var blockers = plan.Issues.Where(i => i.Severity == IssueSeverity.Blocker && i.Code != "backup").ToList();
            if (blockers.Count > 0)
                throw new InvalidOperationException($"Schema {Schema}: no script while these stand: " + string.Join(" ", blockers));

            var lockResource = LockResource;
            var sql = new StringBuilder();
            sql.AppendLine($"-- kdyf.Authorization {PackageVersion}: schema [{Schema}], {detection.Summary}");
            sql.AppendLine($"-- From version {detection.Version?.ToString() ?? "(none)"} to {TargetVersion}. Generated {DateTime.UtcNow:O}.");
            sql.AppendLine("-- Take a backup first. Afterwards run the verification (kdyf-auth verify): this script cannot verify itself.");
            sql.AppendLine("SET XACT_ABORT ON;");
            sql.AppendLine("DECLARE @lock INT;");
            sql.AppendLine($"EXEC @lock = sp_getapplock @Resource = N'{lockResource}', @LockMode = 'Exclusive', @LockOwner = 'Session', @LockTimeout = {(int)_options.LockTimeout.TotalMilliseconds};");
            sql.AppendLine("IF @lock < 0 BEGIN RAISERROR(N'Another migration of this schema is running.', 16, 1); SET NOEXEC ON; END");
            sql.AppendLine("GO");

            foreach (var action in plan.Actions)
            {
                sql.AppendLine($"-- {action}");
                switch (action.Kind)
                {
                    case PlannedActionKind.CreateHistory:
                        sql.AppendLine(SchemaHistory.BootstrapSql(Schema));
                        break;
                    case PlannedActionKind.RepairCollation:
                        sql.AppendLine("BEGIN TRANSACTION;");
                        sql.Append(CollationRepair.Sql(detection.Snapshot));
                        sql.AppendLine("COMMIT;");
                        break;
                    case PlannedActionKind.Apply:
                    case PlannedActionKind.Adopt:
                        var step = Step(action.Version!.Value);
                        sql.AppendLine("BEGIN TRANSACTION;");
                        if (action.Kind == PlannedActionKind.Apply)
                            sql.AppendLine(step.Sql(Schema, Role));
                        var origin = action.Kind == PlannedActionKind.Adopt ? "adopted" : "script";
                        sql.AppendLine($"DELETE FROM [{Schema}].[{SchemaHistory.VersionTable}] WHERE Version = {step.Version} AND Status = '{SchemaHistory.Failed}';");
                        sql.AppendLine($"INSERT INTO [{Schema}].[{SchemaHistory.VersionTable}] (Version, StepId, Checksum, Status, Origin, PackageVersion, RunId) "
                                       + $"VALUES ({step.Version}, '{step.Id}', '{step.Checksum}', '{SchemaHistory.Applied}', '{origin}', '{PackageVersion}', NEWID());");
                        sql.AppendLine("COMMIT;");
                        break;
                    case PlannedActionKind.AddAppUser:
                        sql.AppendLine(AddMemberSql());
                        break;
                }
                sql.AppendLine("GO");
            }

            sql.AppendLine($"EXEC sp_releaseapplock @Resource = N'{lockResource}', @LockOwner = 'Session';");
            sql.AppendLine("GO");
            return sql.ToString();
        }

        /// <summary>
        /// Whether the schema is at the required version and equal to its manifest — tables, keys, collations, indexes and
        /// the runtime role's permissions — with no failed step and every checksum matching the code. Read-only.
        /// </summary>
        public async Task<SchemaVerification> VerifyAsync(CancellationToken cancellationToken = default)
        {
            await using var connection = await OpenAsync(cancellationToken);
            var detection = await SchemaDetector.DetectAsync(connection, null, Schema, Role, cancellationToken);
            var issues = new List<SchemaIssue>();

            if (detection.State != SchemaState.Versioned)
                issues.Add(new(IssueSeverity.Blocker, "not-versioned", detection.Summary));
            else
            {
                var version = detection.Version ?? -1;
                if (version < TargetVersion)
                    issues.Add(new(IssueSeverity.Blocker, "behind", $"at version {version}, the packages require {TargetVersion}."));
                if (detection.FailedStep is { } failed)
                    issues.Add(new(IssueSeverity.Blocker, "failed-step", $"step {failed.StepId} failed: {failed.Error}"));
                foreach (var difference in detection.Differences.Where(d => d.Kind != DifferenceKind.Note))
                    issues.Add(new(IssueSeverity.Blocker, "drift", difference.ToString()));
                issues.AddRange(ChecksumIssues(detection, IssueSeverity.Blocker));
                if (_options.AppUser is not null && !await IsRoleMemberAsync(connection, cancellationToken))
                    issues.Add(new(IssueSeverity.Blocker, "app-user", $"{_options.AppUser} is not a member of {Role}."));
            }

            return new SchemaVerification(detection, issues, TargetVersion);
        }

        /// <summary>
        /// Records that the application runs on this schema for good (<c>CutoverCompleted</c>): from then on the legacy
        /// import refuses to run against it. Only on a schema that passes <see cref="VerifyAsync"/>.
        /// </summary>
        public async Task MarkCutoverAsync(CancellationToken cancellationToken = default)
        {
            var verification = await VerifyAsync(cancellationToken);
            if (!verification.Succeeded)
                throw new InvalidOperationException($"Schema {Schema}: no cutover on a schema that does not verify: " + string.Join(" ", verification.Issues));
            if (verification.Detection.CutoverCompleted)
                return;

            var runId = Guid.NewGuid();
            await using var connection = await OpenAsync(cancellationToken);
            await AcquireLockAsync(connection, cancellationToken);
            try
            {
                await StartLogAsync(connection, runId, "cutover", cancellationToken);
                await ExecuteAsync(connection, null,
                    $"IF NOT EXISTS (SELECT 1 FROM [{Schema}].[{SchemaHistory.MarkerTable}] WHERE Name = @name) "
                    + $"INSERT INTO [{Schema}].[{SchemaHistory.MarkerTable}] (Name, RunId) VALUES (@name, @runId);",
                    cancellationToken, ("@name", SchemaHistory.CutoverCompleted), ("@runId", runId));
                await ExecuteAsync(connection, null,
                    $"UPDATE [{Schema}].[{SchemaHistory.LogTable}] SET EndedAt = SYSUTCDATETIME(), Result = 'Succeeded' WHERE RunId = @runId;",
                    cancellationToken, ("@runId", runId));
                _logger.LogInformation("Schema {Schema}: cutover completed.", Schema);
            }
            finally
            {
                await ReleaseLockAsync(connection);
            }
        }

        private async Task<SchemaMigrationPlan> PlanAsync(DbConnection connection, SchemaDetection detection, CancellationToken cancellationToken)
        {
            var issues = new List<SchemaIssue>();
            var actions = new List<PlannedAction>();

            switch (detection.State)
            {
                case SchemaState.Legacy:
                case SchemaState.Unsupported:
                case SchemaState.Unknown:
                    issues.Add(new(IssueSeverity.Blocker, detection.State.ToString().ToLowerInvariant(), detection.Summary));
                    issues.AddRange(detection.Differences.Where(d => d.Kind != DifferenceKind.Note)
                        .Select(d => new SchemaIssue(IssueSeverity.Blocker, "difference", d.ToString())));
                    return new SchemaMigrationPlan(detection, actions, issues, TargetVersion);

                case SchemaState.Versioned:
                    foreach (var difference in detection.Differences.Where(d => d.Kind != DifferenceKind.Note))
                        issues.Add(new(IssueSeverity.Blocker, "drift", $"the schema differs from version {detection.Version}: {difference}"));
                    issues.AddRange(ChecksumIssues(detection, IssueSeverity.Warning));
                    if (detection.Version > TargetVersion)
                        issues.Add(new(IssueSeverity.Warning, "ahead", $"at version {detection.Version}, newer than these packages ({TargetVersion}): nothing is applied."));
                    if (detection.FailedStep is { } failed)
                        issues.Add(new(IssueSeverity.Warning, "resume", $"step {failed.StepId} failed on {failed.AppliedAt:u} ({failed.Error}); it is applied again."));
                    break;

                case SchemaState.NeedsCollationRepair:
                    if (!_options.Approvals.Contains(SchemaApprovals.CollationRepair))
                        issues.Add(new(IssueSeverity.Blocker, "collation-repair-approval",
                            $"the key columns are not {SchemaManifest.Bin2}; repairing them rebuilds the primary and foreign keys and needs the approval '{SchemaApprovals.CollationRepair}'."));
                    issues.AddRange(CollationRepair.StructuralIssues(detection.Snapshot));
                    await foreach (var (foreignKey, count) in QueryCountsAsync(connection, CollationRepair.MismatchesSql(Schema), cancellationToken))
                        if (count > 0)
                            issues.Add(new(IssueSeverity.Blocker, "collation-case-mismatch",
                                $"{count} row(s) match their {foreignKey} reference only ignoring case; fix their capitalisation by hand before the repair."));
                    break;
            }

            if (detection.History.Count == 0)
                actions.Add(new(PlannedActionKind.CreateHistory, null, $"schema [{Schema}] and its history tables"));
            if (detection.State == SchemaState.NeedsCollationRepair)
                actions.Add(new(PlannedActionKind.RepairCollation, null, $"{SchemaManifest.Bin2} on the key columns"));

            var current = detection.Version ?? -1;
            if (current <= TargetVersion)
                foreach (var step in _steps.Where(s => s.Version > current))
                {
                    // The tables are there already (mtcm, or an adoption that failed half-way): stamped, not created.
                    var exists = SchemaManifest.Tables(step.Version).Any(t => detection.Snapshot.Table(t.Name) is not null);
                    actions.Add(step.Adoptable && exists
                        ? new(PlannedActionKind.Adopt, step.Version, $"{step.Id}: the tables exist; stamped after verifying their shape")
                        : new(PlannedActionKind.Apply, step.Version, $"{step.Id}: {step.Description}"));
                }

            if (_options.AppUser is { } appUser)
            {
                var (exists, privileged) = await AppUserAsync(connection, appUser, cancellationToken);
                if (!exists)
                    issues.Add(new(IssueSeverity.Blocker, "app-user-missing", $"the database user {appUser} does not exist."));
                else
                {
                    if (privileged)
                        issues.Add(_options.Approvals.Contains(SchemaApprovals.PrivilegedAppUser)
                            ? new(IssueSeverity.Warning, "privileged-app-user", $"{appUser} is db_owner or db_datawriter: the denies of {Role} do not bind it (approved).")
                            : new(IssueSeverity.Blocker, "privileged-app-user",
                                $"{appUser} is db_owner or db_datawriter: the denies of {Role} would not bind it, and the application could rewrite the audit log "
                                + $"and the history. Remove those roles from it, or approve '{SchemaApprovals.PrivilegedAppUser}'."));
                    if (!await IsRoleMemberAsync(connection, cancellationToken))
                        actions.Add(new(PlannedActionKind.AddAppUser, null, $"{appUser} into {Role}"));
                }
            }

            var changesData = actions.Any(a => a.Kind is PlannedActionKind.Apply or PlannedActionKind.RepairCollation);
            // Nothing to lose without rows: a backup is required only when the tables hold data.
            if (changesData && !_options.BackupConfirmed && await HasRowsAsync(connection, cancellationToken)
                && !RecentEnough(await LastBackupAsync(connection, cancellationToken)))
                issues.Add(new(IssueSeverity.Blocker, "backup", await IsAzureSqlDatabaseAsync(connection, cancellationToken)
                    ? "Azure SQL Database keeps point-in-time backups, which msdb does not show: note the time to restore to, check the "
                      + "retention, and confirm it (--backup-confirmed)."
                    : $"no backup of this database in the last {_options.BackupMaxAge.TotalHours:0} hours in msdb. Take one, and confirm it (--backup-confirmed)."));

            return new SchemaMigrationPlan(detection, actions, issues, TargetVersion);
        }

        private async Task<bool> HasRowsAsync(DbConnection connection, CancellationToken cancellationToken) =>
            await ScalarAsync(connection, """
                SELECT COUNT(*) FROM sys.partitions p
                JOIN sys.tables t ON t.object_id = p.object_id
                WHERE SCHEMA_NAME(t.schema_id) = @schema AND t.name IN ('Permission', 'Role', 'RolePermission', 'UserRole', 'PersonalAccessToken', 'AuditLog') AND p.index_id IN (0, 1) AND p.rows > 0
                """, cancellationToken, ("@schema", Schema)) is int tables && tables > 0;

        private static async Task<bool> IsAzureSqlDatabaseAsync(DbConnection connection, CancellationToken cancellationToken) =>
            await ScalarAsync(connection, "SELECT CAST(SERVERPROPERTY('EngineEdition') AS INT)", cancellationToken) is int edition && edition == 5;

        private bool RecentEnough(DateTime? backup) => backup is { } at && DateTime.UtcNow - at <= _options.BackupMaxAge;

        private async Task RunAsync(DbConnection connection, Guid runId, PlannedAction action, CancellationToken cancellationToken)
        {
            switch (action.Kind)
            {
                case PlannedActionKind.RepairCollation:
                {
                    await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
                    var before = await SchemaSnapshot.ReadAsync(connection, transaction, Schema, Role, cancellationToken);
                    await ExecuteAsync(connection, transaction, CollationRepair.Sql(before), cancellationToken);
                    var after = await SchemaSnapshot.ReadAsync(connection, transaction, Schema, Role, cancellationToken);
                    var left = SchemaComparer.CompareTables(after, 1).Where(d => d.Kind != DifferenceKind.Note).ToList();
                    if (left.Count > 0)
                        throw new InvalidOperationException("The collation repair did not give the shape of version 1: " + string.Join(" ", left));
                    await transaction.CommitAsync(cancellationToken);
                    return;
                }

                case PlannedActionKind.Apply:
                case PlannedActionKind.Adopt:
                {
                    var step = Step(action.Version!.Value);
                    try
                    {
                        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
                        if (action.Kind == PlannedActionKind.Apply)
                            await ExecuteAsync(connection, transaction, step.Sql(Schema, Role), cancellationToken);

                        // The version is written only if the schema now equals the manifest of that version.
                        var snapshot = await SchemaSnapshot.ReadAsync(connection, transaction, Schema, Role, cancellationToken);
                        var differences = SchemaComparer.CompareTables(snapshot, step.Version)
                            .Concat(SchemaComparer.ComparePermissions(snapshot, step.Version))
                            .Where(d => d.Kind != DifferenceKind.Note)
                            .ToList();
                        if (differences.Count > 0)
                            throw new InvalidOperationException(
                                $"After {step.Id} the schema is not version {step.Version}: " + string.Join(" ", differences));

                        await RecordAsync(connection, transaction, step, SchemaHistory.Applied, action.Kind == PlannedActionKind.Adopt ? "adopted" : "installed", runId, null, cancellationToken);
                        await transaction.CommitAsync(cancellationToken);
                    }
                    catch (Exception ex) when (ex is not OperationCanceledException)
                    {
                        await RecordAsync(connection, null, step, SchemaHistory.Failed, action.Kind == PlannedActionKind.Adopt ? "adopted" : "installed", runId, ex.Message, cancellationToken);
                        throw;
                    }
                    return;
                }

                case PlannedActionKind.AddAppUser:
                    await ExecuteAsync(connection, null, AddMemberSql(), cancellationToken);
                    return;
            }
        }

        private MigrationStep Step(int version) => _steps.Single(s => s.Version == version);

        private IEnumerable<SchemaIssue> ChecksumIssues(SchemaDetection detection, IssueSeverity severity)
        {
            foreach (var row in detection.History.Where(h => h.Status == SchemaHistory.Applied))
            {
                var step = _steps.FirstOrDefault(s => s.Version == row.Version);
                if (step is null)
                    continue;
                if (!string.Equals(step.Id, row.StepId, StringComparison.Ordinal) || !string.Equals(step.Checksum, row.Checksum, StringComparison.OrdinalIgnoreCase))
                    yield return new SchemaIssue(severity, "checksum",
                        $"version {row.Version} was applied as {row.StepId} ({row.Checksum[..12]}…), and the code now has {step.Id} ({step.Checksum[..12]}…).");
            }
        }

        private string AddMemberSql() =>
            $"IF IS_ROLEMEMBER(N'{Role}', N'{_options.AppUser}') = 0 ALTER ROLE [{Role}] ADD MEMBER [{_options.AppUser}];";

        private async Task<bool> IsRoleMemberAsync(DbConnection connection, CancellationToken cancellationToken) =>
            await ScalarAsync(connection, "SELECT ISNULL(IS_ROLEMEMBER(@role, @user), 0)", cancellationToken, ("@role", Role), ("@user", _options.AppUser!)) is int member && member == 1;

        private static async Task<(bool Exists, bool Privileged)> AppUserAsync(DbConnection connection, string user, CancellationToken cancellationToken)
        {
            var exists = await ScalarAsync(connection, "SELECT COUNT(*) FROM sys.database_principals WHERE name = @user", cancellationToken, ("@user", user)) is int count && count > 0;
            if (!exists)
                return (false, false);
            var privileged = await ScalarAsync(connection,
                "SELECT CASE WHEN ISNULL(IS_ROLEMEMBER('db_owner', @user), 0) = 1 OR ISNULL(IS_ROLEMEMBER('db_datawriter', @user), 0) = 1 THEN 1 ELSE 0 END",
                cancellationToken, ("@user", user)) is int p && p == 1;
            return (true, privileged);
        }

        /// <summary>The last full or differential backup in msdb; <c>null</c> when there is none or msdb cannot be read.</summary>
        private async Task<DateTime?> LastBackupAsync(DbConnection connection, CancellationToken cancellationToken)
        {
            try
            {
                return await ScalarAsync(connection,
                    "SELECT MAX(backup_finish_date) FROM msdb.dbo.backupset WHERE database_name = DB_NAME() AND type IN ('D', 'I')",
                    cancellationToken) is DateTime at ? at.ToUniversalTime() : null;
            }
            catch (DbException ex)
            {
                _logger.LogDebug(ex, "msdb.dbo.backupset is not readable.");
                return null;
            }
        }

        private string LockResource => $"kdyf.authorization.schema:{Schema}";

        private async Task AcquireLockAsync(DbConnection connection, CancellationToken cancellationToken)
        {
            await using var command = connection.CreateCommand();
            command.CommandText = """
                DECLARE @result INT;
                EXEC @result = sp_getapplock @Resource = @resource, @LockMode = 'Exclusive', @LockOwner = 'Session', @LockTimeout = @timeout;
                SELECT @result;
                """;
            command.CommandTimeout = (int)_options.LockTimeout.TotalSeconds + 30;
            AddParameters(command, ("@resource", LockResource), ("@timeout", (int)_options.LockTimeout.TotalMilliseconds));
            var result = Convert.ToInt32(await command.ExecuteScalarAsync(cancellationToken));
            if (result < 0)
                throw new TimeoutException($"Schema {Schema}: another migration of this schema is running (sp_getapplock returned {result}).");
        }

        private async Task ReleaseLockAsync(DbConnection connection)
        {
            try
            {
                await ExecuteAsync(connection, null, "EXEC sp_releaseapplock @Resource = @resource, @LockOwner = 'Session';", CancellationToken.None, ("@resource", LockResource));
            }
            catch (DbException ex)
            {
                // Closing the connection releases it anyway.
                _logger.LogDebug(ex, "sp_releaseapplock failed.");
            }
        }

        private async Task StartLogAsync(DbConnection connection, Guid runId, string mode, CancellationToken cancellationToken) =>
            await ExecuteAsync(connection, null,
                $"INSERT INTO [{Schema}].[{SchemaHistory.LogTable}] (RunId, StartedAt, Machine, PackageVersion, HostVersion, Mode) "
                + "VALUES (@runId, SYSUTCDATETIME(), @machine, @packageVersion, @hostVersion, @mode);",
                cancellationToken,
                ("@runId", runId), ("@machine", Environment.MachineName), ("@packageVersion", PackageVersion),
                ("@hostVersion", (object?)_options.HostVersion ?? DBNull.Value), ("@mode", mode));

        private async Task EndLogAsync(DbConnection connection, SchemaMigrationReport report, CancellationToken cancellationToken)
        {
            var json = JsonSerializer.Serialize(new
            {
                state = report.Plan.Detection.State.ToString(),
                summary = report.Plan.Detection.Summary,
                fromVersion = report.Plan.Detection.Version,
                toVersion = report.Version,
                planned = report.Plan.Actions.Select(a => a.ToString()),
                done = report.Done.Select(a => a.ToString()),
                issues = report.Plan.Issues.Select(i => i.ToString()),
                differences = report.Plan.Detection.Differences.Select(d => d.ToString()),
                error = report.Error,
            });
            await ExecuteAsync(connection, null,
                $"UPDATE [{Schema}].[{SchemaHistory.LogTable}] SET EndedAt = SYSUTCDATETIME(), Result = @result, Report = @report WHERE RunId = @runId;",
                cancellationToken, ("@result", report.Result.ToString()), ("@report", json), ("@runId", report.RunId));
        }

        private async Task RecordAsync(
            DbConnection connection, DbTransaction? transaction, MigrationStep step, string status, string origin, Guid runId, string? error,
            CancellationToken cancellationToken) =>
            await ExecuteAsync(connection, transaction, SchemaHistory.RecordSql(Schema), cancellationToken,
                ("@version", step.Version), ("@stepId", step.Id), ("@checksum", step.Checksum), ("@status", status), ("@origin", origin),
                ("@packageVersion", PackageVersion), ("@runId", runId), ("@error", (object?)error ?? DBNull.Value));

        private async Task<DbConnection> OpenAsync(CancellationToken cancellationToken)
        {
            var connection = new SqlConnection(_connectionString);
            await connection.OpenAsync(cancellationToken);
            return connection;
        }

        private static async Task ExecuteAsync(
            DbConnection connection, DbTransaction? transaction, string sql, CancellationToken cancellationToken, params (string Name, object Value)[] parameters)
        {
            await using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = sql;
            command.CommandTimeout = 600;
            AddParameters(command, parameters);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        private static async Task<object?> ScalarAsync(
            DbConnection connection, string sql, CancellationToken cancellationToken, params (string Name, object Value)[] parameters)
        {
            await using var command = connection.CreateCommand();
            command.CommandText = sql;
            AddParameters(command, parameters);
            var value = await command.ExecuteScalarAsync(cancellationToken);
            return value is DBNull ? null : value;
        }

        private static async IAsyncEnumerable<(string Name, int Count)> QueryCountsAsync(
            DbConnection connection, string sql, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
        {
            await using var command = connection.CreateCommand();
            command.CommandText = sql;
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
                yield return (reader.GetString(0), reader.GetInt32(1));
        }

        private static void AddParameters(DbCommand command, params (string Name, object Value)[] parameters)
        {
            foreach (var (name, value) in parameters)
            {
                var parameter = command.CreateParameter();
                parameter.ParameterName = name;
                parameter.Value = value;
                command.Parameters.Add(parameter);
            }
        }
    }
}
