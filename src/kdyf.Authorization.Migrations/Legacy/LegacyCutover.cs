using System.Data.Common;
using System.Security.Cryptography;
using System.Text;
using kdyf.Authorization.Migrations.Schema;
using Microsoft.Data.SqlClient;

namespace kdyf.Authorization.Migrations.Legacy
{
    /// <summary>One check of the go/no-go, with whether it passed.</summary>
    public sealed record GoNoGoCheck(string Name, bool Passed, string Detail)
    {
        public override string ToString() => $"[{(Passed ? "x" : " ")}] {Name}: {Detail}";
    }

    /// <summary>What <c>rollback-sync</c> takes back to the legacy schema: revocations only.</summary>
    public sealed record RollbackChange(string Table, string What, int Count);

    /// <summary>
    /// The cutover of a legacy import and what surrounds it: accepting the reductions, the go/no-go, the cutover with its
    /// rollback window, taking the revocations made since back to the legacy schema (<c>rollback-sync</c>), and the
    /// contraction of the legacy schema once the window is closed.
    /// </summary>
    public static class LegacyCutover
    {
        private const string ReductionsMarker = "ReductionsAccepted:";
        private const string WindowMarker = "RollbackWindowHours:";

        /// <summary>The fingerprint of the reductions: an acceptance holds for this exact list, and no other.</summary>
        public static string ReductionsFingerprint(InvariantReport invariant) =>
            Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join("\n",
                invariant.Reductions.OrderBy(r => r.Key).Select(r => $"{r.Key}:{string.Join(",", r.Value)}")))))[..16].ToLowerInvariant();

        /// <summary>Records that <paramref name="approver"/> accepted the reductions of this dry run.</summary>
        public static async Task<string> AcceptReductionsAsync(string connectionString, string target, InvariantReport invariant, string approver, CancellationToken cancellationToken)
        {
            var fingerprint = ReductionsFingerprint(invariant);
            await using var connection = new SqlConnection(connectionString);
            await connection.OpenAsync(cancellationToken);
            await ExecuteAsync(connection, null, $"""
                DELETE FROM [{target}].[{SchemaHistory.MarkerTable}] WHERE Name LIKE '{ReductionsMarker}%';
                INSERT INTO [{target}].[{SchemaHistory.MarkerTable}] (Name, RunId) VALUES (@name, NEWID());
                INSERT INTO [{target}].[{SchemaHistory.LogTable}] (RunId, StartedAt, EndedAt, Machine, PackageVersion, Mode, Result, Report)
                VALUES (NEWID(), SYSUTCDATETIME(), SYSUTCDATETIME(), @machine, @version, 'reductions', 'Accepted', @report);
                """, cancellationToken,
                ("@name", ReductionsMarker + fingerprint), ("@machine", Environment.MachineName), ("@version", SchemaMigrator.PackageVersion),
                ("@report", $"{{\"acceptedBy\":\"{approver.Replace("\"", "'")}\",\"fingerprint\":\"{fingerprint}\",\"users\":{invariant.Reductions.Count}}}"));
            return fingerprint;
        }

        /// <summary>
        /// The automatic part of the go/no-go, from a dry run of the import taken now. The rest of the list (backup, rehearsed
        /// rollback, monitoring, owners) is a person's.
        /// </summary>
        public static async Task<IReadOnlyList<GoNoGoCheck>> CheckAsync(string connectionString, string target, LegacyImportReport dryRun, CancellationToken cancellationToken)
        {
            var checks = new List<GoNoGoCheck>
            {
                new("no blockers", !dryRun.HasBlockers,
                    dryRun.HasBlockers ? string.Join(" ", dryRun.Issues.Where(i => i.Severity == IssueSeverity.Blocker).Select(i => i.Code).Distinct()) : "the dry run has none"),
            };

            var pending = dryRun.Changes.Where(c => c.Key != "UserRole" && c.Value != (0, 0, 0)).Select(c => c.Key).ToList();
            var userRoles = dryRun.Changes.GetValueOrDefault("UserRole");
            if (userRoles.Inserted != userRoles.Deleted)
                pending.Add("UserRole");
            checks.Add(new("in sync with the legacy schema", dryRun.Changes.Count > 0 && pending.Count == 0,
                pending.Count == 0 ? "the last apply copied everything" : $"run 'import apply' again: {string.Join(", ", pending)} changed"));
            checks.Add(new("audit log copied", dryRun.AuditCopied == 0, dryRun.AuditCopied == 0 ? "nothing pending" : $"{dryRun.AuditCopied} entries pending"));

            await using var connection = new SqlConnection(connectionString);
            await connection.OpenAsync(cancellationToken);
            var markers = await SchemaHistory.ReadMarkersAsync(connection, null, target, cancellationToken);
            var fingerprint = dryRun.Invariant is null ? null : ReductionsFingerprint(dryRun.Invariant);
            var accepted = fingerprint is not null && markers.Contains(ReductionsMarker + fingerprint);
            checks.Add(new("reductions accepted", accepted || dryRun.Invariant?.Reductions.Count == 0,
                dryRun.Invariant?.Reductions.Count == 0 ? "nobody loses anything" : accepted ? "accepted, this exact list" : "run 'import reductions-accept --approver <name>'"));

            var identities = await ScalarAsync(connection, null, $"""
                SELECT CASE WHEN ISNULL(IDENT_CURRENT(N'[{target}].[PersonalAccessToken]'), 0) >= ISNULL((SELECT MAX(PersonalAccessTokenId) FROM [{target}].[PersonalAccessToken]), 0)
                             AND ISNULL(IDENT_CURRENT(N'[{target}].[AuditLog]'), 0) >= ISNULL((SELECT MAX(AuditLogId) FROM [{target}].[AuditLog]), 0) THEN 1 ELSE 0 END
                """, cancellationToken);
            checks.Add(new("identities ahead of the ids", identities == 1, identities == 1 ? "IDENT_CURRENT ≥ MAX(id)" : "reseed the tokens and the audit log"));
            return checks;
        }

        /// <summary>Records the cutover and its rollback window. After it, the import never runs on the target again.</summary>
        public static async Task CutoverAsync(string connectionString, string target, string approver, TimeSpan window, CancellationToken cancellationToken)
        {
            await new SchemaMigrator(connectionString, new SchemaMigrationOptions { Schema = target }).MarkCutoverAsync(cancellationToken);
            await using var connection = new SqlConnection(connectionString);
            await connection.OpenAsync(cancellationToken);
            await ExecuteAsync(connection, null, $"""
                DELETE FROM [{target}].[{SchemaHistory.MarkerTable}] WHERE Name LIKE '{WindowMarker}%';
                INSERT INTO [{target}].[{SchemaHistory.MarkerTable}] (Name, RunId) VALUES (@window, NEWID());
                INSERT INTO [{target}].[{SchemaHistory.LogTable}] (RunId, StartedAt, EndedAt, Machine, PackageVersion, Mode, Result, Report)
                VALUES (NEWID(), SYSUTCDATETIME(), SYSUTCDATETIME(), @machine, @version, 'cutover', 'Succeeded', @report);
                """, cancellationToken,
                ("@window", WindowMarker + (int)window.TotalHours), ("@machine", Environment.MachineName), ("@version", SchemaMigrator.PackageVersion),
                ("@report", $"{{\"approvedBy\":\"{approver.Replace("\"", "'")}\",\"rollbackWindowHours\":{(int)window.TotalHours}}}"));
        }

        /// <summary>When the cutover happened and when its rollback window closes; null before the cutover.</summary>
        public static async Task<(DateTime At, DateTime WindowEnds)?> WindowAsync(DbConnection connection, string target, CancellationToken cancellationToken)
        {
            await using var command = connection.CreateCommand();
            command.CommandText = $"""
                SELECT c.SetAt, w.Name FROM [{target}].[{SchemaHistory.MarkerTable}] c
                LEFT JOIN [{target}].[{SchemaHistory.MarkerTable}] w ON w.Name LIKE '{WindowMarker}%'
                WHERE c.Name = '{SchemaHistory.CutoverCompleted}'
                """;
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken))
                return null;
            var at = DateTime.SpecifyKind(reader.GetDateTime(0), DateTimeKind.Utc);
            var hours = reader.IsDBNull(1) ? 48 : int.Parse(reader.GetString(1)[WindowMarker.Length..]);
            return (at, at.AddHours(hours));
        }

        /// <summary>
        /// Takes the revocations made in the target since the cutover back to the legacy schema, so that going back to the
        /// old version does not undo them: roles taken away, people suspended, tokens deactivated or deleted, permissions a
        /// role no longer grants. Decided by comparing the two schemas, never granting anything. A dry run without
        /// <paramref name="apply"/>.
        /// </summary>
        public static async Task<IReadOnlyList<RollbackChange>> RollbackSyncAsync(
            string connectionString, string legacy, string target, bool apply, CancellationToken cancellationToken)
        {
            await using var connection = new SqlConnection(connectionString);
            await connection.OpenAsync(cancellationToken);
            var window = await WindowAsync(connection, target, cancellationToken)
                         ?? throw new InvalidOperationException($"[{target}] has not been cut over: there is nothing to take back.");

            // Legacy keys of what the target knows: users through their profile, roles through the permanent map.
            const string Users = "SELECT p.legacyUserId AS UserId, p.objectId, p.isActive FROM [{0}].[UserProfile] p WHERE p.legacyUserId IS NOT NULL";
            var users = string.Format(Users, target);
            var statements = new (string Table, string What, string Sql)[]
            {
                ("UserRole", "roles taken away", $"""
                    DELETE ur FROM [{legacy}].[UserRole] ur
                    JOIN ({users}) u ON u.UserId = ur.UserId
                    JOIN [{target}].[LegacyRoleMap] m ON m.RoleId = ur.RoleId
                    WHERE NOT EXISTS (SELECT 1 FROM [{target}].[UserRole] t WHERE t.objectId = u.objectId AND t.roleValue = m.roleValue)
                    """),
                ("User", "people suspended", $"""
                    UPDATE lu SET lu.isActive = 0 FROM [{legacy}].[User] lu JOIN ({users}) u ON u.UserId = lu.UserId
                    WHERE u.isActive = 0 AND lu.isActive = 1
                    """),
                // At the cutover both schemas held the same tokens, some copied inactive on purpose (limited, ownerless): only
                // what an administrator did since counts — a token deleted, or deactivated according to the audit log.
                ("PersonalAccessToken", "tokens deactivated or deleted", $"""
                    UPDATE lt SET lt.isActive = 0 FROM [{legacy}].[PersonalAccessToken] lt
                    WHERE lt.isActive = 1
                      AND (NOT EXISTS (SELECT 1 FROM [{target}].[PersonalAccessToken] t WHERE t.tokenHash = lt.tokenHash)
                           OR EXISTS (SELECT 1 FROM [{target}].[PersonalAccessToken] t
                                      JOIN [{target}].[AuditLog] a ON a.targetType = 'pat' AND a.targetId = CONVERT(NVARCHAR(100), t.PersonalAccessTokenId)
                                      WHERE t.tokenHash = lt.tokenHash AND t.isActive = 0 AND a.action = 'pat.deactivated' AND a.occurredAt >= @cutover))
                    """),
                ("RolePermission", "permissions a role no longer grants", $"""
                    DELETE lp FROM [{legacy}].[RolePermission] lp
                    JOIN [{target}].[LegacyRoleMap] m ON m.RoleId = lp.RoleId
                    WHERE EXISTS (SELECT 1 FROM [{target}].[Permission] c WHERE c.PermissionCode = lp.PermissionCode COLLATE {SchemaManifest.Bin2})
                      AND NOT EXISTS (SELECT 1 FROM [{target}].[RolePermission] t WHERE t.roleValue = m.roleValue AND t.PermissionCode = lp.PermissionCode COLLATE {SchemaManifest.Bin2})
                    """),
            };

            var changes = new List<RollbackChange>();
            await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
            foreach (var (table, what, sql) in statements)
                changes.Add(new RollbackChange(table, what, await ScalarAsync(connection, transaction, sql + "; SELECT @@ROWCOUNT;", cancellationToken, ("@cutover", window.At))));

            if (apply)
            {
                await ExecuteAsync(connection, transaction, $"""
                    INSERT INTO [{target}].[{SchemaHistory.LogTable}] (RunId, StartedAt, EndedAt, Machine, PackageVersion, Mode, Result, Report)
                    VALUES (NEWID(), SYSUTCDATETIME(), SYSUTCDATETIME(), @machine, @version, 'rollback-sync', 'Succeeded', @report);
                    """, cancellationToken, ("@machine", Environment.MachineName), ("@version", SchemaMigrator.PackageVersion),
                    ("@report", "{" + string.Join(",", changes.Select(c => $"\"{c.Table}\":{c.Count}")) + "}"));
                await transaction.CommitAsync(cancellationToken);
            }
            else
                await transaction.RollbackAsync(cancellationToken);
            return changes;
        }

        /// <summary>
        /// The contraction: the legacy schema renamed to <c>{legacy}_legacy_{yyyyMMdd}</c> (every table moved, nothing dropped),
        /// or the renamed schema dropped. Only after the rollback window has closed, and only when confirmed.
        /// </summary>
        public static async Task<string> ContractAsync(
            string connectionString, string legacy, string target, bool drop, DateTime now, CancellationToken cancellationToken)
        {
            await using var connection = new SqlConnection(connectionString);
            await connection.OpenAsync(cancellationToken);
            var window = await WindowAsync(connection, target, cancellationToken)
                         ?? throw new InvalidOperationException($"[{target}] has not been cut over: the legacy schema is still the application's.");
            if (now < window.WindowEnds)
                throw new InvalidOperationException($"The rollback window closes at {window.WindowEnds:u}: the legacy schema is needed until then.");

            var tables = new List<string>();
            await using (var list = connection.CreateCommand())
            {
                list.CommandText = "SELECT name FROM sys.tables WHERE schema_id = SCHEMA_ID(@schema)";
                list.Parameters.Add(new SqlParameter("@schema", legacy));
                await using var reader = await list.ExecuteReaderAsync(cancellationToken);
                while (await reader.ReadAsync(cancellationToken))
                    tables.Add(reader.GetString(0));
            }

            if (drop)
            {
                if (!legacy.Contains("_legacy_", StringComparison.Ordinal))
                    throw new InvalidOperationException($"Only a renamed legacy schema (…_legacy_yyyyMMdd) is dropped, never '{legacy}' itself: rename it first.");
                var sql = new StringBuilder();
                sql.AppendLine($"""
                    DECLARE @fk NVARCHAR(MAX) = N'';
                    SELECT @fk += N'ALTER TABLE [{legacy}].' + QUOTENAME(OBJECT_NAME(parent_object_id)) + N' DROP CONSTRAINT ' + QUOTENAME(name) + N';'
                    FROM sys.foreign_keys WHERE schema_id = SCHEMA_ID(N'{legacy}');
                    EXEC (@fk);
                    """);
                foreach (var table in tables)
                    sql.AppendLine($"DROP TABLE [{legacy}].[{table}];");
                sql.AppendLine($"DROP SCHEMA [{legacy}];");
                await ExecuteAsync(connection, null, sql.ToString(), cancellationToken);
                return $"[{legacy}] dropped ({tables.Count} tables).";
            }

            var renamed = $"{legacy}_legacy_{now:yyyyMMdd}";
            var move = new StringBuilder($"EXEC(N'CREATE SCHEMA [{renamed}] AUTHORIZATION dbo');\n");
            foreach (var table in tables)
                move.AppendLine($"ALTER SCHEMA [{renamed}] TRANSFER [{legacy}].[{table}];");
            await using (var transaction = await connection.BeginTransactionAsync(cancellationToken))
            {
                await ExecuteAsync(connection, transaction, move.ToString(), cancellationToken);
                await transaction.CommitAsync(cancellationToken);
            }
            return $"[{legacy}] moved to [{renamed}] ({tables.Count} tables). Drop it later with 'contract drop --legacy-schema {renamed} --confirm'.";
        }

        private static async Task<int> ScalarAsync(
            DbConnection connection, DbTransaction? transaction, string sql, CancellationToken cancellationToken, params (string Name, object? Value)[] parameters)
        {
            await using var command = connection.CreateCommand();
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
            return Convert.ToInt32(await command.ExecuteScalarAsync(cancellationToken));
        }

        private static async Task ExecuteAsync(
            DbConnection connection, DbTransaction? transaction, string sql, CancellationToken cancellationToken, params (string Name, object? Value)[] parameters)
        {
            await using var command = connection.CreateCommand();
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
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
    }
}
