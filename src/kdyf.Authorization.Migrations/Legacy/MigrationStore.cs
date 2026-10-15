using System.Data.Common;

namespace kdyf.Authorization.Migrations.Legacy
{
    /// <summary>
    /// The working tables of the legacy import, in the target schema: <c>MigrationIdentity</c> (who each legacy user is)
    /// and <c>MigrationGateSnapshot</c> (what both gates said about them). They hold e-mails: the application's runtime
    /// role is denied them, and they are dropped 30 days after the cutover. Not part of the schema's versions.
    /// </summary>
    internal static class MigrationStore
    {
        public const string IdentityTable = "MigrationIdentity";
        public const string GateTable = "MigrationGateSnapshot";

        public static string BootstrapSql(string schema) => $"""
            IF SCHEMA_ID(N'{schema}') IS NULL EXEC(N'CREATE SCHEMA [{schema}] AUTHORIZATION dbo');

            IF OBJECT_ID(N'[{schema}].[{IdentityTable}]') IS NULL
            CREATE TABLE [{schema}].[{IdentityTable}] (
                LegacyUserId     INT           NOT NULL CONSTRAINT PK_{IdentityTable} PRIMARY KEY,
                Email            NVARCHAR(256) NOT NULL,
                LegacyObjectId   NVARCHAR(100) NULL,
                ObjectId         VARCHAR(50)   NULL,
                Method           VARCHAR(20)   NOT NULL,
                Matches          INT           NOT NULL,
                UserType         VARCHAR(20)   NULL,
                AccountEnabled   BIT           NULL,
                Status           VARCHAR(20)   NOT NULL,
                SourceRowVersion CHAR(16)      NOT NULL,
                ResolvedAt       DATETIME2     NOT NULL,
                ApprovedBy       NVARCHAR(128) NULL,
                ApprovedAt       DATETIME2     NULL
            );

            IF OBJECT_ID(N'[{schema}].[{GateTable}]') IS NULL
            CREATE TABLE [{schema}].[{GateTable}] (
                LegacyUserId     INT         NOT NULL CONSTRAINT PK_{GateTable} PRIMARY KEY,
                ObjectId         VARCHAR(50) NULL,
                PassedLegacyGate BIT         NOT NULL,
                PassesNewGate    BIT         NULL,
                TakenAt          DATETIME2   NOT NULL
            );

            {InvariantExceptions.BootstrapSql(schema)}

            DECLARE @role sysname = N'kdyf_{schema}_runtime';
            IF DATABASE_PRINCIPAL_ID(@role) IS NOT NULL
                EXEC(N'DENY SELECT, INSERT, UPDATE, DELETE ON [{schema}].[{IdentityTable}] TO ' + @role + N';
                       DENY SELECT, INSERT, UPDATE, DELETE ON [{schema}].[{GateTable}] TO ' + @role + N';
                       DENY SELECT, INSERT, UPDATE, DELETE ON [{schema}].[{InvariantExceptions.Table}] TO ' + @role + N';');
            """;

        /// <summary>Replaces every identity and its gate snapshot, in one transaction.</summary>
        public static async Task SaveAsync(DbConnection connection, string schema, IReadOnlyCollection<ResolvedIdentity> identities, CancellationToken cancellationToken)
        {
            await ExecuteAsync(connection, null, BootstrapSql(schema), cancellationToken);
            await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
            await ExecuteAsync(connection, transaction, $"DELETE FROM [{schema}].[{GateTable}]; DELETE FROM [{schema}].[{IdentityTable}];", cancellationToken);
            foreach (var i in identities)
            {
                await ExecuteAsync(connection, transaction, $"""
                    INSERT INTO [{schema}].[{IdentityTable}] (LegacyUserId, Email, LegacyObjectId, ObjectId, Method, Matches, UserType, AccountEnabled, Status, SourceRowVersion, ResolvedAt, ApprovedBy, ApprovedAt)
                    VALUES (@id, @email, @legacyObjectId, @objectId, @method, @matches, @userType, @enabled, @status, @version, @resolvedAt, @approvedBy, @approvedAt);
                    INSERT INTO [{schema}].[{GateTable}] (LegacyUserId, ObjectId, PassedLegacyGate, PassesNewGate, TakenAt)
                    VALUES (@id, @objectId, @legacyGate, @newGate, @resolvedAt);
                    """, cancellationToken,
                    ("@id", i.LegacyUserId), ("@email", i.Email), ("@legacyObjectId", i.LegacyObjectId), ("@objectId", i.ObjectId),
                    ("@method", i.Method), ("@matches", i.Matches), ("@userType", i.UserType), ("@enabled", i.AccountEnabled),
                    ("@status", i.Status), ("@version", i.SourceRowVersion), ("@resolvedAt", i.ResolvedAt), ("@approvedBy", i.ApprovedBy),
                    ("@approvedAt", i.ApprovedAt), ("@legacyGate", i.PassedLegacyGate), ("@newGate", i.PassesNewGate));
            }
            await transaction.CommitAsync(cancellationToken);
        }

        /// <summary>The identities with their gate snapshot; empty when none were resolved.</summary>
        public static async Task<IReadOnlyList<ResolvedIdentity>> LoadAsync(DbConnection connection, string schema, CancellationToken cancellationToken)
        {
            await using var command = connection.CreateCommand();
            command.CommandText = $"""
                IF OBJECT_ID(N'[{schema}].[{IdentityTable}]') IS NULL OR OBJECT_ID(N'[{schema}].[{GateTable}]') IS NULL
                    SELECT TOP (0) 0, N'', N'', '', '', 0, '', CAST(0 AS bit), '', '', SYSUTCDATETIME(), N'', SYSUTCDATETIME(), CAST(0 AS bit), CAST(0 AS bit)
                ELSE
                    SELECT i.LegacyUserId, i.Email, i.LegacyObjectId, i.ObjectId, i.Method, i.Matches, i.UserType, i.AccountEnabled, i.Status,
                           i.SourceRowVersion, i.ResolvedAt, i.ApprovedBy, i.ApprovedAt, g.PassedLegacyGate, g.PassesNewGate
                    FROM [{schema}].[{IdentityTable}] i JOIN [{schema}].[{GateTable}] g ON g.LegacyUserId = i.LegacyUserId
                    ORDER BY i.LegacyUserId
                """;
            var list = new List<ResolvedIdentity>();
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
                list.Add(new ResolvedIdentity(
                    reader.GetInt32(0), reader.GetString(1), Text(reader, 2), Text(reader, 3), reader.GetString(4), reader.GetInt32(5),
                    Text(reader, 6), reader.IsDBNull(7) ? null : reader.GetBoolean(7), reader.GetString(8), reader.GetString(9).Trim(),
                    reader.GetBoolean(13), reader.IsDBNull(14) ? null : reader.GetBoolean(14), reader.GetDateTime(10),
                    Text(reader, 11), reader.IsDBNull(12) ? null : reader.GetDateTime(12)));
            return list;
        }

        private static string? Text(DbDataReader reader, int ordinal) => reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);

        private static async Task ExecuteAsync(
            DbConnection connection, DbTransaction? transaction, string sql, CancellationToken cancellationToken, params (string Name, object? Value)[] parameters)
        {
            await using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = sql;
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
