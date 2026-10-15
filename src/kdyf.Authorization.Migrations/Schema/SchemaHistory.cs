using System.Data.Common;

namespace kdyf.Authorization.Migrations.Schema
{
    /// <summary>A row of the history: one step, how it got there, and with which code.</summary>
    public sealed record AppliedStep(
        int Version, string StepId, string Checksum, string Status, string Origin, DateTime AppliedAt, string AppliedBy,
        string PackageVersion, Guid RunId, string? Error);

    /// <summary>
    /// The history of the schema, in the schema itself: <c>SchemaVersion</c> (one row per step), <c>SchemaMigrationLog</c>
    /// (one row per run, with its report) and <c>SchemaMarker</c> (states such as <c>CutoverCompleted</c>). Created
    /// before the first step and never by the application, whose role may read the version and nothing else.
    /// </summary>
    internal static class SchemaHistory
    {
        public const string VersionTable = "SchemaVersion";
        public const string LogTable = "SchemaMigrationLog";
        public const string MarkerTable = "SchemaMarker";

        public const string Applied = "Applied";
        public const string Failed = "Failed";

        /// <summary>The marker that closes the legacy import: once set, it refuses to run.</summary>
        public const string CutoverCompleted = "CutoverCompleted";

        /// <summary>The schema and the three tables, if missing. Idempotent.</summary>
        public static string BootstrapSql(string schema) => $"""
            IF SCHEMA_ID(N'{schema}') IS NULL EXEC(N'CREATE SCHEMA [{schema}] AUTHORIZATION dbo');

            IF OBJECT_ID(N'[{schema}].[{VersionTable}]') IS NULL
            CREATE TABLE [{schema}].[{VersionTable}] (
                Version        INT              NOT NULL CONSTRAINT PK_{VersionTable} PRIMARY KEY,
                StepId         VARCHAR(100)     NOT NULL,
                Checksum       CHAR(64)         NOT NULL,
                Status         VARCHAR(20)      NOT NULL,
                Origin         VARCHAR(20)      NOT NULL,
                AppliedAt      DATETIME2        NOT NULL CONSTRAINT DF_{VersionTable}_AppliedAt DEFAULT SYSUTCDATETIME(),
                AppliedBy      NVARCHAR(128)    NOT NULL CONSTRAINT DF_{VersionTable}_AppliedBy DEFAULT SUSER_SNAME(),
                PackageVersion VARCHAR(100)     NOT NULL,
                RunId          UNIQUEIDENTIFIER NOT NULL,
                Error          NVARCHAR(MAX)    NULL
            );

            IF OBJECT_ID(N'[{schema}].[{LogTable}]') IS NULL
            CREATE TABLE [{schema}].[{LogTable}] (
                RunId          UNIQUEIDENTIFIER NOT NULL CONSTRAINT PK_{LogTable} PRIMARY KEY,
                StartedAt      DATETIME2        NOT NULL,
                EndedAt        DATETIME2        NULL,
                Machine        NVARCHAR(128)    NOT NULL,
                DatabaseUser   NVARCHAR(128)    NOT NULL CONSTRAINT DF_{LogTable}_DatabaseUser DEFAULT SUSER_SNAME(),
                PackageVersion VARCHAR(100)     NOT NULL,
                HostVersion    VARCHAR(100)     NULL,
                Mode           VARCHAR(20)      NOT NULL,
                Result         VARCHAR(20)      NULL,
                Report         NVARCHAR(MAX)    NULL
            );

            IF OBJECT_ID(N'[{schema}].[{MarkerTable}]') IS NULL
            CREATE TABLE [{schema}].[{MarkerTable}] (
                Name   VARCHAR(50)      NOT NULL CONSTRAINT PK_{MarkerTable} PRIMARY KEY,
                SetAt  DATETIME2        NOT NULL CONSTRAINT DF_{MarkerTable}_SetAt DEFAULT SYSUTCDATETIME(),
                SetBy  NVARCHAR(128)    NOT NULL CONSTRAINT DF_{MarkerTable}_SetBy DEFAULT SUSER_SNAME(),
                RunId  UNIQUEIDENTIFIER NOT NULL
            );
            """;

        /// <summary>The row of a step, applied or failed. Replaces a failed row of the same version.</summary>
        public static string RecordSql(string schema) => $"""
            DELETE FROM [{schema}].[{VersionTable}] WHERE Version = @version AND Status = '{Failed}';
            INSERT INTO [{schema}].[{VersionTable}] (Version, StepId, Checksum, Status, Origin, PackageVersion, RunId, Error)
            VALUES (@version, @stepId, @checksum, @status, @origin, @packageVersion, @runId, @error);
            """;

        public static async Task<IReadOnlyList<AppliedStep>> ReadAsync(
            DbConnection connection, DbTransaction? transaction, string schema, CancellationToken cancellationToken)
        {
            await using var exists = connection.CreateCommand();
            exists.Transaction = transaction;
            exists.CommandText = $"SELECT OBJECT_ID(N'[{schema}].[{VersionTable}]')";
            if (await exists.ExecuteScalarAsync(cancellationToken) is null or DBNull)
                return Array.Empty<AppliedStep>();

            await using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = $"""
                SELECT Version, StepId, Checksum, Status, Origin, AppliedAt, AppliedBy, PackageVersion, RunId, Error
                FROM [{schema}].[{VersionTable}] ORDER BY Version
                """;
            var rows = new List<AppliedStep>();
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
                rows.Add(new AppliedStep(
                    reader.GetInt32(0), reader.GetString(1), reader.GetString(2), reader.GetString(3), reader.GetString(4),
                    reader.GetDateTime(5), reader.GetString(6), reader.GetString(7), reader.GetGuid(8),
                    reader.IsDBNull(9) ? null : reader.GetString(9)));
            return rows;
        }

        public static async Task<IReadOnlySet<string>> ReadMarkersAsync(
            DbConnection connection, DbTransaction? transaction, string schema, CancellationToken cancellationToken)
        {
            await using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = $"""
                IF OBJECT_ID(N'[{schema}].[{MarkerTable}]') IS NOT NULL
                    SELECT Name FROM [{schema}].[{MarkerTable}]
                ELSE
                    SELECT CAST(NULL AS VARCHAR(50)) WHERE 1 = 0
                """;
            var markers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
                markers.Add(reader.GetString(0));
            return markers;
        }
    }
}
