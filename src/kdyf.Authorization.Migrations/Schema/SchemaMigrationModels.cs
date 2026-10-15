using System.Text.RegularExpressions;

namespace kdyf.Authorization.Migrations.Schema
{
    /// <summary>The approvals a person gives for what the migration never does on its own.</summary>
    public static class SchemaApprovals
    {
        /// <summary>Rebuild the keys of version 1 with the binary collation (drops and recreates primary and foreign keys).</summary>
        public const string CollationRepair = "collation-repair";

        /// <summary>
        /// Accept an application user that is <c>db_owner</c> or <c>db_datawriter</c>: the denies of the runtime role do
        /// not bind it, so the history and the audit log stay writable by the application.
        /// </summary>
        public const string PrivilegedAppUser = "privileged-app-user";
    }

    /// <summary>How a run of the migration behaves.</summary>
    public sealed partial class SchemaMigrationOptions
    {
        /// <summary>The schema to version: the <c>Schema</c> of the packages' configuration.</summary>
        public string Schema { get; set; } = "auth";

        /// <summary>
        /// The application's database user, made a member of the runtime role. Optional: without it the role exists and is
        /// granted, and who belongs to it is left to the DBA.
        /// </summary>
        public string? AppUser { get; set; }

        /// <summary>What a person approved (<see cref="SchemaApprovals"/>).</summary>
        public ISet<string> Approvals { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// The operator confirms a backup of the database taken for this run. Without it, applying to a database that
        /// holds tables needs a full or differential backup in <c>msdb</c> younger than <see cref="BackupMaxAge"/>.
        /// </summary>
        public bool BackupConfirmed { get; set; }

        public TimeSpan BackupMaxAge { get; set; } = TimeSpan.FromHours(24);

        /// <summary>How long a run waits for another one on the same schema to finish.</summary>
        public TimeSpan LockTimeout { get; set; } = TimeSpan.FromMinutes(1);

        /// <summary>The version of the host running the migration, for the log.</summary>
        public string? HostVersion { get; set; }

        /// <summary>The database role of the application: <c>kdyf_{schema}_runtime</c>.</summary>
        public string RuntimeRole => $"kdyf_{Schema}_runtime";

        [GeneratedRegex("^[A-Za-z_][A-Za-z0-9_]*$")]
        private static partial Regex Identifier();

        internal void Validate()
        {
            if (string.IsNullOrWhiteSpace(Schema) || !Identifier().IsMatch(Schema))
                throw new ArgumentException($"'{Schema}' is not a valid SQL schema name (letters, digits and '_', not starting with a digit).");
            if (AppUser is not null && (AppUser.Length > 128 || AppUser.Contains(']') || AppUser.Trim().Length == 0))
                throw new ArgumentException($"'{AppUser}' is not a valid database user name.");
        }
    }

    public enum IssueSeverity
    {
        Warning,

        /// <summary>Nothing is applied while it stands.</summary>
        Blocker,

        /// <summary>Worth knowing; decides nothing.</summary>
        Info,
    }

    /// <summary>Something found before applying: a code that does not change, and a message for a person.</summary>
    public sealed record SchemaIssue(IssueSeverity Severity, string Code, string Message)
    {
        public override string ToString() => $"{Severity.ToString().ToUpperInvariant()} {Code}: {Message}";
    }

    /// <summary>What a run would do, step by step.</summary>
    public enum PlannedActionKind
    {
        CreateHistory,
        RepairCollation,
        Apply,
        Adopt,
        AddAppUser,
    }

    public sealed record PlannedAction(PlannedActionKind Kind, int? Version, string Description)
    {
        public override string ToString() => Version is null ? $"{Kind}: {Description}" : $"{Kind} {Version}: {Description}";
    }

    /// <summary>The dry run: the state, what would be done, and what stands in the way. Writes nothing.</summary>
    public sealed class SchemaMigrationPlan
    {
        internal SchemaMigrationPlan(SchemaDetection detection, IReadOnlyList<PlannedAction> actions, IReadOnlyList<SchemaIssue> issues, int targetVersion)
        {
            Detection = detection;
            Actions = actions;
            Issues = issues;
            TargetVersion = targetVersion;
        }

        public SchemaDetection Detection { get; }

        public IReadOnlyList<PlannedAction> Actions { get; }

        public IReadOnlyList<SchemaIssue> Issues { get; }

        /// <summary>The version the packages require: the last step.</summary>
        public int TargetVersion { get; }

        public bool HasBlockers => Issues.Any(i => i.Severity == IssueSeverity.Blocker);

        /// <summary>Nothing to do: already at the target version, nothing failed, no app user to add.</summary>
        public bool UpToDate => Actions.Count == 0;
    }

    public enum SchemaRunResult
    {
        /// <summary>Everything planned was applied and verified.</summary>
        Succeeded,

        /// <summary>Already at the target version.</summary>
        UpToDate,

        /// <summary>Blockers: nothing was applied.</summary>
        Refused,

        /// <summary>A step failed: it is recorded as failed and the next run resumes it.</summary>
        Failed,
    }

    /// <summary>What a run did.</summary>
    public sealed class SchemaMigrationReport
    {
        internal SchemaMigrationReport(Guid runId, SchemaRunResult result, SchemaMigrationPlan plan, IReadOnlyList<PlannedAction> done, int? version, string? error)
        {
            RunId = runId;
            Result = result;
            Plan = plan;
            Done = done;
            Version = version;
            Error = error;
        }

        public Guid RunId { get; }

        public SchemaRunResult Result { get; }

        /// <summary>The plan the run was made from, computed after taking the lock.</summary>
        public SchemaMigrationPlan Plan { get; }

        /// <summary>What was applied, in order.</summary>
        public IReadOnlyList<PlannedAction> Done { get; }

        /// <summary>The version at the end of the run.</summary>
        public int? Version { get; }

        public string? Error { get; }

        public bool Succeeded => Result is SchemaRunResult.Succeeded or SchemaRunResult.UpToDate;
    }

    /// <summary>The verification: the schema equals the manifest of its version, and the history the code.</summary>
    public sealed class SchemaVerification
    {
        internal SchemaVerification(SchemaDetection detection, IReadOnlyList<SchemaIssue> issues, int targetVersion)
        {
            Detection = detection;
            Issues = issues;
            TargetVersion = targetVersion;
        }

        public SchemaDetection Detection { get; }

        public IReadOnlyList<SchemaIssue> Issues { get; }

        public int TargetVersion { get; }

        /// <summary>At the target version, equal to its manifest, no failed step, and every checksum matches.</summary>
        public bool Succeeded => Issues.Count == 0;
    }
}
