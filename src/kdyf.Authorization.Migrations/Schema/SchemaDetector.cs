using System.Data.Common;

namespace kdyf.Authorization.Migrations.Schema
{
    /// <summary>What the schema is, as far as the migration is concerned.</summary>
    public enum SchemaState
    {
        /// <summary>None of the tables: install from scratch.</summary>
        Empty,

        /// <summary>Has a history: apply the steps after its version.</summary>
        Versioned,

        /// <summary>The shape of version 1 without a history (mtcm today): adopt, do not rebuild.</summary>
        Adoptable,

        /// <summary>Version 1 except for the binary collation of the key columns: adoptable after a repair, with approval.</summary>
        NeedsCollationRepair,

        /// <summary>The legacy kdyf.auth.* schema (WIMBA, kdyf.admin): imported into another schema, never upgraded in place.</summary>
        Legacy,

        /// <summary>A known shape that cannot be migrated automatically (mtcm before September 2026's model): fix by hand.</summary>
        Unsupported,

        /// <summary>Any other combination: nothing is done, and the differences are reported.</summary>
        Unknown,
    }

    /// <summary>What the detector found.</summary>
    public sealed class SchemaDetection
    {
        internal SchemaDetection(
            SchemaState state, SchemaSnapshot snapshot, IReadOnlyList<AppliedStep> history, IReadOnlySet<string> markers,
            IReadOnlyList<SchemaDifference> differences, string summary)
        {
            State = state;
            Snapshot = snapshot;
            History = history;
            Markers = markers;
            Differences = differences;
            Summary = summary;
        }

        public SchemaState State { get; }

        public SchemaSnapshot Snapshot { get; }

        /// <summary>The rows of <c>SchemaVersion</c>, applied and failed.</summary>
        public IReadOnlyList<AppliedStep> History { get; }

        /// <summary>The markers set on the schema, such as <c>CutoverCompleted</c>.</summary>
        public IReadOnlySet<string> Markers { get; }

        /// <summary>
        /// The differences with the manifest: at the current version when versioned, with version 1 when adoptable or
        /// unknown.
        /// </summary>
        public IReadOnlyList<SchemaDifference> Differences { get; }

        public string Summary { get; }

        /// <summary>
        /// The version the schema is at: the highest step applied with every step before it applied too. <c>null</c>
        /// without a history.
        /// </summary>
        public int? Version
        {
            get
            {
                int? version = null;
                foreach (var row in History.Where(h => h.Status == SchemaHistory.Applied).OrderBy(h => h.Version))
                {
                    if (row.Version != (version ?? -1) + 1)
                        break;
                    version = row.Version;
                }
                return version;
            }
        }

        /// <summary>A step that failed and has not been applied since: the next run resumes it.</summary>
        public AppliedStep? FailedStep => History.FirstOrDefault(h => h.Status == SchemaHistory.Failed);

        public bool CutoverCompleted => Markers.Contains(SchemaHistory.CutoverCompleted);
    }

    /// <summary>
    /// Tells what state a schema is in, from the catalog only: tables, columns, types, lengths, collations, keys, foreign
    /// keys with their action, indexes. Read-only.
    /// </summary>
    internal static class SchemaDetector
    {
        public static async Task<SchemaDetection> DetectAsync(
            DbConnection connection, DbTransaction? transaction, string schema, string runtimeRole, CancellationToken cancellationToken)
        {
            var snapshot = await SchemaSnapshot.ReadAsync(connection, transaction, schema, runtimeRole, cancellationToken);
            var history = await SchemaHistory.ReadAsync(connection, transaction, schema, cancellationToken);
            var markers = await SchemaHistory.ReadMarkersAsync(connection, transaction, schema, cancellationToken);
            return Detect(snapshot, history, markers);
        }

        internal static SchemaDetection Detect(SchemaSnapshot snapshot, IReadOnlyList<AppliedStep> history, IReadOnlySet<string> markers)
        {
            var schema = snapshot.Schema;

            if (history.Count > 0)
            {
                var detection = new SchemaDetection(SchemaState.Versioned, snapshot, history, markers, Array.Empty<SchemaDifference>(), "");
                var version = detection.Version ?? -1;
                var differences = version < 0
                    ? new List<SchemaDifference>()
                    : SchemaComparer.CompareTables(snapshot, version).Concat(SchemaComparer.ComparePermissions(snapshot, version)).ToList();
                return new SchemaDetection(SchemaState.Versioned, snapshot, history, markers, differences,
                    version < 0 ? $"{schema}: versioned, no step applied yet." : $"{schema}: at version {version}.");
            }

            var ours = SchemaManifest.TableNames.Where(n => snapshot.Table(n) is not null).ToList();
            var role = snapshot.Table("Role");

            if (snapshot.Table("User") is not null || role?.Column("RoleId") is not null)
                return new SchemaDetection(SchemaState.Legacy, snapshot, history, markers, Array.Empty<SchemaDifference>(),
                    $"{schema}: the legacy kdyf.auth.* schema (auth.[User] or Role.RoleId). It is imported into another schema, "
                    + "never upgraded in place: set the target schema to a new one (for example 'authz') and use the legacy import.");

            if (ours.Count == 0)
                return new SchemaDetection(SchemaState.Empty, snapshot, history, markers, Array.Empty<SchemaDifference>(),
                    snapshot.Exists ? $"{schema}: none of the tables." : $"{schema}: the schema does not exist.");

            if (role is null && snapshot.Table("RolePermission")?.Column("roleValue") is not null)
                return new SchemaDetection(SchemaState.Unsupported, snapshot, history, markers, Array.Empty<SchemaDifference>(),
                    $"{schema}: RolePermission keyed by roleValue without a Role table (the model of 10 September 2026). "
                    + "Bring it to the current shape by hand (mtcm's auth-schema.sql), then adopt it.");

            var tableDifferences = SchemaComparer.CompareTables(snapshot, 1);
            if (tableDifferences.Any(d => d.Kind == DifferenceKind.Mismatch))
                return new SchemaDetection(SchemaState.Unknown, snapshot, history, markers, tableDifferences,
                    $"{schema}: tables of authorization in a shape no step knows. Nothing is done; the differences with version 1 follow.");

            if (tableDifferences.Any(d => d.Kind == DifferenceKind.Collation))
                return new SchemaDetection(SchemaState.NeedsCollationRepair, snapshot, history, markers, tableDifferences,
                    $"{schema}: version 1 without the binary collation on key columns. Adoptable after a collation repair, "
                    + $"which needs the approval '{SchemaApprovals.CollationRepair}'.");

            return new SchemaDetection(SchemaState.Adoptable, snapshot, history, markers, tableDifferences,
                $"{schema}: the shape of version 1 without a history. Adopted: stamped, not rebuilt.");
        }
    }
}
