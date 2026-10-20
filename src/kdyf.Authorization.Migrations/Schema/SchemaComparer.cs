namespace kdyf.Authorization.Migrations.Schema
{
    /// <summary>How much a difference between the database and the manifest matters.</summary>
    public enum DifferenceKind
    {
        /// <summary>Harmless and tolerated: an extra index, another name for the same constraint.</summary>
        Note,

        /// <summary>A key column without the binary collation: repairable, with approval.</summary>
        Collation,

        /// <summary>A different shape: the database is not at that version.</summary>
        Mismatch,
    }

    /// <summary>One difference between the database and the manifest.</summary>
    public sealed record SchemaDifference(DifferenceKind Kind, string Table, string Description)
    {
        /// <summary><c>[Kind] Table: Description</c>.</summary>
        public override string ToString() => $"[{Kind}] {Table}: {Description}";
    }

    /// <summary>
    /// Compares what the catalog says with what a version of the manifest expects. Tolerates, and only these: extra
    /// tables (backups, the host's own), extra indexes, other names for the same constraint, and defaults (not compared).
    /// </summary>
    internal static class SchemaComparer
    {
        /// <summary>The differences of the tables, at <paramref name="version"/>.</summary>
        public static IReadOnlyList<SchemaDifference> CompareTables(SchemaSnapshot snapshot, int version)
        {
            var differences = new List<SchemaDifference>();
            foreach (var spec in SchemaManifest.Tables(version))
            {
                var table = snapshot.Table(spec.Name);
                if (table is null)
                {
                    differences.Add(new(DifferenceKind.Mismatch, spec.Name, "the table is missing"));
                    continue;
                }
                CompareTable(snapshot.Schema, spec, table, differences);
            }
            return differences;
        }

        /// <summary>The differences of the runtime role's permissions, at <paramref name="version"/>.</summary>
        public static IReadOnlyList<SchemaDifference> ComparePermissions(SchemaSnapshot snapshot, int version)
        {
            var differences = new List<SchemaDifference>();
            if (!snapshot.RoleExists)
            {
                differences.Add(new(DifferenceKind.Mismatch, "(database)", "the runtime role is missing"));
                return differences;
            }

            Compare(SchemaManifest.Grants(version), snapshot.Grants, "granted");
            Compare(SchemaManifest.Denies(version), snapshot.Denies, "denied");
            return differences;

            void Compare(IReadOnlyDictionary<string, string[]> expected, IReadOnlyDictionary<string, IReadOnlySet<string>> actual, string verb)
            {
                foreach (var (table, permissions) in expected)
                {
                    actual.TryGetValue(table, out var has);
                    var missing = permissions.Where(p => has is null || !has.Contains(p)).ToList();
                    if (missing.Count > 0)
                        differences.Add(new(DifferenceKind.Mismatch, table, $"the runtime role is not {verb} {string.Join(", ", missing)}"));
                }
            }
        }

        private static void CompareTable(string schema, TableSpec spec, TableShape table, List<SchemaDifference> differences)
        {
            foreach (var column in spec.Columns)
            {
                var actual = table.Column(column.Name);
                if (actual is null)
                {
                    differences.Add(new(DifferenceKind.Mismatch, spec.Name, $"column {column.Name} is missing"));
                    continue;
                }
                if (!string.Equals(actual.Name, column.Name, StringComparison.Ordinal))
                    differences.Add(new(DifferenceKind.Note, spec.Name, $"column {column.Name} is spelled {actual.Name}"));
                if (!string.Equals(actual.Type, column.Type, StringComparison.OrdinalIgnoreCase))
                    differences.Add(new(DifferenceKind.Mismatch, spec.Name, $"column {column.Name} is {actual.Type}, expected {column.Type}"));
                if (actual.Nullable != column.Nullable)
                    differences.Add(new(DifferenceKind.Mismatch, spec.Name, $"column {column.Name} is {(actual.Nullable ? "NULL" : "NOT NULL")}, expected {(column.Nullable ? "NULL" : "NOT NULL")}"));
                if (actual.Identity != column.Identity)
                    differences.Add(new(DifferenceKind.Mismatch, spec.Name, $"column {column.Name} is {(actual.Identity ? "" : "not ")}an identity"));
                if (column.Collation is not null && !string.Equals(actual.Collation, column.Collation, StringComparison.OrdinalIgnoreCase))
                    differences.Add(new(DifferenceKind.Collation, spec.Name, $"column {column.Name} has collation {actual.Collation ?? "(none)"}, expected {column.Collation}"));
            }

            foreach (var extra in table.Columns.Where(c => spec.Columns.All(s => !string.Equals(s.Name, c.Name, StringComparison.OrdinalIgnoreCase))))
                differences.Add(new(DifferenceKind.Mismatch, spec.Name, $"column {extra.Name} is not expected"));

            var primaryKey = table.PrimaryKey;
            if (primaryKey is null)
                differences.Add(new(DifferenceKind.Mismatch, spec.Name, "the primary key is missing"));
            else
            {
                if (!SameColumns(primaryKey.Columns, spec.PrimaryKey))
                    differences.Add(new(DifferenceKind.Mismatch, spec.Name, $"the primary key is ({string.Join(", ", primaryKey.Columns)}), expected ({string.Join(", ", spec.PrimaryKey)})"));
                if (!string.Equals(primaryKey.Name, spec.PrimaryKeyName, StringComparison.OrdinalIgnoreCase))
                    differences.Add(new(DifferenceKind.Note, spec.Name, $"the primary key is named {primaryKey.Name}, expected {spec.PrimaryKeyName}"));
            }

            foreach (var foreignKey in spec.ForeignKeys)
            {
                var actual = table.ForeignKeys.FirstOrDefault(f =>
                    SameColumns(f.Columns, foreignKey.Columns)
                    && string.Equals(f.ReferencedTable, foreignKey.ReferencedTable, StringComparison.OrdinalIgnoreCase)
                    && SameColumns(f.ReferencedColumns, foreignKey.ReferencedColumns));
                if (actual is null)
                {
                    differences.Add(new(DifferenceKind.Mismatch, spec.Name, $"foreign key {foreignKey.Name} is missing"));
                    continue;
                }
                if (!string.Equals(actual.OnDelete, foreignKey.OnDelete, StringComparison.OrdinalIgnoreCase))
                    differences.Add(new(DifferenceKind.Mismatch, spec.Name, $"foreign key {foreignKey.Name} is ON DELETE {actual.OnDelete}, expected {foreignKey.OnDelete}"));
                if (!string.Equals(actual.ReferencedSchema, schema, StringComparison.OrdinalIgnoreCase))
                    differences.Add(new(DifferenceKind.Mismatch, spec.Name, $"foreign key {foreignKey.Name} points at another schema"));
                if (!string.Equals(actual.Name, foreignKey.Name, StringComparison.OrdinalIgnoreCase))
                    differences.Add(new(DifferenceKind.Note, spec.Name, $"foreign key {foreignKey.Name} is named {actual.Name}"));
            }

            foreach (var extra in table.ForeignKeys.Where(f => spec.ForeignKeys.All(s => !SameColumns(s.Columns, f.Columns))))
                differences.Add(new(DifferenceKind.Mismatch, spec.Name, $"foreign key {extra.Name} is not expected"));

            var secondary = table.Indexes.Where(i => !i.PrimaryKey).ToList();
            foreach (var index in spec.Indexes)
            {
                var actual = secondary.FirstOrDefault(i => SameColumns(i.Columns, index.Columns) && i.Unique == index.Unique && SameFilter(i.Filter, index.Filter));
                if (actual is null)
                {
                    differences.Add(new(DifferenceKind.Mismatch, spec.Name, $"index {index.Name} ({string.Join(", ", index.Columns)}{(index.Unique ? ", unique" : "")}) is missing"));
                    continue;
                }
                if (!string.Equals(actual.Name, index.Name, StringComparison.OrdinalIgnoreCase))
                    differences.Add(new(DifferenceKind.Note, spec.Name, $"index {index.Name} is named {actual.Name}"));
            }

            foreach (var extra in secondary.Where(i => spec.Indexes.All(s => !SameColumns(s.Columns, i.Columns) || s.Unique != i.Unique)))
                differences.Add(new(DifferenceKind.Note, spec.Name, $"index {extra.Name} is not expected (tolerated)"));
        }

        /// <summary>SQL Server stores a filter as it normalised it, '([legacyUserId] IS NOT NULL)': compared without brackets, parentheses or spacing.</summary>
        private static bool SameFilter(string? actual, string? expected)
        {
            static string Normal(string? filter) =>
                new string((filter ?? string.Empty).Where(c => c is not ('[' or ']' or '(' or ')') && !char.IsWhiteSpace(c)).ToArray()).ToLowerInvariant();
            return Normal(actual) == Normal(expected);
        }

        private static bool SameColumns(IReadOnlyList<string> a, IReadOnlyList<string> b) =>
            a.Count == b.Count && a.Zip(b).All(p => string.Equals(p.First, p.Second, StringComparison.OrdinalIgnoreCase));
    }
}
