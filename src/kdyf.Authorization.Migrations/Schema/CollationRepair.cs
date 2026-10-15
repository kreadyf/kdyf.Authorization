using System.Text;

namespace kdyf.Authorization.Migrations.Schema
{
    /// <summary>
    /// Gives the key columns of version 1 the binary collation, for a database created with the database's default
    /// (case-insensitive) collation: drops the foreign keys, indexes and primary keys over them, alters the columns and
    /// recreates the keys under the manifest's names. Only with the approval <see cref="SchemaApprovals.CollationRepair"/>.
    /// </summary>
    /// <remarks>
    /// The repair cannot create duplicates: a primary key that held under a case-insensitive collation holds under a
    /// binary one. What it can break is a reference that only matched ignoring case ('portal.admin' granted, 'Portal.Admin'
    /// defined): those are counted first, and any of them is a blocker to fix by hand.
    /// </remarks>
    internal static class CollationRepair
    {
        private static readonly (string Table, string Column)[] KeyColumns =
        {
            ("Permission", "PermissionCode"),
            ("Role", "roleValue"),
            ("RolePermission", "roleValue"),
            ("RolePermission", "PermissionCode"),
            ("UserRole", "roleValue"),
        };

        private static readonly string[] Tables = { "Role", "Permission", "RolePermission", "UserRole" };

        /// <summary>The references that only match ignoring case, per foreign key. Each one is a blocker.</summary>
        public static string MismatchesSql(string schema) => $"""
            SELECT 'FK_RolePermission_Role', COUNT(*) FROM [{schema}].[RolePermission] c
            WHERE NOT EXISTS (SELECT 1 FROM [{schema}].[Role] p WHERE p.roleValue = c.roleValue COLLATE {SchemaManifest.Bin2})
            UNION ALL
            SELECT 'FK_RolePermission_Permission', COUNT(*) FROM [{schema}].[RolePermission] c
            WHERE NOT EXISTS (SELECT 1 FROM [{schema}].[Permission] p WHERE p.PermissionCode = c.PermissionCode COLLATE {SchemaManifest.Bin2})
            UNION ALL
            SELECT 'FK_UserRole_Role', COUNT(*) FROM [{schema}].[UserRole] c
            WHERE NOT EXISTS (SELECT 1 FROM [{schema}].[Role] p WHERE p.roleValue = c.roleValue COLLATE {SchemaManifest.Bin2})
            """;

        /// <summary>What in the shape itself prevents the repair.</summary>
        public static IEnumerable<SchemaIssue> StructuralIssues(SchemaSnapshot snapshot)
        {
            foreach (var table in Tables.Select(snapshot.Table).OfType<TableShape>())
                foreach (var index in table.Indexes.Where(i => !i.PrimaryKey && i.Unique && TouchesKey(table.Name, i.Columns)))
                    yield return new SchemaIssue(IssueSeverity.Blocker, "collation-unique-index",
                        $"{snapshot.Schema}.{table.Name}: the unique index {index.Name} covers a key column; drop it by hand before the repair.");
        }

        public static string Sql(SchemaSnapshot snapshot)
        {
            var schema = snapshot.Schema;
            var sql = new StringBuilder();
            var tables = Tables.Select(snapshot.Table).OfType<TableShape>().ToList();

            foreach (var table in tables)
                foreach (var foreignKey in table.ForeignKeys)
                    sql.AppendLine($"ALTER TABLE [{schema}].[{table.Name}] DROP CONSTRAINT [{foreignKey.Name}];");

            var recreate = new List<(string Table, IndexShape Index)>();
            foreach (var table in tables)
                foreach (var index in table.Indexes.Where(i => !i.PrimaryKey && TouchesKey(table.Name, i.Columns)))
                {
                    sql.AppendLine($"DROP INDEX [{index.Name}] ON [{schema}].[{table.Name}];");
                    recreate.Add((table.Name, index));
                }

            foreach (var table in tables.Where(t => t.PrimaryKey is not null))
                sql.AppendLine($"ALTER TABLE [{schema}].[{table.Name}] DROP CONSTRAINT [{table.PrimaryKey!.Name}];");

            var manifest = SchemaManifest.Tables(1).ToDictionary(t => t.Name, StringComparer.OrdinalIgnoreCase);
            foreach (var (table, column) in KeyColumns)
            {
                var spec = manifest[table].Columns.Single(c => c.Name == column);
                sql.AppendLine($"ALTER TABLE [{schema}].[{table}] ALTER COLUMN [{column}] {spec.Type} COLLATE {SchemaManifest.Bin2} NOT NULL;");
            }

            foreach (var name in Tables)
            {
                var spec = manifest[name];
                sql.AppendLine($"ALTER TABLE [{schema}].[{name}] ADD CONSTRAINT [{spec.PrimaryKeyName}] PRIMARY KEY ({Columns(spec.PrimaryKey)});");
            }

            foreach (var name in Tables)
                foreach (var foreignKey in manifest[name].ForeignKeys)
                    sql.AppendLine($"ALTER TABLE [{schema}].[{name}] ADD CONSTRAINT [{foreignKey.Name}] FOREIGN KEY ({Columns(foreignKey.Columns)}) "
                                   + $"REFERENCES [{schema}].[{foreignKey.ReferencedTable}]({Columns(foreignKey.ReferencedColumns)})"
                                   + (foreignKey.OnDelete == "CASCADE" ? " ON DELETE CASCADE;" : ";"));

            foreach (var (table, index) in recreate)
                sql.AppendLine($"CREATE NONCLUSTERED INDEX [{index.Name}] ON [{schema}].[{table}]({Columns(index.Columns)})"
                               + (index.Filter is null ? ";" : $" WHERE {index.Filter};"));

            return sql.ToString();
        }

        private static bool TouchesKey(string table, IReadOnlyList<string> columns) =>
            KeyColumns.Any(k => string.Equals(k.Table, table, StringComparison.OrdinalIgnoreCase)
                                && columns.Contains(k.Column, StringComparer.OrdinalIgnoreCase));

        private static string Columns(IEnumerable<string> columns) => string.Join(", ", columns.Select(c => $"[{c}]"));
    }
}
