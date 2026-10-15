using System.Data.Common;

namespace kdyf.Authorization.Migrations.Schema
{
    /// <summary>A column as SQL Server describes it: the declared type as it would be written in DDL.</summary>
    public sealed record ColumnShape(string Name, string Type, bool Nullable, bool Identity, string? Collation);

    /// <summary>An index, a primary key or a unique constraint: SQL Server keeps all three in <c>sys.indexes</c>.</summary>
    public sealed record IndexShape(string Name, IReadOnlyList<string> Columns, bool PrimaryKey, bool Unique, string? Filter);

    /// <summary>A foreign key, with the action on delete (<c>NO_ACTION</c>, <c>CASCADE</c>…).</summary>
    public sealed record ForeignKeyShape(
        string Name, IReadOnlyList<string> Columns, string ReferencedSchema, string ReferencedTable,
        IReadOnlyList<string> ReferencedColumns, string OnDelete);

    /// <summary>A table of the schema, as it is.</summary>
    public sealed record TableShape(
        string Name,
        IReadOnlyList<ColumnShape> Columns,
        IReadOnlyList<IndexShape> Indexes,
        IReadOnlyList<ForeignKeyShape> ForeignKeys)
    {
        public ColumnShape? Column(string name) =>
            Columns.FirstOrDefault(c => string.Equals(c.Name, name, StringComparison.OrdinalIgnoreCase));

        public IndexShape? PrimaryKey => Indexes.FirstOrDefault(i => i.PrimaryKey);
    }

    /// <summary>
    /// What one schema of the database holds, read from the catalog (<c>sys.*</c>): never deduced from a model or from
    /// the name of a table. Two databases with tables of the same names can have different shapes, and only the
    /// catalog tells them apart.
    /// </summary>
    public sealed class SchemaSnapshot
    {
        public SchemaSnapshot(
            string schema, bool exists, IReadOnlyDictionary<string, TableShape> tables,
            IReadOnlyDictionary<string, IReadOnlySet<string>> grants, IReadOnlyDictionary<string, IReadOnlySet<string>> denies,
            bool roleExists)
        {
            Schema = schema;
            Exists = exists;
            Tables = tables;
            Grants = grants;
            Denies = denies;
            RoleExists = roleExists;
        }

        public string Schema { get; }

        public bool Exists { get; }

        /// <summary>The tables, by name (case-insensitive, as SQL Server resolves them).</summary>
        public IReadOnlyDictionary<string, TableShape> Tables { get; }

        /// <summary>What the runtime role is granted, per table: <c>SELECT</c>, <c>INSERT</c>…</summary>
        public IReadOnlyDictionary<string, IReadOnlySet<string>> Grants { get; }

        /// <summary>What the runtime role is denied, per table.</summary>
        public IReadOnlyDictionary<string, IReadOnlySet<string>> Denies { get; }

        /// <summary>Whether the runtime role exists in the database.</summary>
        public bool RoleExists { get; }

        public TableShape? Table(string name) => Tables.TryGetValue(name, out var table) ? table : null;

        /// <summary>Reads the schema from the catalog, inside <paramref name="transaction"/> when there is one.</summary>
        internal static async Task<SchemaSnapshot> ReadAsync(
            DbConnection connection, DbTransaction? transaction, string schema, string runtimeRole, CancellationToken cancellationToken)
        {
            var exists = await ScalarAsync(connection, transaction, "SELECT COUNT(*) FROM sys.schemas WHERE name = @schema", schema, cancellationToken) > 0;
            var roleExists = await ScalarAsync(connection, transaction,
                "SELECT COUNT(*) FROM sys.database_principals WHERE name = @schema AND type = 'R'", runtimeRole, cancellationToken) > 0;

            var columns = new Dictionary<string, List<ColumnShape>>(StringComparer.OrdinalIgnoreCase);
            await ReadAsync(connection, transaction, ColumnsSql, schema, cancellationToken, r =>
            {
                var table = r.GetString(0);
                var type = TypeName(r.GetString(2), r.GetInt16(3), r.GetByte(4), r.GetByte(5));
                Add(columns, table, new ColumnShape(r.GetString(1), type, r.GetBoolean(6), r.GetBoolean(8), r.IsDBNull(7) ? null : r.GetString(7)));
            });

            var indexes = new Dictionary<string, List<IndexShape>>(StringComparer.OrdinalIgnoreCase);
            var indexColumns = new Dictionary<(string Table, string Index), (IndexShape Shape, List<string> Columns)>();
            await ReadAsync(connection, transaction, IndexesSql, schema, cancellationToken, r =>
            {
                var key = (r.GetString(0), r.GetString(1));
                if (!indexColumns.TryGetValue(key, out var entry))
                {
                    var list = new List<string>();
                    entry = (new IndexShape(key.Item2, list, r.GetBoolean(2), r.GetBoolean(3), r.IsDBNull(4) ? null : r.GetString(4)), list);
                    indexColumns[key] = entry;
                    Add(indexes, key.Item1, entry.Shape);
                }
                entry.Columns.Add(r.GetString(5));
            });

            var foreignKeys = new Dictionary<string, List<ForeignKeyShape>>(StringComparer.OrdinalIgnoreCase);
            var fkColumns = new Dictionary<string, (List<string> Columns, List<string> Referenced)>(StringComparer.OrdinalIgnoreCase);
            await ReadAsync(connection, transaction, ForeignKeysSql, schema, cancellationToken, r =>
            {
                var name = r.GetString(0);
                if (!fkColumns.TryGetValue(name, out var entry))
                {
                    entry = (new List<string>(), new List<string>());
                    fkColumns[name] = entry;
                    Add(foreignKeys, r.GetString(1), new ForeignKeyShape(name, entry.Columns, r.GetString(2), r.GetString(3), entry.Referenced, r.GetString(4)));
                }
                entry.Columns.Add(r.GetString(5));
                entry.Referenced.Add(r.GetString(6));
            });

            var tables = columns.ToDictionary(
                c => c.Key,
                c => new TableShape(
                    c.Key,
                    c.Value,
                    indexes.TryGetValue(c.Key, out var i) ? i : new List<IndexShape>(),
                    foreignKeys.TryGetValue(c.Key, out var f) ? f : new List<ForeignKeyShape>()),
                StringComparer.OrdinalIgnoreCase);

            var grants = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
            var denies = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
            await ReadAsync(connection, transaction, PermissionsSql, schema, cancellationToken, r =>
            {
                var target = r.GetString(1) == "D" ? denies : grants;
                if (!string.Equals(r.GetString(3), runtimeRole, StringComparison.OrdinalIgnoreCase))
                    return;
                if (!target.TryGetValue(r.GetString(0), out var set))
                    target[r.GetString(0)] = set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                set.Add(r.GetString(2));
            });

            return new SchemaSnapshot(
                schema, exists, tables,
                grants.ToDictionary(g => g.Key, g => (IReadOnlySet<string>)g.Value, StringComparer.OrdinalIgnoreCase),
                denies.ToDictionary(g => g.Key, g => (IReadOnlySet<string>)g.Value, StringComparer.OrdinalIgnoreCase),
                roleExists);
        }

        /// <summary>The type as DDL writes it: <c>nvarchar(50)</c>, not the 100 bytes the catalog stores.</summary>
        internal static string TypeName(string type, short maxLength, byte precision, byte scale) => type switch
        {
            "nvarchar" or "nchar" => $"{type}({(maxLength == -1 ? "max" : (maxLength / 2).ToString())})",
            "varchar" or "char" or "varbinary" or "binary" => $"{type}({(maxLength == -1 ? "max" : maxLength.ToString())})",
            "datetime2" or "datetimeoffset" or "time" => $"{type}({scale})",
            "decimal" or "numeric" => $"{type}({precision},{scale})",
            _ => type,
        };

        private static void Add<T>(Dictionary<string, List<T>> map, string key, T value)
        {
            if (!map.TryGetValue(key, out var list))
                map[key] = list = new List<T>();
            list.Add(value);
        }

        private static async Task<int> ScalarAsync(
            DbConnection connection, DbTransaction? transaction, string sql, string parameter, CancellationToken cancellationToken)
        {
            await using var command = Command(connection, transaction, sql, parameter);
            return Convert.ToInt32(await command.ExecuteScalarAsync(cancellationToken));
        }

        private static async Task ReadAsync(
            DbConnection connection, DbTransaction? transaction, string sql, string schema, CancellationToken cancellationToken,
            Action<DbDataReader> row)
        {
            await using var command = Command(connection, transaction, sql, schema);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
                row(reader);
        }

        private static DbCommand Command(DbConnection connection, DbTransaction? transaction, string sql, string schema)
        {
            var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = sql;
            var parameter = command.CreateParameter();
            parameter.ParameterName = "@schema";
            parameter.Value = schema;
            command.Parameters.Add(parameter);
            return command;
        }

        private const string ColumnsSql = """
            SELECT t.name, c.name, ty.name, c.max_length, c.precision, c.scale, c.is_nullable, c.collation_name, c.is_identity
            FROM sys.tables t
            JOIN sys.schemas s ON s.schema_id = t.schema_id
            JOIN sys.columns c ON c.object_id = t.object_id
            JOIN sys.types ty ON ty.user_type_id = c.user_type_id
            WHERE s.name = @schema
            ORDER BY t.name, c.column_id
            """;

        private const string IndexesSql = """
            SELECT t.name, i.name, i.is_primary_key, CAST(i.is_unique AS bit), i.filter_definition, c.name
            FROM sys.indexes i
            JOIN sys.tables t ON t.object_id = i.object_id
            JOIN sys.schemas s ON s.schema_id = t.schema_id
            JOIN sys.index_columns ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id
            JOIN sys.columns c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
            WHERE s.name = @schema AND i.type > 0 AND ic.is_included_column = 0
            ORDER BY t.name, i.name, ic.key_ordinal
            """;

        private const string ForeignKeysSql = """
            SELECT fk.name, tp.name, rs.name, rt.name, fk.delete_referential_action_desc, pc.name, rc.name
            FROM sys.foreign_keys fk
            JOIN sys.tables tp ON tp.object_id = fk.parent_object_id
            JOIN sys.schemas s ON s.schema_id = tp.schema_id
            JOIN sys.tables rt ON rt.object_id = fk.referenced_object_id
            JOIN sys.schemas rs ON rs.schema_id = rt.schema_id
            JOIN sys.foreign_key_columns fkc ON fkc.constraint_object_id = fk.object_id
            JOIN sys.columns pc ON pc.object_id = fkc.parent_object_id AND pc.column_id = fkc.parent_column_id
            JOIN sys.columns rc ON rc.object_id = fkc.referenced_object_id AND rc.column_id = fkc.referenced_column_id
            WHERE s.name = @schema
            ORDER BY fk.name, fkc.constraint_column_id
            """;

        // Object-level permissions only (minor_id = 0), on the tables of the schema.
        private const string PermissionsSql = """
            SELECT o.name, p.state, p.permission_name, pr.name
            FROM sys.database_permissions p
            JOIN sys.objects o ON o.object_id = p.major_id
            JOIN sys.schemas s ON s.schema_id = o.schema_id
            JOIN sys.database_principals pr ON pr.principal_id = p.grantee_principal_id
            WHERE p.class = 1 AND p.minor_id = 0 AND s.name = @schema
            """;
    }
}
