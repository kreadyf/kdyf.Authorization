namespace kdyf.Authorization.Migrations.Schema
{
    /// <summary>A column the schema must have.</summary>
    public sealed record ColumnSpec(string Name, string Type, bool Nullable = false, bool Identity = false, string? Collation = null);

    /// <summary>An index the schema must have; <see cref="Name"/> is what the steps create.</summary>
    public sealed record IndexSpec(string Name, IReadOnlyList<string> Columns, bool Unique = false, string? Filter = null);

    /// <summary>A foreign key the schema must have, with its action on delete.</summary>
    public sealed record ForeignKeySpec(string Name, IReadOnlyList<string> Columns, string ReferencedTable, IReadOnlyList<string> ReferencedColumns, string OnDelete);

    /// <summary>A table the schema must have.</summary>
    public sealed record TableSpec(
        string Name,
        IReadOnlyList<ColumnSpec> Columns,
        string PrimaryKeyName,
        IReadOnlyList<string> PrimaryKey,
        IReadOnlyList<ForeignKeySpec> ForeignKeys,
        IReadOnlyList<IndexSpec> Indexes);

    /// <summary>
    /// The shape of the schema at each version: what the steps create, what an existing database must look like to be
    /// adopted, and what <c>verify</c> checks. Version 1 is the shape the reference databases already have; the EF model of the
    /// packages is aligned to the latest version, and a test holds the two together.
    /// </summary>
    public static class SchemaManifest
    {
        /// <summary>The binary collation of role values and permission codes.</summary>
        public const string Bin2 = "Latin1_General_100_BIN2";

        /// <summary>The tables of version 1 (the six of authorization and administration).</summary>
        public static IReadOnlyList<string> TableNames { get; } = new[] { "Permission", "Role", "RolePermission", "UserRole", "PersonalAccessToken", "AuditLog" };

        /// <summary>The tables of <paramref name="version"/>: none before version 1.</summary>
        public static IReadOnlyList<TableSpec> Tables(int version)
        {
            if (version < 1)
                return Array.Empty<TableSpec>();

            var rolePermissionIndexes = version >= 2
                ? new[] { new IndexSpec("IX_RolePermission_PermissionCode", new[] { "PermissionCode" }) }
                : Array.Empty<IndexSpec>();

            return new[]
            {
                new TableSpec("Permission",
                    new[]
                    {
                        new ColumnSpec("PermissionCode", "varchar(50)", Collation: Bin2),
                        new ColumnSpec("name", "nvarchar(100)", Nullable: true),
                        new ColumnSpec("description", "nvarchar(200)", Nullable: true),
                    },
                    "PK_Permission", new[] { "PermissionCode" },
                    Array.Empty<ForeignKeySpec>(), Array.Empty<IndexSpec>()),

                new TableSpec("Role",
                    new[]
                    {
                        new ColumnSpec("roleValue", "varchar(100)", Collation: Bin2),
                        new ColumnSpec("name", "nvarchar(200)"),
                        new ColumnSpec("description", "nvarchar(500)", Nullable: true),
                        new ColumnSpec("createdAt", "datetime2(7)"),
                    },
                    "PK_Role", new[] { "roleValue" },
                    Array.Empty<ForeignKeySpec>(), Array.Empty<IndexSpec>()),

                new TableSpec("RolePermission",
                    new[]
                    {
                        new ColumnSpec("roleValue", "varchar(100)", Collation: Bin2),
                        new ColumnSpec("PermissionCode", "varchar(50)", Collation: Bin2),
                    },
                    "PK_RolePermission", new[] { "roleValue", "PermissionCode" },
                    new[]
                    {
                        new ForeignKeySpec("FK_RolePermission_Role", new[] { "roleValue" }, "Role", new[] { "roleValue" }, "CASCADE"),
                        new ForeignKeySpec("FK_RolePermission_Permission", new[] { "PermissionCode" }, "Permission", new[] { "PermissionCode" }, "NO_ACTION"),
                    },
                    rolePermissionIndexes),

                new TableSpec("UserRole",
                    new[]
                    {
                        // Lower-case GUID text, normalised by the code: no binary collation, as in the reference databases.
                        new ColumnSpec("objectId", "varchar(50)"),
                        new ColumnSpec("roleValue", "varchar(100)", Collation: Bin2),
                    },
                    "PK_UserRole", new[] { "objectId", "roleValue" },
                    new[] { new ForeignKeySpec("FK_UserRole_Role", new[] { "roleValue" }, "Role", new[] { "roleValue" }, "NO_ACTION") },
                    new[] { new IndexSpec("IX_UserRole_Role", new[] { "roleValue" }) }),

                new TableSpec("PersonalAccessToken",
                    new[]
                    {
                        new ColumnSpec("PersonalAccessTokenId", "int", Identity: true),
                        new ColumnSpec("name", "nvarchar(100)"),
                        new ColumnSpec("tokenHash", "varbinary(32)"),
                        new ColumnSpec("tokenPrefix", "nvarchar(12)", Nullable: true),
                        new ColumnSpec("ownerObjectId", "nvarchar(50)"),
                        new ColumnSpec("ownerLabel", "nvarchar(256)"),
                        new ColumnSpec("isActive", "bit"),
                        new ColumnSpec("expiresAt", "datetime2(7)", Nullable: true),
                        new ColumnSpec("createdAt", "datetime2(7)"),
                        new ColumnSpec("lastUsedAt", "datetime2(7)", Nullable: true),
                    },
                    "PK_PersonalAccessToken", new[] { "PersonalAccessTokenId" },
                    Array.Empty<ForeignKeySpec>(),
                    new[]
                    {
                        // A unique constraint or a unique index: both are a unique index in the catalog.
                        new IndexSpec("UQ_PersonalAccessToken_Hash", new[] { "tokenHash" }, Unique: true),
                        new IndexSpec("IX_PersonalAccessToken_Owner", new[] { "ownerObjectId" }),
                    }),

                new TableSpec("AuditLog",
                    new[]
                    {
                        new ColumnSpec("AuditLogId", "bigint", Identity: true),
                        new ColumnSpec("occurredAt", "datetime2(7)"),
                        new ColumnSpec("actorObjectId", "nvarchar(50)", Nullable: true),
                        new ColumnSpec("actorEmail", "nvarchar(256)"),
                        new ColumnSpec("action", "varchar(40)"),
                        new ColumnSpec("targetType", "varchar(20)"),
                        new ColumnSpec("targetId", "nvarchar(100)", Nullable: true),
                        new ColumnSpec("targetLabel", "nvarchar(256)"),
                        new ColumnSpec("details", "nvarchar(max)", Nullable: true),
                    },
                    "PK_AuditLog", new[] { "AuditLogId" },
                    Array.Empty<ForeignKeySpec>(),
                    new[]
                    {
                        new IndexSpec("IX_AuditLog_Target", new[] { "targetType", "targetId" }),
                        new IndexSpec("IX_AuditLog_OccurredAt", new[] { "occurredAt" }),
                        new IndexSpec("IX_AuditLog_ActorObjectId", new[] { "actorObjectId" }),
                    }),
            }.Concat(version >= 4 ? new[] { UserProfile } : Array.Empty<TableSpec>()).ToArray();
        }

        /// <summary>
        /// Version 4: one row per person the application knows, keyed by their Entra object id. No row means an active
        /// person, so a host that never writes here behaves as before.
        /// </summary>
        private static TableSpec UserProfile { get; } = new("UserProfile",
            new[]
            {
                new ColumnSpec("objectId", "varchar(50)"),
                new ColumnSpec("legacyUserId", "int", Nullable: true),
                new ColumnSpec("email", "nvarchar(256)", Nullable: true),
                new ColumnSpec("displayName", "nvarchar(200)", Nullable: true),
                new ColumnSpec("isActive", "bit"),
                new ColumnSpec("createdAt", "datetime2(7)"),
                new ColumnSpec("lastLoginAt", "datetime2(7)", Nullable: true),
            },
            "PK_UserProfile", new[] { "objectId" },
            Array.Empty<ForeignKeySpec>(),
            new[] { new IndexSpec("UQ_UserProfile_LegacyUserId", new[] { "legacyUserId" }, Unique: true, Filter: "legacyUserId IS NOT NULL") });

        /// <summary>
        /// What the runtime role may do on each table at <paramref name="version"/>. The history tables are granted
        /// (read-only) or denied from version 0.
        /// </summary>
        /// <remarks>
        /// <c>Permission</c> gets <c>DELETE</c>: the administration removes an undeclared code once nobody is granted it.
        /// <c>AuditLog</c> is insert-only: the application cannot rewrite who did what.
        /// </remarks>
        public static IReadOnlyDictionary<string, string[]> Grants(int version)
        {
            var grants = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
            {
                [SchemaHistory.VersionTable] = new[] { "SELECT" },
            };
            if (version >= 3)
            {
                var all = new[] { "SELECT", "INSERT", "UPDATE", "DELETE" };
                grants["Permission"] = all;
                grants["Role"] = all;
                grants["RolePermission"] = all;
                grants["UserRole"] = all;
                grants["PersonalAccessToken"] = all;
                grants["AuditLog"] = new[] { "SELECT", "INSERT" };
            }
            if (version >= 4)
                grants["UserProfile"] = new[] { "SELECT", "INSERT", "UPDATE", "DELETE" };
            return grants;
        }

        /// <summary>What the runtime role is explicitly denied: writing the history, and touching the run log at all.</summary>
        public static IReadOnlyDictionary<string, string[]> Denies(int version)
        {
            var denies = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
            {
                [SchemaHistory.VersionTable] = new[] { "INSERT", "UPDATE", "DELETE" },
                [SchemaHistory.LogTable] = new[] { "SELECT", "INSERT", "UPDATE", "DELETE" },
                [SchemaHistory.MarkerTable] = new[] { "INSERT", "UPDATE", "DELETE" },
            };
            if (version >= 3)
                denies["AuditLog"] = new[] { "UPDATE", "DELETE" };
            return denies;
        }
    }
}
