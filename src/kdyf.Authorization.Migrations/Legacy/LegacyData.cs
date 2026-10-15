using System.Data.Common;
using kdyf.Authorization.Migrations.Schema;

namespace kdyf.Authorization.Migrations.Legacy
{
    public sealed record LegacyUser(int UserId, string Email, string? ObjectId, string? DisplayName, bool IsActive, DateTime? CreatedAt = null);

    public sealed record LegacyUserRole(int UserId, int RoleId);

    public sealed record LegacyGrant(int RoleId, string PermissionCode);

    /// <summary>A token limited to a role (shape B): <c>PersonalAccessTokenRole</c>.</summary>
    public sealed record LegacyTokenRole(int TokenId, int RoleId);

    public sealed record LegacyToken(int Id, string Name, byte[] TokenHash, string? TokenPrefix, int UserId, bool IsActive, DateTime? ExpiresAt,
        DateTime? CreatedAt = null, DateTime? LastUsedAt = null);

    /// <summary>A reference to the legacy tables from outside them: a foreign key, or a column named like a legacy id.</summary>
    public sealed record ExternalReference(string Table, string Column, string Kind);

    /// <summary>
    /// The rows of a legacy kdyf.auth.* schema, read once, whole: they are a few hundred rows (the audit log is only
    /// counted). Column names that changed between the legacy versions are found by their alternatives.
    /// </summary>
    public sealed class LegacyData
    {
        public required string Schema { get; init; }
        public required IReadOnlyList<LegacyUser> Users { get; init; }
        public required IReadOnlyList<LegacyRole> Roles { get; init; }
        public required IReadOnlyList<LegacyGrant> Grants { get; init; }
        public required IReadOnlyList<LegacyUserRole> UserRoles { get; init; }
        public required IReadOnlyList<LegacyToken> Tokens { get; init; }
        public required IReadOnlyList<LegacyTokenRole> TokenRoles { get; init; }
        public required IReadOnlyList<string> CatalogCodes { get; init; }
        public required int AuditLogCount { get; init; }
        public required long? AuditLogMaxId { get; init; }
        public required IReadOnlyList<ExternalReference> ExternalReferences { get; init; }

        internal static async Task<LegacyData> ReadAsync(DbConnection connection, SchemaSnapshot snapshot, CancellationToken cancellationToken)
        {
            var s = snapshot.Schema;
            string Column(string table, params string[] names) =>
                names.FirstOrDefault(n => snapshot.Table(table)?.Column(n) is not null)
                ?? throw new InvalidOperationException($"{s}.{table} has none of the columns {string.Join(", ", names)}.");
            string? Optional(string table, params string[] names) => names.FirstOrDefault(n => snapshot.Table(table)?.Column(n) is not null);

            var users = await ListAsync(connection,
                $"SELECT [{Column("User", "UserId")}], [{Column("User", "email", "Email")}], [{Column("User", "objectId", "AzureObjectId", "ObjectId")}], "
                + $"{Nullable(Optional("User", "displayName", "DisplayName"))}, {Nullable(Optional("User", "isActive", "IsActive"), "CAST(1 AS bit)")}, "
                + $"{Nullable(Optional("User", "createdAt", "CreatedAt"))} FROM [{s}].[User]",
                r => new LegacyUser(r.GetInt32(0), r.GetString(1), Text(r, 2), Text(r, 3), r.GetBoolean(4), r.IsDBNull(5) ? null : r.GetDateTime(5)), cancellationToken);

            var roles = await ListAsync(connection,
                $"SELECT [{Column("Role", "RoleId")}], [{Column("Role", "name", "Name")}], {Nullable(Optional("Role", "description", "Description"))} FROM [{s}].[Role]",
                r => new LegacyRole(r.GetInt32(0), r.GetString(1), Text(r, 2)), cancellationToken);

            var grants = await ListAsync(connection,
                $"SELECT [{Column("RolePermission", "RoleId")}], [{Column("RolePermission", "PermissionCode", "Code")}] FROM [{s}].[RolePermission]",
                r => new LegacyGrant(r.GetInt32(0), r.GetString(1)), cancellationToken);

            var userRoles = await ListAsync(connection,
                $"SELECT [{Column("UserRole", "UserId")}], [{Column("UserRole", "RoleId")}] FROM [{s}].[UserRole]",
                r => new LegacyUserRole(r.GetInt32(0), r.GetInt32(1)), cancellationToken);

            var catalog = snapshot.Table("Permission") is null
                ? new List<string>()
                : await ListAsync(connection, $"SELECT [{Column("Permission", "PermissionCode", "Code")}] FROM [{s}].[Permission]", r => r.GetString(0), cancellationToken);

            var tokens = snapshot.Table("PersonalAccessToken") is null
                ? new List<LegacyToken>()
                : await ListAsync(connection,
                    $"SELECT [{Column("PersonalAccessToken", "PersonalAccessTokenId")}], [{Column("PersonalAccessToken", "name", "Name")}], "
                    + $"[{Column("PersonalAccessToken", "tokenHash", "TokenHash")}], {Nullable(Optional("PersonalAccessToken", "tokenPrefix", "TokenPrefix"))}, "
                    + $"[{Column("PersonalAccessToken", "userId", "UserId")}], [{Column("PersonalAccessToken", "isActive", "IsActive")}], "
                    + $"{Nullable(Optional("PersonalAccessToken", "expiresAt", "ExpiresAt"))}, {Nullable(Optional("PersonalAccessToken", "createdAt", "CreatedAt"))}, "
                    + $"{Nullable(Optional("PersonalAccessToken", "lastUsedAt", "LastUsedAt"))} FROM [{s}].[PersonalAccessToken]",
                    r => new LegacyToken(r.GetInt32(0), r.GetString(1), (byte[])r.GetValue(2), Text(r, 3), r.GetInt32(4), r.GetBoolean(5),
                        r.IsDBNull(6) ? null : r.GetDateTime(6), r.IsDBNull(7) ? null : r.GetDateTime(7), r.IsDBNull(8) ? null : r.GetDateTime(8)), cancellationToken);

            var tokenRoles = snapshot.Table("PersonalAccessTokenRole") is null
                ? new List<LegacyTokenRole>()
                : await ListAsync(connection, $"SELECT [PersonalAccessTokenId], [RoleId] FROM [{s}].[PersonalAccessTokenRole]",
                    r => new LegacyTokenRole(r.GetInt32(0), r.GetInt32(1)), cancellationToken);

            var (count, max) = snapshot.Table("AuditLog") is null
                ? (0, (long?)null)
                : (await ListAsync(connection, $"SELECT COUNT(*), MAX(CAST([{Column("AuditLog", "AuditLogId")}] AS BIGINT)) FROM [{s}].[AuditLog]",
                    r => (r.GetInt32(0), r.IsDBNull(1) ? (long?)null : r.GetInt64(1)), cancellationToken)).Single();

            // Who else points at these tables: foreign keys from other schemas, and columns named like the legacy ids.
            var external = await ListAsync(connection, $"""
                SELECT OBJECT_SCHEMA_NAME(fk.parent_object_id) + '.' + OBJECT_NAME(fk.parent_object_id), COL_NAME(fkc.parent_object_id, fkc.parent_column_id), 'foreign key ' + fk.name
                FROM sys.foreign_keys fk JOIN sys.foreign_key_columns fkc ON fkc.constraint_object_id = fk.object_id
                WHERE OBJECT_SCHEMA_NAME(fk.referenced_object_id) = N'{s}' AND OBJECT_SCHEMA_NAME(fk.parent_object_id) <> N'{s}'
                UNION ALL
                SELECT SCHEMA_NAME(t.schema_id) + '.' + t.name, c.name, 'column'
                FROM sys.columns c JOIN sys.tables t ON t.object_id = c.object_id
                WHERE SCHEMA_NAME(t.schema_id) NOT IN (N'{s}', 'sys') AND (c.name LIKE '%RoleId' OR c.name LIKE '%UserId')
                """, r => new ExternalReference(r.GetString(0), r.GetString(1), r.GetString(2)), cancellationToken);

            return new LegacyData
            {
                Schema = s, Users = users, Roles = roles, Grants = grants, UserRoles = userRoles, Tokens = tokens, TokenRoles = tokenRoles,
                CatalogCodes = catalog, AuditLogCount = count, AuditLogMaxId = max, ExternalReferences = external,
            };
        }

        private static string Nullable(string? column, string otherwise = "NULL") => column is null ? otherwise : $"[{column}]";

        private static string? Text(DbDataReader reader, int ordinal) => reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);

        private static async Task<List<T>> ListAsync<T>(DbConnection connection, string sql, Func<DbDataReader, T> row, CancellationToken cancellationToken)
        {
            await using var command = connection.CreateCommand();
            command.CommandText = sql;
            var list = new List<T>();
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
                list.Add(row(reader));
            return list;
        }
    }
}
