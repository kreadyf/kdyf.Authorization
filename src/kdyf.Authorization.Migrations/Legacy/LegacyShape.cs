using kdyf.Authorization.Migrations.Schema;

namespace kdyf.Authorization.Migrations.Legacy
{
    /// <summary>Which of the legacy kdyf.auth.* shapes a schema has, and whether it can be imported.</summary>
    /// <param name="Label">A (2026-07-14), B (07-15), B′ (B + 07-22 scripts), C (07-27, final), K0 (a host's first model).</param>
    /// <param name="Supported">Whether it can be imported.</param>
    /// <param name="Description">What it is, for a person.</param>
    /// <param name="Notes">What else the catalog shows (an EF-created table, a missing index).</param>
    public sealed record LegacyShape(string Label, bool Supported, string Description, IReadOnlyList<string> Notes);

    /// <summary>
    /// Tells the legacy shapes apart from the catalog, by what each history step added or removed:
    /// <list type="bullet">
    /// <item><b>A</b>: <c>Permission.Code</c>, <c>User.AzureObjectId</c> (uniqueidentifier), PascalCase, five tables. Not
    /// supported: no database is known to still have it.</item>
    /// <item><b>B</b>: lower-case columns, <c>objectId nvarchar(50)</c>, tokens with <c>PersonalAccessTokenRole</c>, no audit log.</item>
    /// <item><b>B′</b>: B plus the audit log and <c>IX_PersonalAccessToken_UserId</c>; <c>PersonalAccessTokenRole</c> may remain.</item>
    /// <item><b>C</b>: seven tables, no <c>PersonalAccessTokenRole</c>: the final script, in every repository today.</item>
    /// <item><b>K0</b>: a host before its alignment: <c>objectId nvarchar(100)</c>, with or without tokens and audit log.</item>
    /// </list>
    /// </summary>
    public static class LegacyShapes
    {
        public static LegacyShape Classify(SchemaSnapshot snapshot)
        {
            var notes = new List<string>();
            var user = snapshot.Table("User");
            var permission = snapshot.Table("Permission");
            var token = snapshot.Table("PersonalAccessToken");
            var tokenRoles = snapshot.Table("PersonalAccessTokenRole");
            var audit = snapshot.Table("AuditLog");

            if (user is null || snapshot.Table("Role")?.Column("RoleId") is null || snapshot.Table("UserRole") is null || snapshot.Table("RolePermission") is null)
                return new("?", false, "Not a legacy kdyf.auth.* schema: it needs User, Role (RoleId), UserRole and RolePermission.", notes);

            if (permission?.Column("Code") is not null || user.Column("AzureObjectId") is not null)
                return new("A", false,
                    "The first legacy shape (Permission.Code, User.AzureObjectId). Bring it to the final script (auth-schema.sql) by hand before importing.", notes);

            var objectId = user.Column("objectId");
            if (objectId is null)
                return new("?", false, "User has no objectId column.", notes);

            if (audit?.Column("action") is { } action && action.Type.StartsWith("nvarchar", StringComparison.OrdinalIgnoreCase))
                notes.Add("The audit log was created by EF (action nvarchar): copied as it is.");
            if (user.Indexes.All(i => !i.Columns.Contains("objectId", StringComparer.OrdinalIgnoreCase)))
                notes.Add("No index on User.objectId (created by EF?): duplicated object ids are possible, and checked.");

            if (objectId.Type.Equals("nvarchar(100)", StringComparison.OrdinalIgnoreCase))
                return new("K0", true,
                    "a host before its alignment (objectId nvarchar(100))" + (token is null ? ", without tokens" : "") + (audit is null ? ", without audit log" : "") + ".", notes);

            if (tokenRoles is not null)
            {
                notes.Add("PersonalAccessTokenRole is present: a token limited to some roles would hold everything its owner holds after the import. Those tokens are checked.");
                return audit is null
                    ? new("B", true, "Tokens limited to roles (PersonalAccessTokenRole), no audit log: imported without history.", notes)
                    : new("B′", true, "B plus the audit log; PersonalAccessTokenRole was not dropped.", notes);
            }

            return token is null || audit is null
                ? new("C?", true, "Like the final script but without " + (token is null ? "tokens" : "the audit log") + ": imported with what there is.", notes)
                : new("C", true, "The final legacy script: seven tables.", notes);
        }
    }
}
