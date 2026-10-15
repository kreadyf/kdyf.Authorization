using System.Security.Cryptography;
using System.Text;

namespace kdyf.Authorization.Migrations.Schema
{
    /// <summary>
    /// One step of the schema: a version number, a stable id and the SQL that takes the schema from the previous version
    /// to this one. The SQL is a template (<c>{schema}</c>, <c>{role}</c>) and its checksum is computed on the template,
    /// so the same step has the same checksum in every database, whatever its schema is called.
    /// </summary>
    /// <remarks>
    /// A step never changes once released: the history keeps its checksum, and <c>verify</c> reports a step whose code
    /// no longer matches what was applied. A change is a new step. Steps widen, they do not break: an application one
    /// version behind keeps working on a schema one version ahead.
    /// </remarks>
    internal abstract class MigrationStep
    {
        /// <summary>The version the schema is at once this step is applied.</summary>
        public abstract int Version { get; }

        /// <summary>Stable id, <c>0001-tables</c>: never renamed.</summary>
        public abstract string Id { get; }

        public abstract string Description { get; }

        /// <summary>Whether an existing database can have this step stamped as adopted instead of applied.</summary>
        public virtual bool Adoptable => false;

        protected abstract string Template { get; }

        public string Checksum => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Template.ReplaceLineEndings("\n")))).ToLowerInvariant();

        public string Sql(string schema, string role) => Template.Replace("{schema}", schema).Replace("{role}", role);
    }

    /// <summary>The runtime role, and what it may do on the history: read the version, write nothing.</summary>
    internal sealed class RuntimeRoleStep : MigrationStep
    {
        public override int Version => 0;
        public override string Id => "0000-runtime-role";
        public override string Description => "The runtime role of the application; the history is read-only for it.";

        protected override string Template => """
            IF DATABASE_PRINCIPAL_ID(N'{role}') IS NULL CREATE ROLE [{role}] AUTHORIZATION dbo;
            GRANT SELECT ON [{schema}].[SchemaVersion] TO [{role}];
            DENY INSERT, UPDATE, DELETE ON [{schema}].[SchemaVersion] TO [{role}];
            DENY SELECT, INSERT, UPDATE, DELETE ON [{schema}].[SchemaMigrationLog] TO [{role}];
            DENY INSERT, UPDATE, DELETE ON [{schema}].[SchemaMarker] TO [{role}];
            """;
    }

    /// <summary>
    /// Version 1: the six tables, as mtcm's databases already have them. An existing database with this shape is
    /// adopted: stamped, not rebuilt.
    /// </summary>
    internal sealed class TablesStep : MigrationStep
    {
        public override int Version => 1;
        public override string Id => "0001-tables";
        public override string Description => "The tables of authorization and administration (version 1).";
        public override bool Adoptable => true;

        protected override string Template => """
            CREATE TABLE [{schema}].[Permission] (
                PermissionCode VARCHAR(50)   COLLATE Latin1_General_100_BIN2 NOT NULL CONSTRAINT PK_Permission PRIMARY KEY,
                name           NVARCHAR(100) NULL,
                description    NVARCHAR(200) NULL
            );

            CREATE TABLE [{schema}].[Role] (
                roleValue   VARCHAR(100)  COLLATE Latin1_General_100_BIN2 NOT NULL CONSTRAINT PK_Role PRIMARY KEY,
                name        NVARCHAR(200) NOT NULL,
                description NVARCHAR(500) NULL,
                createdAt   DATETIME2     NOT NULL CONSTRAINT DF_Role_CreatedAt DEFAULT SYSUTCDATETIME()
            );

            CREATE TABLE [{schema}].[RolePermission] (
                roleValue      VARCHAR(100) COLLATE Latin1_General_100_BIN2 NOT NULL,
                PermissionCode VARCHAR(50)  COLLATE Latin1_General_100_BIN2 NOT NULL,
                CONSTRAINT PK_RolePermission PRIMARY KEY (roleValue, PermissionCode),
                CONSTRAINT FK_RolePermission_Role FOREIGN KEY (roleValue) REFERENCES [{schema}].[Role](roleValue) ON DELETE CASCADE,
                CONSTRAINT FK_RolePermission_Permission FOREIGN KEY (PermissionCode) REFERENCES [{schema}].[Permission](PermissionCode)
            );

            CREATE TABLE [{schema}].[UserRole] (
                objectId  VARCHAR(50)  NOT NULL,
                roleValue VARCHAR(100) COLLATE Latin1_General_100_BIN2 NOT NULL,
                CONSTRAINT PK_UserRole PRIMARY KEY (objectId, roleValue),
                CONSTRAINT FK_UserRole_Role FOREIGN KEY (roleValue) REFERENCES [{schema}].[Role](roleValue)
            );
            CREATE NONCLUSTERED INDEX IX_UserRole_Role ON [{schema}].[UserRole](roleValue);

            CREATE TABLE [{schema}].[PersonalAccessToken] (
                PersonalAccessTokenId INT IDENTITY(1,1) NOT NULL CONSTRAINT PK_PersonalAccessToken PRIMARY KEY,
                name                  NVARCHAR(100)     NOT NULL,
                tokenHash             VARBINARY(32)     NOT NULL CONSTRAINT UQ_PersonalAccessToken_Hash UNIQUE,
                tokenPrefix           NVARCHAR(12)      NULL,
                ownerObjectId         NVARCHAR(50)      NOT NULL,
                ownerLabel            NVARCHAR(256)     NOT NULL,
                isActive              BIT               NOT NULL CONSTRAINT DF_PersonalAccessToken_IsActive DEFAULT 1,
                expiresAt             DATETIME2         NULL,
                createdAt             DATETIME2         NOT NULL CONSTRAINT DF_PersonalAccessToken_CreatedAt DEFAULT SYSUTCDATETIME(),
                lastUsedAt            DATETIME2         NULL
            );
            CREATE NONCLUSTERED INDEX IX_PersonalAccessToken_Owner ON [{schema}].[PersonalAccessToken](ownerObjectId);

            CREATE TABLE [{schema}].[AuditLog] (
                AuditLogId    BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_AuditLog PRIMARY KEY,
                occurredAt    DATETIME2     NOT NULL CONSTRAINT DF_AuditLog_OccurredAt DEFAULT SYSUTCDATETIME(),
                actorObjectId NVARCHAR(50)  NULL,
                actorEmail    NVARCHAR(256) NOT NULL,
                action        VARCHAR(40)   NOT NULL,
                targetType    VARCHAR(20)   NOT NULL,
                targetId      NVARCHAR(100) NULL,
                targetLabel   NVARCHAR(256) NOT NULL,
                details       NVARCHAR(MAX) NULL
            );
            CREATE NONCLUSTERED INDEX IX_AuditLog_Target        ON [{schema}].[AuditLog](targetType, targetId);
            CREATE NONCLUSTERED INDEX IX_AuditLog_OccurredAt    ON [{schema}].[AuditLog](occurredAt);
            CREATE NONCLUSTERED INDEX IX_AuditLog_ActorObjectId ON [{schema}].[AuditLog](actorObjectId);
            """;
    }

    /// <summary>
    /// Version 2: the index behind <c>FK_RolePermission_Permission</c>. Deleting a catalog row checks that no role grants
    /// it; without the index that is a scan of every grant.
    /// </summary>
    internal sealed class RolePermissionIndexStep : MigrationStep
    {
        public override int Version => 2;
        public override string Id => "0002-rolepermission-permissioncode-index";
        public override string Description => "Index IX_RolePermission_PermissionCode.";

        protected override string Template => """
            IF NOT EXISTS (
                SELECT 1 FROM sys.indexes i
                JOIN sys.index_columns ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id AND ic.key_ordinal = 1
                JOIN sys.columns c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
                WHERE i.object_id = OBJECT_ID(N'[{schema}].[RolePermission]') AND i.is_primary_key = 0 AND c.name = N'PermissionCode')
            CREATE NONCLUSTERED INDEX IX_RolePermission_PermissionCode ON [{schema}].[RolePermission](PermissionCode);
            """;
    }

    /// <summary>
    /// Version 3: what the application may do on its tables, through the runtime role. The audit log is insert-only.
    /// Which database user is a member of the role is not a step (it differs per environment): see
    /// <c>SchemaMigrationOptions.AppUser</c>.
    /// </summary>
    internal sealed class RuntimeGrantsStep : MigrationStep
    {
        public override int Version => 3;
        public override string Id => "0003-runtime-grants";
        public override string Description => "Grants of the runtime role on the tables; the audit log is insert-only.";

        protected override string Template => """
            GRANT SELECT, INSERT, UPDATE, DELETE ON [{schema}].[Permission]          TO [{role}];
            GRANT SELECT, INSERT, UPDATE, DELETE ON [{schema}].[Role]                TO [{role}];
            GRANT SELECT, INSERT, UPDATE, DELETE ON [{schema}].[RolePermission]      TO [{role}];
            GRANT SELECT, INSERT, UPDATE, DELETE ON [{schema}].[UserRole]            TO [{role}];
            GRANT SELECT, INSERT, UPDATE, DELETE ON [{schema}].[PersonalAccessToken] TO [{role}];
            GRANT SELECT, INSERT                 ON [{schema}].[AuditLog]            TO [{role}];
            DENY UPDATE, DELETE                  ON [{schema}].[AuditLog]            TO [{role}];
            """;
    }

    /// <summary>The steps, in order. The last one is the version the packages require.</summary>
    internal static class MigrationSteps
    {
        public static IReadOnlyList<MigrationStep> All { get; } = new MigrationStep[]
        {
            new RuntimeRoleStep(),
            new TablesStep(),
            new RolePermissionIndexStep(),
            new RuntimeGrantsStep(),
        };
    }
}
