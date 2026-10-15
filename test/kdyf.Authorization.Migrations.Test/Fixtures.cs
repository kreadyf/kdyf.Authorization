namespace kdyf.Authorization.Migrations.Test;

/// <summary>Databases in the shapes the detector must tell apart, built from DDL as the hosts' scripts wrote it.</summary>
internal static class Fixtures
{
    /// <summary>
    /// The shape of the databases created by the hosts' script before versioning (mtcm's auth-schema.sql): version 1,
    /// without IX_RolePermission_PermissionCode, with defaults and the token hash as a unique constraint.
    /// </summary>
    public const string HostScriptVersion1 = """
        CREATE SCHEMA auth;
        GO
        CREATE TABLE auth.Permission (
            PermissionCode VARCHAR(50)   COLLATE Latin1_General_100_BIN2 NOT NULL CONSTRAINT PK_Permission PRIMARY KEY,
            name           NVARCHAR(100) NULL,
            description    NVARCHAR(200) NULL
        );
        CREATE TABLE auth.Role (
            roleValue   VARCHAR(100)  COLLATE Latin1_General_100_BIN2 NOT NULL CONSTRAINT PK_Role PRIMARY KEY,
            name        NVARCHAR(200) NOT NULL,
            description NVARCHAR(500) NULL,
            createdAt   DATETIME2     NOT NULL CONSTRAINT DF_Role_CreatedAt DEFAULT SYSUTCDATETIME()
        );
        CREATE TABLE auth.RolePermission (
            roleValue      VARCHAR(100) COLLATE Latin1_General_100_BIN2 NOT NULL,
            PermissionCode VARCHAR(50)  COLLATE Latin1_General_100_BIN2 NOT NULL,
            CONSTRAINT PK_RolePermission PRIMARY KEY (roleValue, PermissionCode)
        );
        ALTER TABLE auth.RolePermission
            ADD CONSTRAINT FK_RolePermission_Role FOREIGN KEY (roleValue) REFERENCES auth.Role(roleValue) ON DELETE CASCADE;
        ALTER TABLE auth.RolePermission
            ADD CONSTRAINT FK_RolePermission_Permission FOREIGN KEY (PermissionCode) REFERENCES auth.Permission(PermissionCode);
        CREATE TABLE auth.UserRole (
            objectId  VARCHAR(50)  NOT NULL,
            roleValue VARCHAR(100) COLLATE Latin1_General_100_BIN2 NOT NULL,
            CONSTRAINT PK_UserRole PRIMARY KEY (objectId, roleValue),
            CONSTRAINT FK_UserRole_Role FOREIGN KEY (roleValue) REFERENCES auth.Role(roleValue)
        );
        CREATE NONCLUSTERED INDEX IX_UserRole_Role ON auth.UserRole(roleValue);
        CREATE TABLE auth.PersonalAccessToken (
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
        CREATE NONCLUSTERED INDEX IX_PersonalAccessToken_Owner ON auth.PersonalAccessToken(ownerObjectId);
        CREATE TABLE auth.AuditLog (
            AuditLogId    BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_AuditLog PRIMARY KEY,
            occurredAt    DATETIME2      NOT NULL CONSTRAINT DF_AuditLog_OccurredAt DEFAULT SYSUTCDATETIME(),
            actorObjectId NVARCHAR(50)   NULL,
            actorEmail    NVARCHAR(256)  NOT NULL,
            action        VARCHAR(40)    NOT NULL,
            targetType    VARCHAR(20)    NOT NULL,
            targetId      NVARCHAR(100)  NULL,
            targetLabel   NVARCHAR(256)  NOT NULL,
            details       NVARCHAR(MAX)  NULL
        );
        CREATE NONCLUSTERED INDEX IX_AuditLog_Target        ON auth.AuditLog(targetType, targetId);
        CREATE NONCLUSTERED INDEX IX_AuditLog_OccurredAt    ON auth.AuditLog(occurredAt);
        CREATE NONCLUSTERED INDEX IX_AuditLog_ActorObjectId ON auth.AuditLog(actorObjectId);
        """;

    /// <summary>Version 1 created with the database's default (case-insensitive) collation on the keys.</summary>
    public static string CaseInsensitiveVersion1 => HostScriptVersion1.Replace(" COLLATE Latin1_General_100_BIN2", "");

    /// <summary>Rows the adoption and the repair must keep.</summary>
    public const string Data = """
        INSERT INTO auth.Permission (PermissionCode, name) VALUES ('*', N'Everything'), ('portal.Read', N'Read');
        INSERT INTO auth.Role (roleValue, name) VALUES ('Portal.Admin', N'Administrator'), ('Portal.Reader', N'Reader');
        INSERT INTO auth.RolePermission (roleValue, PermissionCode) VALUES ('Portal.Admin', '*'), ('Portal.Reader', 'portal.Read');
        INSERT INTO auth.UserRole (objectId, roleValue) VALUES ('0f1e2d3c-0000-0000-0000-000000000001', 'Portal.Admin');
        INSERT INTO auth.PersonalAccessToken (name, tokenHash, ownerObjectId, ownerLabel)
        VALUES (N'ci', 0x0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20, N'0f1e2d3c-0000-0000-0000-000000000001', N'admin@example.com');
        INSERT INTO auth.AuditLog (actorEmail, action, targetType, targetLabel) VALUES (N'admin@example.com', 'role.created', 'role', N'Portal.Admin');
        """;

    /// <summary>The legacy kdyf.auth.* schema, reduced to what identifies it: auth.[User] and Role.RoleId.</summary>
    public const string Legacy = """
        CREATE SCHEMA auth;
        GO
        CREATE TABLE auth.[User] (UserId INT IDENTITY(1,1) NOT NULL CONSTRAINT PK_User PRIMARY KEY, email NVARCHAR(256) NOT NULL, objectId NVARCHAR(100) NULL);
        CREATE TABLE auth.Role (RoleId INT IDENTITY(1,1) NOT NULL CONSTRAINT PK_Role PRIMARY KEY, name NVARCHAR(100) NOT NULL);
        CREATE TABLE auth.UserRole (UserId INT NOT NULL, RoleId INT NOT NULL, CONSTRAINT PK_UserRole PRIMARY KEY (UserId, RoleId));
        """;

    /// <summary>mtcm's model of 10 September 2026: grants keyed by roleValue with no Role table.</summary>
    public const string RolesWithoutTable = """
        CREATE SCHEMA auth;
        GO
        CREATE TABLE auth.RolePermission (
            roleValue      VARCHAR(100) NOT NULL,
            PermissionCode VARCHAR(50)  NOT NULL,
            CONSTRAINT PK_RolePermission PRIMARY KEY (roleValue, PermissionCode)
        );
        """;
}
