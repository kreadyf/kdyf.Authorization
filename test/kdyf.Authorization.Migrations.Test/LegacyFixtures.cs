namespace kdyf.Authorization.Migrations.Test;

/// <summary>
/// The legacy kdyf.auth.* shapes as their scripts created them: A, B, C and K0 (a host's first model). B′ is C with
/// PersonalAccessTokenRole left in place.
/// </summary>
internal static class LegacyFixtures
{
    public const string ShapeA = """
        CREATE SCHEMA auth;
        GO
        CREATE TABLE auth.Permission (Code VARCHAR(50) NOT NULL CONSTRAINT PK_Permission PRIMARY KEY, [Group] VARCHAR(50) NULL, Description NVARCHAR(200) NULL);
        CREATE TABLE auth.Role (RoleId INT IDENTITY(1,1) NOT NULL CONSTRAINT PK_Role PRIMARY KEY, Name NVARCHAR(100) NOT NULL CONSTRAINT UQ_Role_Name UNIQUE, Description NVARCHAR(200) NULL);
        CREATE TABLE auth.[User] (UserId INT IDENTITY(1,1) NOT NULL CONSTRAINT PK_User PRIMARY KEY, Email NVARCHAR(256) NOT NULL CONSTRAINT UQ_User_Email UNIQUE,
            AzureObjectId UNIQUEIDENTIFIER NULL, DisplayName NVARCHAR(200) NULL, IsActive BIT NOT NULL CONSTRAINT DF_User_IsActive DEFAULT 1,
            CreatedAt DATETIME2 NOT NULL CONSTRAINT DF_User_CreatedAt DEFAULT SYSUTCDATETIME(), LastLoginAt DATETIME2 NULL);
        CREATE TABLE auth.RolePermission (RoleId INT NOT NULL, PermissionCode VARCHAR(50) NOT NULL, CONSTRAINT PK_RolePermission PRIMARY KEY (RoleId, PermissionCode));
        CREATE TABLE auth.UserRole (UserId INT NOT NULL, RoleId INT NOT NULL, CONSTRAINT PK_UserRole PRIMARY KEY (UserId, RoleId));
        """;

    private const string Common = """
        CREATE SCHEMA auth;
        GO
        CREATE TABLE auth.Permission (PermissionCode VARCHAR(50) NOT NULL CONSTRAINT PK_Permission PRIMARY KEY, name NVARCHAR(100) NULL, description NVARCHAR(200) NULL);
        CREATE TABLE auth.Role (RoleId INT IDENTITY(1,1) NOT NULL CONSTRAINT PK_Role PRIMARY KEY, name NVARCHAR(100) NOT NULL CONSTRAINT UQ_Role_Name UNIQUE, description NVARCHAR(200) NULL);
        CREATE TABLE auth.[User] (UserId INT IDENTITY(1,1) NOT NULL CONSTRAINT PK_User PRIMARY KEY, email NVARCHAR(256) NOT NULL CONSTRAINT UQ_User_Email UNIQUE,
            objectId NVARCHAR({0}) NULL, displayName NVARCHAR(200) NULL, isActive BIT NOT NULL CONSTRAINT DF_User_IsActive DEFAULT 1,
            createdAt DATETIME2 NOT NULL CONSTRAINT DF_User_CreatedAt DEFAULT SYSUTCDATETIME(), lastLoginAt DATETIME2 NULL);
        CREATE UNIQUE INDEX IX_User_ObjectId ON auth.[User](objectId) WHERE objectId IS NOT NULL;
        CREATE TABLE auth.RolePermission (RoleId INT NOT NULL, PermissionCode VARCHAR(50) NOT NULL, CONSTRAINT PK_RolePermission PRIMARY KEY (RoleId, PermissionCode),
            CONSTRAINT FK_RolePermission_Role FOREIGN KEY (RoleId) REFERENCES auth.Role(RoleId) ON DELETE CASCADE,
            CONSTRAINT FK_RolePermission_Permission FOREIGN KEY (PermissionCode) REFERENCES auth.Permission(PermissionCode));
        CREATE TABLE auth.UserRole (UserId INT NOT NULL, RoleId INT NOT NULL, CONSTRAINT PK_UserRole PRIMARY KEY (UserId, RoleId),
            CONSTRAINT FK_UserRole_User FOREIGN KEY (UserId) REFERENCES auth.[User](UserId) ON DELETE CASCADE,
            CONSTRAINT FK_UserRole_Role FOREIGN KEY (RoleId) REFERENCES auth.Role(RoleId) ON DELETE CASCADE);
        """;

    private const string Tokens = """
        CREATE TABLE auth.PersonalAccessToken (PersonalAccessTokenId INT IDENTITY(1,1) NOT NULL CONSTRAINT PK_PersonalAccessToken PRIMARY KEY,
            name NVARCHAR(100) NOT NULL, tokenHash VARBINARY(32) NOT NULL CONSTRAINT UQ_PersonalAccessToken_Hash UNIQUE, tokenPrefix NVARCHAR(12) NULL,
            userId INT NOT NULL, isActive BIT NOT NULL CONSTRAINT DF_PersonalAccessToken_IsActive DEFAULT 1, expiresAt DATETIME2 NULL,
            createdAt DATETIME2 NOT NULL CONSTRAINT DF_PersonalAccessToken_CreatedAt DEFAULT SYSUTCDATETIME(), lastUsedAt DATETIME2 NULL,
            CONSTRAINT FK_PersonalAccessToken_User FOREIGN KEY (userId) REFERENCES auth.[User](UserId) ON DELETE CASCADE);
        """;

    private const string TokenRoles = """
        CREATE TABLE auth.PersonalAccessTokenRole (PersonalAccessTokenId INT NOT NULL, RoleId INT NOT NULL,
            CONSTRAINT PK_PersonalAccessTokenRole PRIMARY KEY (PersonalAccessTokenId, RoleId),
            CONSTRAINT FK_PersonalAccessTokenRole_Pat FOREIGN KEY (PersonalAccessTokenId) REFERENCES auth.PersonalAccessToken(PersonalAccessTokenId) ON DELETE CASCADE,
            CONSTRAINT FK_PersonalAccessTokenRole_Role FOREIGN KEY (RoleId) REFERENCES auth.Role(RoleId) ON DELETE CASCADE);
        """;

    private const string Audit = """
        CREATE NONCLUSTERED INDEX IX_PersonalAccessToken_UserId ON auth.PersonalAccessToken(userId);
        CREATE TABLE auth.AuditLog (AuditLogId BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_AuditLog PRIMARY KEY,
            occurredAt DATETIME2 NOT NULL CONSTRAINT DF_AuditLog_OccurredAt DEFAULT SYSUTCDATETIME(), actorUserId INT NULL, actorEmail NVARCHAR(256) NOT NULL,
            action VARCHAR(40) NOT NULL, targetType VARCHAR(20) NOT NULL, targetId INT NULL, targetLabel NVARCHAR(256) NOT NULL, details NVARCHAR(MAX) NULL);
        """;

    public static string ShapeB => string.Format(Common, 50) + Tokens + TokenRoles;

    public static string ShapeBPrime => string.Format(Common, 50) + Tokens + TokenRoles + Audit;

    public static string ShapeC => string.Format(Common, 50) + Tokens + Audit;

    public static string ShapeK0 => string.Format(Common, 100);

    /// <summary>Rows with what the import has to decide about. The token of user 1 is limited to role 2 of its roles 1 and 2.</summary>
    public const string Data = """
        INSERT INTO auth.Permission (PermissionCode) VALUES ('Default'), ('*'), ('Orders.Read'), ('Orders.Write');
        SET IDENTITY_INSERT auth.Role ON;
        INSERT INTO auth.Role (RoleId, name) VALUES (1, 'Super Admin'), (2, 'Order Reader'), (3, 'Empty Role');
        SET IDENTITY_INSERT auth.Role OFF;
        INSERT INTO auth.RolePermission (RoleId, PermissionCode) VALUES (1, '*'), (2, 'Orders.Read');
        SET IDENTITY_INSERT auth.[User] ON;
        INSERT INTO auth.[User] (UserId, email, objectId, isActive) VALUES
            (1, 'admin@test', '0F1E2D3C-0000-0000-0000-000000000001', 1),
            (2, 'reader@test', '0f1e2d3c-0000-0000-0000-000000000002', 0),
            (3, 'service@test', NULL, 1),
            (4, 'nothing@test', '0f1e2d3c-0000-0000-0000-000000000004', 1);
        SET IDENTITY_INSERT auth.[User] OFF;
        INSERT INTO auth.UserRole (UserId, RoleId) VALUES (1, 1), (1, 2), (2, 2), (3, 2), (4, 3);
        """;

    public const string TokenData = """
        INSERT INTO auth.PersonalAccessToken (name, tokenHash, userId) VALUES
            ('limited', 0x0101010101010101010101010101010101010101010101010101010101010101, 1),
            ('service', 0x0202020202020202020202020202020202020202020202020202020202020202, 3);
        """;

    public const string TokenRoleData = "INSERT INTO auth.PersonalAccessTokenRole (PersonalAccessTokenId, RoleId) VALUES (1, 2);";
}
