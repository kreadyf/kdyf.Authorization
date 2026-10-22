-- =============================================================================
-- kdyf.Authorization 1.2.0 — POST-DEPLOYMENT: wildcard rows become nodes of the permission tree.
--
-- Before 1.2.0 a role granted everything with '*' and an area with 'area.*'. From 1.2.0 a code covers itself and
-- everything below it: the root '' (empty) is everything, 'area' is the area. 1.2.0 still READS the old rows
-- ('*' as '', 'area.*' as 'area'), so this script is not needed for the application to work; it removes the old
-- spelling for good, so that the tables say what the application does.
--
-- Order:
--   1. Deploy 1.2.0 to EVERY instance of EVERY host that shares these tables. The catalog sync creates the root and
--      the area nodes; it leaves the wildcard rows alone.
--   2. Run this script with @DryRun = 1 and read the counts. Then with @DryRun = 0.
--   3. Restart the hosts (or wait for the permission cache to expire).
--   Do not go back to a version before 1.2.0 afterwards: it would not find '*'.
--
-- What it does, in ONE transaction:
--   - each '*' grant becomes a grant of '', each 'area.*' grant a grant of 'area' (the role keeps exactly the same
--     access); a role holding both 'area' and 'area.*' ends up with one row;
--   - every ancestor of every code gets a catalog row if it has none (existing names and descriptions are kept);
--   - the wildcard grants and catalog rows are deleted, after their replacements are in. The foreign key
--     RolePermission -> Permission is never dropped nor disabled;
--   - it verifies that every role grants exactly what it granted before, normalized, and rolls back otherwise.
-- It refuses (and changes nothing) on a malformed wildcard ('.*', 'a..*', '*.*', a star in the middle), on a code
-- that is not a path, and on two paths that differ only in capitalisation.
--
-- The model of the package: auth.RolePermission (roleValue, PermissionCode), keys with a BIN2 collation. If your
-- schema is not 'auth', replace 'auth.' below. Idempotent: a second run finds nothing to do.
-- =============================================================================

SET XACT_ABORT ON;
SET NOCOUNT ON;

DECLARE @DryRun BIT = 1;               -- 1: everything is done and checked, then rolled back. 0: committed.

-- Optional: forbid '*' in the two tables from now on. Off by default: the schema check of 'kdyf-auth migrate'
-- compares the tables with what the package creates, and an extra constraint is a difference it reports.
DECLARE @AddCheckConstraints BIT = 0;

BEGIN TRY
    BEGIN TRANSACTION;

    IF OBJECT_ID(N'auth.Permission', N'U') IS NULL OR OBJECT_ID(N'auth.RolePermission', N'U') IS NULL
        THROW 51010, 'auth.Permission and auth.RolePermission must exist.', 1;

    IF COL_LENGTH('auth.RolePermission', 'roleValue') IS NULL
        THROW 51017, 'auth.RolePermission has no roleValue: this is the legacy schema. Import it first (kdyf-auth migrate).', 1;

    IF NOT EXISTS (
        SELECT 1 FROM sys.foreign_keys
        WHERE parent_object_id = OBJECT_ID(N'auth.RolePermission')
          AND referenced_object_id = OBJECT_ID(N'auth.Permission')
          AND is_disabled = 0)
        THROW 51011, 'The foreign key RolePermission -> Permission must exist and be enabled.', 1;

    -- Both tables frozen while they are read and rewritten.
    DECLARE @grantsBefore TABLE (
        roleValue      VARCHAR(100) COLLATE Latin1_General_100_BIN2 NOT NULL,
        PermissionCode VARCHAR(50)  COLLATE Latin1_General_100_BIN2 NOT NULL,
        PRIMARY KEY (roleValue, PermissionCode)
    );
    INSERT INTO @grantsBefore
    SELECT roleValue, PermissionCode FROM auth.RolePermission WITH (TABLOCKX, HOLDLOCK);

    DECLARE @codes TABLE (
        StoredCode VARCHAR(50) COLLATE Latin1_General_100_BIN2 NOT NULL PRIMARY KEY,
        Code       VARCHAR(50) COLLATE Latin1_General_100_BIN2 NOT NULL
    );
    INSERT INTO @codes (StoredCode, Code)
    SELECT PermissionCode,
        CASE
            WHEN DATALENGTH(PermissionCode) = 1 AND PermissionCode = '*' THEN ''
            WHEN RIGHT(PermissionCode, 2) = '.*' THEN LEFT(PermissionCode, LEN(PermissionCode) - 2)
            ELSE PermissionCode
        END
    FROM auth.Permission WITH (TABLOCKX, HOLDLOCK);

    -- '' and ' ' compare equal in SQL Server, even under BIN2: the byte length tells the root from a blank.
    IF EXISTS (
        SELECT 1 FROM @grantsBefore g
        WHERE NOT EXISTS (
            SELECT 1 FROM @codes c
            WHERE c.StoredCode = g.PermissionCode AND DATALENGTH(c.StoredCode) = DATALENGTH(g.PermissionCode)))
        THROW 51016, 'A grant has no catalog row with exactly its code. Fix that reference first.', 1;

    -- Only '*' and a well-formed 'prefix.*' are converted; anything else with a star, and any code that is not a path
    -- (empty segments, spaces, characters outside printable ASCII, '|'), stops the script. A typo must never become a
    -- broader grant.
    DECLARE @invalid VARCHAR(50);
    SELECT TOP (1) @invalid = StoredCode
    FROM @codes
    WHERE (StoredCode LIKE '%*%'
           AND NOT (DATALENGTH(StoredCode) = 1 AND StoredCode = '*')
           AND (RIGHT(StoredCode, 2) <> '.*' OR DATALENGTH(Code) = 0))
       OR (DATALENGTH(Code) > 0 AND (
            Code LIKE '%*%' OR Code LIKE '%|%'
            OR Code COLLATE Latin1_General_100_BIN2 LIKE '%[^!-~]%'
            OR LEFT(Code, 1) = '.' OR RIGHT(Code, 1) = '.' OR Code LIKE '%..%'
            OR DATALENGTH(Code) <> LEN(Code)));

    IF @invalid IS NOT NULL
    BEGIN
        DECLARE @invalidMessage NVARCHAR(2048) =
            N'Not a permission path nor a convertible wildcard: [' + @invalid + N']. Nothing was changed.';
        THROW 51012, @invalidMessage, 1;
    END;

    -- Every node: the codes, the root, and every ancestor of every code.
    DECLARE @nodes TABLE (Code VARCHAR(50) COLLATE Latin1_General_100_BIN2 NOT NULL PRIMARY KEY);
    INSERT INTO @nodes (Code)
    SELECT Code FROM @codes
    UNION SELECT '';

    DECLARE @added INT = 1;
    WHILE @added > 0
    BEGIN
        INSERT INTO @nodes (Code)
        SELECT DISTINCT LEFT(n.Code, LEN(n.Code) - CHARINDEX('.', REVERSE(n.Code)))
        FROM @nodes n
        WHERE CHARINDEX('.', n.Code) > 0
          AND NOT EXISTS (
              SELECT 1 FROM @nodes e
              WHERE e.Code = LEFT(n.Code, LEN(n.Code) - CHARINDEX('.', REVERSE(n.Code))));
        SET @added = @@ROWCOUNT;
    END;

    IF EXISTS (
        SELECT Code COLLATE Latin1_General_100_CI_AS FROM @nodes
        GROUP BY Code COLLATE Latin1_General_100_CI_AS HAVING COUNT(*) > 1)
        THROW 51013, 'Two paths differ only in capitalisation. Resolve them before running this script.', 1;

    -- The missing catalog rows. Existing names and descriptions are never touched.
    INSERT INTO auth.Permission (PermissionCode, name, description)
    SELECT n.Code,
        CASE WHEN DATALENGTH(n.Code) = 0 THEN N'Everything' ELSE CONVERT(NVARCHAR(100), n.Code) END,
        CASE WHEN DATALENGTH(n.Code) = 0 THEN N'All permissions, including those added later.'
             ELSE CONVERT(NVARCHAR(200), N'Everything under ' + n.Code + N', including permissions added later.') END
    FROM @nodes n
    WHERE NOT EXISTS (
        SELECT 1 FROM auth.Permission p
        WHERE p.PermissionCode = n.Code AND DATALENGTH(p.PermissionCode) = DATALENGTH(n.Code));
    DECLARE @addedCatalogRows INT = @@ROWCOUNT;

    -- What every role must grant afterwards: what it granted, normalized.
    DECLARE @expected TABLE (
        roleValue      VARCHAR(100) COLLATE Latin1_General_100_BIN2 NOT NULL,
        PermissionCode VARCHAR(50)  COLLATE Latin1_General_100_BIN2 NOT NULL,
        PRIMARY KEY (roleValue, PermissionCode)
    );
    INSERT INTO @expected (roleValue, PermissionCode)
    SELECT DISTINCT g.roleValue, c.Code
    FROM @grantsBefore g
    JOIN @codes c ON c.StoredCode = g.PermissionCode AND DATALENGTH(c.StoredCode) = DATALENGTH(g.PermissionCode);

    -- The new grants first, then the old ones go: the foreign key holds at every step.
    INSERT INTO auth.RolePermission (roleValue, PermissionCode)
    SELECT e.roleValue, e.PermissionCode
    FROM @expected e
    WHERE NOT EXISTS (
        SELECT 1 FROM auth.RolePermission rp
        WHERE rp.roleValue = e.roleValue
          AND rp.PermissionCode = e.PermissionCode
          AND DATALENGTH(rp.PermissionCode) = DATALENGTH(e.PermissionCode));
    DECLARE @addedGrants INT = @@ROWCOUNT;

    DELETE FROM auth.RolePermission WHERE PermissionCode LIKE '%*%';
    DECLARE @removedWildcardGrants INT = @@ROWCOUNT;

    DELETE FROM auth.Permission WHERE PermissionCode LIKE '%*%';
    DECLARE @removedWildcardRows INT = @@ROWCOUNT;

    IF @AddCheckConstraints = 1
    BEGIN
        IF OBJECT_ID(N'auth.CK_Permission_NoWildcards', N'C') IS NULL
            EXEC (N'ALTER TABLE auth.Permission WITH CHECK ADD CONSTRAINT CK_Permission_NoWildcards CHECK (PermissionCode NOT LIKE ''%*%'')');
        IF OBJECT_ID(N'auth.CK_RolePermission_NoWildcards', N'C') IS NULL
            EXEC (N'ALTER TABLE auth.RolePermission WITH CHECK ADD CONSTRAINT CK_RolePermission_NoWildcards CHECK (PermissionCode NOT LIKE ''%*%'')');
    END;

    -- Every role grants exactly what it granted before, normalized: nothing more, nothing less.
    IF EXISTS (
        SELECT roleValue, PermissionCode, DATALENGTH(PermissionCode) FROM @expected
        EXCEPT
        SELECT roleValue, PermissionCode COLLATE Latin1_General_100_BIN2, DATALENGTH(PermissionCode) FROM auth.RolePermission)
       OR EXISTS (
        SELECT roleValue, PermissionCode COLLATE Latin1_General_100_BIN2, DATALENGTH(PermissionCode) FROM auth.RolePermission
        EXCEPT
        SELECT roleValue, PermissionCode, DATALENGTH(PermissionCode) FROM @expected)
        THROW 51014, 'The grants after do not match the normalized grants before. Rolled back.', 1;

    SELECT CASE WHEN @DryRun = 1 THEN 'DRY RUN (rolled back)' ELSE 'APPLIED' END AS Outcome,
        @addedCatalogRows AS AddedCatalogRows,
        @addedGrants AS AddedGrants,
        @removedWildcardGrants AS RemovedWildcardGrants,
        @removedWildcardRows AS RemovedWildcardRows,
        (SELECT COUNT(*) FROM @expected) AS GrantsAfter;

    IF @DryRun = 1
        ROLLBACK TRANSACTION;
    ELSE
        COMMIT TRANSACTION;
END TRY
BEGIN CATCH
    IF XACT_STATE() <> 0
        ROLLBACK TRANSACTION;
    THROW;
END CATCH;
