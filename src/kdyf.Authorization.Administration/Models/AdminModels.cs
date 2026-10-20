namespace kdyf.Authorization.Administration.Models
{
    // ---------- People and their access ----------

    /// <summary>A person, whether they are in the access group, and the roles the application gives them.</summary>
    public class AccessUserResponse
    {
        /// <summary>Their immutable Entra object id: the key every other call takes.</summary>
        public string ObjectId { get; set; } = string.Empty;

        /// <summary>Name to show. May be null for a guest who has not redeemed the invitation yet.</summary>
        public string? DisplayName { get; set; }

        /// <summary>Real address. For a guest this is NOT their sign-in name.</summary>
        public string? Email { get; set; }

        /// <summary>Sign-in name. For a guest it has the <c>#EXT#</c> shape, which is why it is not the e-mail.</summary>
        public string? UserPrincipalName { get; set; }

        /// <summary>External user invited through B2B.</summary>
        public bool IsGuest { get; set; }

        /// <summary>
        /// False when Entra no longer knows them (the account was deleted) and only roles are left behind here.
        /// They hold nothing; <c>DELETE /users/{objectId}</c> or <c>DELETE /roles/orphans</c> clears the rows.
        /// </summary>
        public bool InDirectory { get; set; }

        /// <summary>False when the account is disabled in Entra: they hold nothing, whatever the roles say.</summary>
        public bool AccountEnabled { get; set; }

        /// <summary>In the access group, directly or through a nested group. Outside it they hold nothing.</summary>
        public bool IsMember { get; set; }

        /// <summary>May use the application: an enabled account in the access group, not suspended.</summary>
        public bool HasAccess { get; set; }

        /// <summary>
        /// Suspended by the application: they hold nothing (sessions, tokens, simulation), whatever the directory and
        /// their roles say. Their roles stay, for when they are reactivated.
        /// </summary>
        public bool IsSuspended { get; set; }

        /// <summary>The last time they used the application with their own session (not a token, not somebody looking them up), to the minutes of the recording interval.</summary>
        public DateTime? LastLoginAt { get; set; }

        /// <summary>The caller themselves. The screen should not offer to change it: nobody changes their own access.</summary>
        public bool IsSelf { get; set; }

        /// <summary>The roles they hold, including ones the caller could not grant (flagged, not hidden).</summary>
        public List<AssignedRoleResponse> Roles { get; set; } = new();

        /// <summary>
        /// Effective permissions: what every member holds plus what their roles grant, wildcards expanded. Empty
        /// without access.
        /// </summary>
        public List<string> Permissions { get; set; } = new();
    }

    /// <summary>One role a person holds.</summary>
    public class AssignedRoleResponse
    {
        /// <summary>The role's value, e.g. <c>Portal.Editor</c>.</summary>
        public string Value { get; set; } = string.Empty;

        /// <summary>The role's name on screen.</summary>
        public string Name { get; set; } = string.Empty;

        /// <summary>False when no permission is configured for this role: it grants nothing yet.</summary>
        public bool Configured { get; set; }

        /// <summary>
        /// Whether the caller could grant or remove this role: everything it grants is something they hold.
        /// False means: show it, explain it, and do not offer to change it.
        /// </summary>
        public bool Assignable { get; set; }
    }

    /// <summary>The complete set of roles a person should hold. It REPLACES their current roles.</summary>
    public class SetRolesRequest
    {
        /// <summary>
        /// Role values. Must include the roles the caller cannot change that the person already holds, exactly
        /// as <c>GET</c> returned them: leaving one out is asking to remove it, and is refused. An empty list
        /// leaves them with the base access only. Somebody not yet in the access group is added to it.
        /// </summary>
        public List<string> Roles { get; set; } = new();
    }

    // ---------- Roles ----------

    /// <summary>A role of the application, with the permissions it grants.</summary>
    public class RoleResponse
    {
        /// <summary>The role's value: the key. Never changes.</summary>
        public string Value { get; set; } = string.Empty;

        /// <summary>The name on screen.</summary>
        public string Name { get; set; } = string.Empty;

        /// <summary>Free text shown with the role; null when it has none.</summary>
        public string? Description { get; set; }

        /// <summary>What it grants, as configured (patterns included), ordered.</summary>
        public List<string> Permissions { get; set; } = new();

        /// <summary>
        /// Configured codes that no permission declaration matches any more (renamed or removed in code). They
        /// grant nothing; saving the role without them cleans them up.
        /// </summary>
        public List<string> UnknownPermissions { get; set; } = new();

        /// <summary>False while no permission is configured for it: it can be given, and grants nothing yet.</summary>
        public bool Configured { get; set; }

        /// <summary>Whether the caller could hand it out (everything it grants is something they hold).</summary>
        public bool Assignable { get; set; }

        /// <summary>
        /// Whether the caller may change what it grants: they do not hold it themselves (four eyes) and it
        /// grants nothing beyond them.
        /// </summary>
        public bool Editable { get; set; }

        /// <summary>How many people hold it.</summary>
        public int UserCount { get; set; }

        /// <summary>
        /// What the role (its name, description and permissions) looked like when read. Send it back in <see cref="SetRolePermissionsRequest.Version"/>
        /// to be told, instead of silently overwriting, that somebody changed the role in the meantime.
        /// </summary>
        public string Version { get; set; } = string.Empty;
    }

    /// <summary>A new role.</summary>
    public class CreateRoleRequest
    {
        /// <summary>
        /// The key, e.g. <c>Portal.Auditor</c>: letters, digits, '.', '_' and '-', starting with a letter, at
        /// most 100 characters. It cannot be changed later.
        /// </summary>
        public string Value { get; set; } = string.Empty;

        /// <summary>The name on screen. Defaults to the value.</summary>
        public string? Name { get; set; }

        /// <summary>Free text shown with the role, at most 500 characters. Blank is stored as none.</summary>
        public string? Description { get; set; }

        /// <summary>What it grants from the start. Optional: a role may be created empty and configured later.</summary>
        public List<string> Permissions { get; set; } = new();
    }

    /// <summary>
    /// A role's name and description and, optionally, what it grants: all of it in one transaction and one audit entry,
    /// or nothing.
    /// </summary>
    public class UpdateRoleRequest
    {
        /// <summary>The name on screen. Required, at most 200 characters.</summary>
        public string Name { get; set; } = string.Empty;

        /// <summary>Free text shown with the role, at most 500 characters. Blank clears it.</summary>
        public string? Description { get; set; }

        /// <summary>
        /// The complete set of permissions it should grant, REPLACING the current ones, with the rules of
        /// <see cref="SetRolePermissionsRequest"/>. Null leaves what it grants as it is.
        /// </summary>
        public List<string>? Permissions { get; set; }

        /// <summary>The <see cref="RoleResponse.Version"/> the caller read; when it no longer matches, nothing is changed.</summary>
        public string? Version { get; set; }
    }

    /// <summary>The complete set of permissions a role should grant. It REPLACES the current ones.</summary>
    public class SetRolePermissionsRequest
    {
        /// <summary>Permission codes declared by the application (<c>GET /permissions</c>). Empty: the role grants nothing.</summary>
        public List<string> Permissions { get; set; } = new();

        /// <summary>
        /// The <see cref="RoleResponse.Version"/> the caller read. When it no longer matches, the change is refused
        /// instead of overwriting somebody else's. Optional, but a screen that edits roles should send it: the
        /// change REPLACES the set, so without it a concurrent edit is lost silently.
        /// </summary>
        public string? Version { get; set; }
    }

    // ---------- What is left behind ----------

    /// <summary>
    /// What is left behind, or still missing, in the configuration. Nothing here grants anything.
    /// </summary>
    public class RoleConsistencyResponse
    {
        /// <summary>Roles with no permission configured: they can be given, and grant nothing yet.</summary>
        public List<string> UnconfiguredRoles { get; set; } = new();

        /// <summary>
        /// Configured codes that no permission declaration matches any more (a permission class removed or its
        /// namespace changed), per role. They grant nothing. <c>DELETE /roles/orphans</c> removes them —
        /// otherwise a permission declared later with the same code would silently reach those roles again.
        /// </summary>
        public List<ConfiguredRoleResponse> UnknownPermissions { get; set; } = new();

        /// <summary>
        /// Rows of the permission catalog (<c>auth.Permission</c>) that no class declares any more. The
        /// synchronisation never deletes them; <c>DELETE /roles/orphans</c> does, after removing their grants.
        /// </summary>
        public List<string> UndeclaredCatalogPermissions { get; set; } = new();

        /// <summary>
        /// People who hold roles but are no longer in the access group (taken out in the Entra portal, or deleted
        /// from Entra). They hold nothing. <c>DELETE /roles/orphans</c> removes their roles — otherwise adding
        /// them back to the group would silently bring the old roles back.
        /// </summary>
        public List<FormerMemberResponse> FormerMembers { get; set; } = new();
    }

    /// <summary>What <c>DELETE /roles/orphans</c> removed.</summary>
    public class OrphanCleanupResponse
    {
        /// <summary>Per role, the configured codes the application no longer declares.</summary>
        public List<ConfiguredRoleResponse> RemovedPermissions { get; set; } = new();

        /// <summary>Rows removed from the permission catalog: codes no class declares any more.</summary>
        public List<string> RemovedCatalogPermissions { get; set; } = new();

        /// <summary>People outside the access group, with the roles removed from them.</summary>
        public List<FormerMemberResponse> RemovedMembers { get; set; } = new();
    }

    /// <summary>A role value and codes configured for it.</summary>
    public class ConfiguredRoleResponse
    {
        /// <summary>The role's value.</summary>
        public string Value { get; set; } = string.Empty;
        /// <summary>The codes in question, configured for that role.</summary>
        public List<string> Permissions { get; set; } = new();
    }

    /// <summary>Somebody holding roles outside the access group.</summary>
    public class FormerMemberResponse
    {
        /// <summary>Their Entra object id.</summary>
        public string ObjectId { get; set; } = string.Empty;

        /// <summary>E-mail or sign-in name when Entra still knows them; null when it does not.</summary>
        public string? Label { get; set; }

        /// <summary>False when Entra no longer knows them at all.</summary>
        public bool InDirectory { get; set; }

        /// <summary>The role values they still hold (or, in <see cref="OrphanCleanupResponse"/>, that were removed).</summary>
        public List<string> Roles { get; set; } = new();
    }

    // ---------- Catalog ----------

    /// <summary>A permission the application declares: what a role can be configured to grant.</summary>
    public class PermissionResponse
    {
        /// <summary>The code roles grant and doors demand, e.g. <c>Portal.Admin</c>.</summary>
        public string PermissionCode { get; set; } = string.Empty;
        /// <summary>The name given in the declaration, if any.</summary>
        public string? Name { get; set; }
        /// <summary>The description given in the declaration, if any.</summary>
        public string? Description { get; set; }

        /// <summary>A wildcard (<c>*</c>, <c>area.*</c>): granted by roles, never demanded by a door.</summary>
        public bool IsPattern { get; set; }

        /// <summary>Held by every member of the access group without any role (the base access).</summary>
        public bool HeldByEveryMember { get; set; }
    }
}
