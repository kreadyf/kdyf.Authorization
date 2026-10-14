namespace kdyf.Authorization.EntityFrameworkCore.Entities
{
    /// <summary>
    /// One role a person holds, given by an administrator of the application.
    /// </summary>
    /// <remarks>
    /// The person is named by their immutable Entra object id and nothing else: their name, e-mail and whether
    /// their account is enabled live in Entra. There is no user table to keep in sync. Holding a role grants
    /// nothing outside the access group.
    /// </remarks>
    public class UserRole
    {
        /// <summary>The person's Entra object id ('oid'), lower-case, as <c>Guid.ToString()</c> writes it.</summary>
        public string ObjectId { get; set; } = string.Empty;

        /// <summary>The role's value (<see cref="Role.RoleValue"/>).</summary>
        public string RoleValue { get; set; } = string.Empty;

        /// <summary>The canonical form object ids are stored and compared in.</summary>
        public static string Normalize(string objectId) =>
            Guid.TryParse(objectId, out var id) ? id.ToString() : objectId.Trim().ToLowerInvariant();
    }
}
