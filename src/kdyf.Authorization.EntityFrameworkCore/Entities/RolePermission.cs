namespace kdyf.Authorization.EntityFrameworkCore.Entities
{
    /// <summary>
    /// One permission a role grants: the configurable half of the access model.
    /// </summary>
    public class RolePermission
    {
        /// <summary>The role's value (<see cref="Role.RoleValue"/>), e.g. <c>Portal.Editor</c>.</summary>
        public string RoleValue { get; set; } = string.Empty;

        /// <summary>A permission declared in code (<c>PermissionDefinition</c>), or a declared wildcard (<c>*</c>).</summary>
        public string PermissionCode { get; set; } = string.Empty;
    }
}
