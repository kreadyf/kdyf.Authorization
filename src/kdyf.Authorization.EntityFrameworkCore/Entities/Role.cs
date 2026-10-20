namespace kdyf.Authorization.EntityFrameworkCore.Entities
{
    /// <summary>
    /// A role of the application: created and named by its administrators, not by the directory.
    /// </summary>
    public class Role
    {
        /// <summary>The key, e.g. <c>Portal.Editor</c>. Never changes once created: rows point at it.</summary>
        public string RoleValue { get; set; } = string.Empty;

        /// <summary>The name on screen.</summary>
        public string Name { get; set; } = string.Empty;

        /// <summary>What the role is for, on screen. Optional.</summary>
        public string? Description { get; set; }

        /// <summary>When the role was created (UTC).</summary>
        public DateTime CreatedAt { get; set; }
    }
}
