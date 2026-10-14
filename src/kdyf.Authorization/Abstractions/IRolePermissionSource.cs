namespace kdyf.Authorization.Abstractions
{
    /// <summary>
    /// The roles and what each one grants: the configurable part of the access model.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The roles are the application's own, created and configured by its administrators and stored by the
    /// consumer (e.g. <c>auth.Role</c> and <c>auth.RolePermission</c>). A role is named by its value
    /// (<c>Portal.Editor</c>). WHO holds it is <see cref="IUserRoleSource"/>; the store behind this interface
    /// holds no people.
    /// </para>
    /// <para>
    /// Security contract: a real failure (database down) THROWS — the caller denies. An empty answer means
    /// "no role grants anything", which denies everybody; it is never a fallback.
    /// </para>
    /// </remarks>
    public interface IRolePermissionSource
    {
        /// <summary>
        /// Every role that exists, with the permission codes it grants (patterns included). A role that grants
        /// nothing yet is in the answer with an empty set.
        /// </summary>
        Task<IReadOnlyDictionary<string, IReadOnlySet<string>>> GetAllAsync(CancellationToken cancellationToken = default);
    }
}
