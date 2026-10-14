namespace kdyf.Authorization.Abstractions
{
    /// <summary>
    /// Catalog of permissions that exist in the system. Optional: only used by the startup
    /// validation, which checks the policy names of the [Authorize] attributes against this catalog.
    /// </summary>
    /// <remarks>
    /// Without this validation, a typo in a permission name does not fail: it denies silently.
    /// A silent denial is as dangerous as an extra permission, because nobody investigates it
    /// until a user complains.
    /// </remarks>
    public interface IPermissionCatalog
    {
        /// <summary>
        /// Returns all valid permission codes.
        /// </summary>
        Task<IReadOnlySet<string>> GetAllAsync(CancellationToken cancellationToken = default);
    }
}
