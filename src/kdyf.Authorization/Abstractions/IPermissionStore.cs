namespace kdyf.Authorization.Abstractions
{
    /// <summary>
    /// Source of a user's effective permissions. It is the only coupling point
    /// between this package and the consumer's persistence.
    /// </summary>
    /// <remarks>
    /// Security contract that every implementation must honor:
    /// <list type="bullet">
    /// <item>Return an empty set if the user does not exist or is inactive. Never throw for "not found".</item>
    /// <item>Return the permissions already flattened (resolved through roles, groups or whatever the consumer uses).</item>
    /// <item>On a real failure (DB down), throw. The handler treats it as a denial, never as a grant.</item>
    /// </list>
    /// </remarks>
    public interface IPermissionStore
    {
        /// <summary>
        /// Returns the effective permission codes of the given user.
        /// </summary>
        Task<IReadOnlySet<string>> GetPermissionsAsync(UserIdentity user, CancellationToken cancellationToken = default);
    }
}
