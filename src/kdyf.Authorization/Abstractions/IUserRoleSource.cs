namespace kdyf.Authorization.Abstractions
{
    /// <summary>
    /// Which roles each person holds: given by the application's administrators, stored by the consumer
    /// (e.g. <c>auth.UserRole</c>), keyed by the person's immutable subject id.
    /// </summary>
    /// <remarks>
    /// Holding a role grants nothing on its own: the person must also be a member of the access group
    /// (<see cref="IMembershipSource"/>). Security contract: a real failure THROWS — the caller denies. A person
    /// with no row holds no role.
    /// </remarks>
    public interface IUserRoleSource
    {
        /// <summary>The values of the roles the person holds. Empty when they hold none.</summary>
        Task<IReadOnlySet<string>> GetRolesAsync(string subjectId, CancellationToken cancellationToken = default);
    }
}
