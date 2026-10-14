namespace kdyf.Authorization.Administration.Abstractions
{
    /// <summary>A person in the directory, with whether their account is enabled.</summary>
    public sealed record DirectoryAccount(DirectoryUser User, bool AccountEnabled);

    /// <summary>
    /// Who may use the application at all, read AND written: the gate the administration opens and closes. Today
    /// an Entra security group (<c>GraphAccessGroupDirectory</c>); the gate does not change this contract.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Having access lets a person in; what they may do is the roles the application gives them. Revoking access
    /// takes it away, whatever roles they hold — their account in the directory is never touched: deprovisioning
    /// it belongs to whoever administers the tenant.
    /// </para>
    /// <para>
    /// Every failure throws <see cref="DirectoryException"/>; "not found" answers null, granting access somebody
    /// already has and revoking access already gone are not errors.
    /// </para>
    /// </remarks>
    public interface IAccessDirectory
    {
        /// <summary>Every user with access.</summary>
        Task<IReadOnlyList<DirectoryAccount>> ListWithAccessAsync(CancellationToken cancellationToken = default);

        /// <summary>The user, or null when the directory does not know them.</summary>
        Task<DirectoryAccount?> GetUserAsync(string objectId, CancellationToken cancellationToken = default);

        /// <summary>Those of <paramref name="objectIds"/> the directory knows. Unknown ids are left out.</summary>
        Task<IReadOnlyList<DirectoryAccount>> GetUsersAsync(IReadOnlyCollection<string> objectIds, CancellationToken cancellationToken = default);

        /// <summary>Whether the user has access.</summary>
        Task<bool> HasAccessAsync(string objectId, CancellationToken cancellationToken = default);

        /// <summary>Gives the user access. Idempotent.</summary>
        Task GrantAsync(string objectId, CancellationToken cancellationToken = default);

        /// <summary>
        /// Takes the access this directory gave. Idempotent. With a group, only the DIRECT membership goes: somebody
        /// also in a nested group keeps access through it — check <see cref="HasAccessAsync"/> afterwards.
        /// </summary>
        Task RevokeAsync(string objectId, CancellationToken cancellationToken = default);
    }
}
