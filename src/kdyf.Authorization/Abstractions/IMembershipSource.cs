namespace kdyf.Authorization.Abstractions
{
    /// <summary>
    /// What the directory says about one person, right now: whether their account is enabled, and whether
    /// they belong to the application's access group.
    /// </summary>
    /// <param name="AccountEnabled">False when the account is disabled in the directory.</param>
    /// <param name="IsMember">True when they are in the access group, directly or through a nested group.</param>
    public sealed record Membership(bool AccountEnabled, bool IsMember)
    {
        /// <summary>May use the application at all. Without it they hold nothing, whatever roles they have.</summary>
        public bool HasAccess => AccountEnabled && IsMember;
    }

    /// <summary>A person found in the directory by e-mail.</summary>
    /// <param name="SubjectId">Their immutable id ('oid').</param>
    /// <param name="Email">The address they were found by, normalised (trimmed, lower-case).</param>
    /// <param name="DisplayName">For the name on screen. Optional.</param>
    public sealed record DirectoryIdentity(string SubjectId, string Email, string? DisplayName);

    /// <summary>
    /// Who may use the application: the members of one directory group. In production, a Microsoft Entra ID
    /// security group, read through Microsoft Graph.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The group is the gate, not the source of permissions: what a member may DO comes from the roles the
    /// application's administrators give them (<see cref="IUserRoleSource"/>). Somebody outside the group
    /// holds nothing, even with roles left in the database.
    /// </para>
    /// <para>Security contract, the same one <see cref="IPermissionStore"/> honours:</para>
    /// <list type="bullet">
    /// <item>Unknown person: <c>null</c>. Never throw for "not found".</item>
    /// <item>A real failure (the directory is down, the credential expired): THROW. The caller turns it into a
    /// denial; a failure must never read as "still a member".</item>
    /// <item>Keyed by the immutable subject id, never by e-mail: a guest's sign-in name carries
    /// <c>#EXT#</c>, and an e-mail can be reassigned to somebody else.</item>
    /// </list>
    /// </remarks>
    public interface IMembershipSource
    {
        /// <summary>The person's membership, or null when the directory does not know them.</summary>
        Task<Membership?> GetMembershipAsync(string subjectId, CancellationToken cancellationToken = default);

        /// <summary>
        /// The person with this e-mail, or null. Used to resolve a simulation target, which is named by e-mail
        /// because that is what an administrator types.
        /// </summary>
        Task<DirectoryIdentity?> FindByEmailAsync(string email, CancellationToken cancellationToken = default);
    }
}
