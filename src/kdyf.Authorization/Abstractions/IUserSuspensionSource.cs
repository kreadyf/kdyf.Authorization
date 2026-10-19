namespace kdyf.Authorization.Abstractions
{
    /// <summary>
    /// Whether the application suspended a person: its own "no", on top of the directory. A suspended person holds
    /// nothing, with a session, with a personal access token, or as the target of a simulation.
    /// </summary>
    /// <remarks>
    /// Security contract, the one <see cref="IPermissionStore"/> honours: an unknown person is NOT suspended (no
    /// profile means active); a real failure THROWS, and the caller denies. Keyed by the immutable subject id.
    /// </remarks>
    public interface IUserSuspensionSource
    {
        /// <summary>True when the application suspended the person.</summary>
        Task<bool> IsSuspendedAsync(string subjectId, CancellationToken cancellationToken = default);
    }

    /// <summary>
    /// Records that a person signed in: a request of their own session (on a cache miss of their permissions).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Not when somebody else's permissions are resolved: the vault listing who may use it, the administration valuing a
    /// token, a simulation borrowing a person's permissions, or a background job. None of those is that person's access.
    /// </para>
    /// <para>
    /// Not when one of their personal access tokens is used either: a token is an integration, not the person, and has
    /// its own last use (<c>PersonalAccessToken.lastUsedAt</c>).
    /// </para>
    /// <para>Never in the way: a failure is logged by the caller and the request goes on.</para>
    /// </remarks>
    public interface IUserActivityRecorder
    {
        Task RecordAsync(UserIdentity user, CancellationToken cancellationToken = default);
    }
}
