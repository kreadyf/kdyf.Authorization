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
    /// Records that a person was seen: their permissions were resolved for a request (a sign-in, a token). Called on a
    /// cache miss only, so at most once per cache duration per person and instance.
    /// </summary>
    /// <remarks>Never in the way: a failure is logged by the caller and the request goes on.</remarks>
    public interface IUserActivityRecorder
    {
        Task RecordAsync(UserIdentity user, CancellationToken cancellationToken = default);
    }
}
