namespace kdyf.Authorization.Abstractions
{
    /// <summary>
    /// The user a simulation is about to borrow: enough to build a principal, and nothing more.
    /// </summary>
    /// <param name="Email">Normalised e-mail — what the permission store compares by.</param>
    /// <param name="SubjectId">Immutable id ('oid'). Null when the user has never signed in.</param>
    /// <param name="DisplayName">For the name on screen. Optional.</param>
    public sealed record SimulationTarget(string Email, string? SubjectId, string? DisplayName);

    /// <summary>
    /// Finds the user a simulation names. The consumer decides where users live; the package only
    /// needs to know whether this one exists and may be borrowed.
    /// </summary>
    /// <remarks>
    /// Returning null covers both "no such user" and "not active", on purpose: the middleware turns
    /// either into the same refusal, and telling the two apart across an API would answer whether a
    /// given address is registered — to somebody who has already proved they administer users, but
    /// still a distinction with no use here.
    /// </remarks>
    public interface ISimulationTargetResolver
    {
        Task<SimulationTarget?> ResolveAsync(string email, CancellationToken cancellationToken = default);
    }
}
