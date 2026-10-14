using kdyf.Authorization.Administration.Validation;

namespace kdyf.Authorization.Administration.Models
{
    /// <summary>One side of a session: who signed in, or who the session is served as.</summary>
    /// <param name="ObjectId">Immutable id ('oid').</param>
    /// <param name="Email">Normalised e-mail.</param>
    public sealed record SimulationUser(string? ObjectId, string? Email);

    /// <summary>
    /// Who a session is for. The real and the effective user are kept apart, always: outside a simulation they are the
    /// same person; during one the real user is the administrator and the effective user the person being simulated.
    /// </summary>
    /// <param name="IsSimulating">True while the session is served as somebody else.</param>
    /// <param name="RealUser">Who actually signed in — the one every audit entry names.</param>
    /// <param name="EffectiveUser">Whose permissions and data the session is served with.</param>
    /// <param name="ReadOnly">True when the server refuses every write in this session.</param>
    public sealed record SimulationContext(bool IsSimulating, SimulationUser RealUser, SimulationUser EffectiveUser, bool ReadOnly);

    /// <summary>A simulation that has just been started, and how the client keeps it going.</summary>
    /// <param name="Context">The session as it will be on the next simulated request.</param>
    /// <param name="HeaderName">The header the client sends on every request while simulating.</param>
    /// <param name="HeaderValue">Its value: the e-mail of the person being simulated.</param>
    /// <param name="IdleTimeout">After this long without a simulated request, the next one records a new start.</param>
    /// <param name="Resumed">True when this pair was already simulating, so no new start was recorded.</param>
    public sealed record SimulationStart(SimulationContext Context, string HeaderName, string HeaderValue, TimeSpan IdleTimeout, bool Resumed);

    /// <summary>A person with access, and whether the caller may simulate them.</summary>
    /// <param name="ObjectId">Immutable id ('oid').</param>
    /// <param name="Email">Normalised e-mail: what to start the simulation with.</param>
    /// <param name="Name">Display name, when the directory has one.</param>
    /// <param name="CanSimulate">True when a start would be accepted.</param>
    /// <param name="Reason">Why not, when <paramref name="CanSimulate"/> is false. Fit to show.</param>
    public sealed record SimulationCandidate(string ObjectId, string? Email, string? Name, bool CanSimulate, string? Reason);

    /// <summary>
    /// What a simulation service answers: the data, a refusal (<see cref="ValidationResult.Validation"/>), or — when the
    /// person named does not exist or may not be simulated — <see cref="NotFound"/>, the same either way on purpose.
    /// </summary>
    public sealed class SimulationResult<T> : ValidationResult<T>
    {
        /// <summary>Set when nobody who may be simulated answers to the e-mail. Fit to show.</summary>
        public string? NotFound { get; set; }

        internal static SimulationResult<T> Ok(T data)
        {
            var result = new SimulationResult<T> { Data = data };
            result.Validation.IsValid = true;
            return result;
        }

        internal static SimulationResult<T> Refused(string reason)
        {
            var result = new SimulationResult<T>();
            result.Validation.Errors.Add(reason);
            return result;
        }

        internal static SimulationResult<T> FieldError(string field, string message)
        {
            var result = new SimulationResult<T>();
            result.Validation.AddFieldError(field, message);
            return result;
        }

        internal static SimulationResult<T> Missing(string email) =>
            new() { NotFound = $"An active user with the e-mail {email} was not found." };
    }
}
