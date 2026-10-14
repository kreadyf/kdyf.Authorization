using System.Security.Claims;
using kdyf.Authorization.Administration.Models;

namespace kdyf.Authorization.Administration
{
    /// <summary>
    /// Starting, ending and offering a user simulation: an administrator reading the application as another user —
    /// read-only, with the real and the simulated user kept apart and both recorded.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The header is what simulates, not this service: the swap and the refusal of writes happen for every request in
    /// kdyf.Authorization, before any endpoint runs. This service tells the client up front whether a simulation would
    /// be accepted, records its start and end, and lists who can be simulated — with the same rules
    /// (<see cref="kdyf.Authorization.Simulation.SimulationRules"/>), so neither promises what a request then refuses.
    /// </para>
    /// <para>
    /// Every operation needs an interactive sign-in that is not simulating: the audit has to name a person behind
    /// every simulation, and a borrowed principal must never start or end anything in anybody's name.
    /// </para>
    /// </remarks>
    public interface ISimulationAdminService
    {
        /// <summary>
        /// Checks the caller may read the application as the person with <paramref name="email"/>, records the start and
        /// answers how to carry on. A pair already simulating is resumed, without a second record.
        /// </summary>
        /// <param name="caller">The caller's principal.</param>
        /// <param name="email">Who to simulate. Compared trimmed and lower-case.</param>
        /// <param name="path">Where the start was asked for, recorded with it.</param>
        /// <param name="ct">Cancels the checks; a start that was recorded stays recorded.</param>
        Task<SimulationResult<SimulationStart>> StartAsync(ClaimsPrincipal caller, string? email, string? path, CancellationToken ct);

        /// <summary>
        /// Records the end of the caller's simulation of that person — found even if they lost their access meanwhile —
        /// and forgets the session, so a later simulation records a new start.
        /// </summary>
        Task<SimulationResult<bool>> EndAsync(ClaimsPrincipal caller, string? email, CancellationToken ct);

        /// <summary>
        /// Everybody with access but the caller, each with whether a start would be accepted and, when not, why. Ordered
        /// by name.
        /// </summary>
        Task<SimulationResult<IReadOnlyList<SimulationCandidate>>> ListCandidatesAsync(ClaimsPrincipal caller, CancellationToken ct);
    }
}
