using Microsoft.Extensions.Caching.Memory;

namespace kdyf.Authorization.Simulation
{
    /// <summary>
    /// Which simulations are running, so the start is recorded once and not on every request.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A simulation is not a server-side session: the client sends <c>X-Simulate-User</c> on every request.
    /// A pair administrator → person counts as one simulation while requests keep arriving; after
    /// <c>SessionIdleTimeout</c> without one, the next request starts (and records) a new one.
    /// </para>
    /// <para>
    /// In memory, per instance: with several instances each may record its own start for the same
    /// simulation. That errs on the side of more trace, never less.
    /// </para>
    /// </remarks>
    public sealed class SimulationSessions
    {
        private const string KeyPrefix = "kdyf:simulation:";

        private readonly IMemoryCache _cache;
        private readonly UserSimulationOptions _options;

        /// <param name="cache">Where the running pairs are kept, per instance.</param>
        /// <param name="options">Supplies <c>SessionIdleTimeout</c>, the sliding expiry of a pair.</param>
        public SimulationSessions(IMemoryCache cache, UserSimulationOptions options)
        {
            _cache = cache;
            _options = options;
        }

        /// <summary>Whether this pair is already simulating. Touching it keeps the session alive.</summary>
        public bool IsActive(string realSubjectId, string targetSubjectId) =>
            _cache.TryGetValue(Key(realSubjectId, targetSubjectId), out _);

        /// <summary>Marks the pair as simulating, after its start was recorded.</summary>
        public void Begin(string realSubjectId, string targetSubjectId) =>
            _cache.Set(Key(realSubjectId, targetSubjectId), true, new MemoryCacheEntryOptions()
                .SetSlidingExpiration(_options.SessionIdleTimeout)
                .SetSize(1));

        /// <summary>Forgets the pair: the next simulated request records a new start.</summary>
        public void End(string realSubjectId, string targetSubjectId) =>
            _cache.Remove(Key(realSubjectId, targetSubjectId));

        private static string Key(string real, string target) =>
            $"{KeyPrefix}{real.ToLowerInvariant()}:{target.ToLowerInvariant()}";
    }
}
