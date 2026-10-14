using Microsoft.Extensions.Logging;

namespace kdyf.Authorization.Abstractions
{
    /// <summary>One administrator reading the application as one person.</summary>
    /// <param name="RealSubjectId">The administrator's immutable id ('oid').</param>
    /// <param name="RealEmail">The administrator's e-mail.</param>
    /// <param name="TargetSubjectId">The simulated person's immutable id.</param>
    /// <param name="TargetEmail">The simulated person's e-mail.</param>
    /// <param name="Path">The request that started it (for <c>Started</c>); null otherwise.</param>
    public sealed record SimulationSession(
        string RealSubjectId,
        string RealEmail,
        string TargetSubjectId,
        string TargetEmail,
        string? Path = null);

    /// <summary>
    /// Keeps the trace of who read the application as whom: the start and the end of each simulation.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Declared here, implemented by the administration package against its audit log — authorization
    /// does not depend on administration. The default only logs.
    /// </para>
    /// <para>
    /// A failure to record <see cref="StartedAsync"/> refuses the simulation: reading somebody else's data
    /// without a trace is exactly what recording it exists to prevent.
    /// </para>
    /// </remarks>
    public interface ISimulationRecorder
    {
        Task StartedAsync(SimulationSession session, CancellationToken cancellationToken = default);

        Task EndedAsync(SimulationSession session, CancellationToken cancellationToken = default);
    }

    /// <summary>The default <see cref="ISimulationRecorder"/>: a log line per start and end.</summary>
    public sealed class LoggingSimulationRecorder : ISimulationRecorder
    {
        private readonly ILogger<LoggingSimulationRecorder> _logger;

        public LoggingSimulationRecorder(ILogger<LoggingSimulationRecorder> logger) => _logger = logger;

        public Task StartedAsync(SimulationSession session, CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("Simulation started: {Real} ({RealId}) as {Target} ({TargetId}), at {Path}.",
                session.RealEmail, session.RealSubjectId, session.TargetEmail, session.TargetSubjectId, session.Path);
            return Task.CompletedTask;
        }

        public Task EndedAsync(SimulationSession session, CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("Simulation ended: {Real} ({RealId}) as {Target} ({TargetId}).",
                session.RealEmail, session.RealSubjectId, session.TargetEmail, session.TargetSubjectId);
            return Task.CompletedTask;
        }
    }
}
