using System.Text.Json;
using kdyf.Authorization.Administration.Abstractions;
using kdyf.Authorization.Abstractions;
using Microsoft.EntityFrameworkCore;

namespace kdyf.Authorization.Administration.Persistence
{
    /// <summary>
    /// <see cref="ISimulationRecorder"/> over the audit log: who read the application as whom, and when it
    /// started and ended. The actor is the REAL administrator, by their Entra object id.
    /// </summary>
    /// <remarks>
    /// Saves its own entry: a simulation changes nothing else, so there is no other change to share a
    /// transaction with. A failure propagates — the simulation then refuses to start.
    /// </remarks>
    public sealed class AuditSimulationRecorder<TContext> : ISimulationRecorder where TContext : DbContext
    {
        private readonly TContext _context;
        private readonly IAuditLog _audit;

        public AuditSimulationRecorder(TContext context, IAuditLog audit)
        {
            _context = context;
            _audit = audit;
        }

        public Task StartedAsync(SimulationSession session, CancellationToken cancellationToken = default) =>
            RecordAsync("simulation.started", session, JsonSerializer.Serialize(new { path = session.Path }), cancellationToken);

        public Task EndedAsync(SimulationSession session, CancellationToken cancellationToken = default) =>
            RecordAsync("simulation.ended", session, null, cancellationToken);

        private async Task RecordAsync(string action, SimulationSession session, string? details, CancellationToken ct)
        {
            _audit.Record(new AuditActor(session.RealSubjectId, session.RealEmail),
                new AuditEntry(action, "user", session.TargetSubjectId, session.TargetEmail, details));
            await _context.SaveChangesAsync(ct);
        }
    }
}
