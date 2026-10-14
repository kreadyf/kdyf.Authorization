using Microsoft.Extensions.Logging;

namespace kdyf.Authorization.Administration.Abstractions
{
    /// <summary>A change to one person's access, as it was applied.</summary>
    /// <param name="SubjectId">The person's Entra object id.</param>
    /// <param name="SubjectLabel">Their e-mail (or sign-in name), for display.</param>
    /// <param name="Added">Role values assigned.</param>
    /// <param name="Removed">Role values removed.</param>
    /// <param name="ActorObjectId">The administrator's Entra object id.</param>
    /// <param name="ActorEmail">The administrator's e-mail.</param>
    /// <param name="OccurredAt">When it was applied.</param>
    public sealed record AccessChange(
        string SubjectId,
        string SubjectLabel,
        IReadOnlyList<string> Added,
        IReadOnlyList<string> Removed,
        string? ActorObjectId,
        string ActorEmail,
        DateTimeOffset OccurredAt);

    /// <summary>
    /// Tells the rest of the system that somebody's access changed — so an open session can refresh its
    /// menu instead of waiting for its next 403.
    /// </summary>
    /// <remarks>
    /// The default only logs. A host with a real-time channel (SignalR, a message bus) registers its own
    /// before or after <c>AddAuthAdministration</c>; the library uses whatever is registered.
    /// A failure here never undoes nor fails the change: it is logged and the change stands.
    /// <para>
    /// Only changes made THROUGH this application are published. One made directly in the Entra portal
    /// reaches the running sessions when the permission cache expires (<c>CacheDuration</c>).
    /// </para>
    /// </remarks>
    public interface IAccessChangeNotifier
    {
        Task NotifyAsync(AccessChange change, CancellationToken cancellationToken = default);
    }

    /// <summary>The default <see cref="IAccessChangeNotifier"/>: one log line per change.</summary>
    public sealed class LoggingAccessChangeNotifier : IAccessChangeNotifier
    {
        private readonly ILogger<LoggingAccessChangeNotifier> _logger;

        public LoggingAccessChangeNotifier(ILogger<LoggingAccessChangeNotifier> logger) => _logger = logger;

        public Task NotifyAsync(AccessChange change, CancellationToken cancellationToken = default)
        {
            _logger.LogInformation(
                "Access changed for {Subject} ({SubjectId}) by {Actor}: added [{Added}], removed [{Removed}].",
                change.SubjectLabel, change.SubjectId, change.ActorEmail,
                string.Join(", ", change.Added), string.Join(", ", change.Removed));
            return Task.CompletedTask;
        }
    }
}
