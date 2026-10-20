using System.Text.Json;
using Microsoft.Extensions.Logging;
using kdyf.Authorization.Administration.Abstractions;

namespace kdyf.Authorization.EntraId.Migration
{
    /// <summary>What one pass of the sync did.</summary>
    /// <param name="Assigned">People in the group who were given the assignment.</param>
    /// <param name="Unassigned">Assignments of people no longer in the group that were removed.</param>
    /// <param name="Failed">Changes Graph refused; the next pass tries them again.</param>
    internal sealed record GateMigrationResult(int Assigned, int Unassigned, int Failed);

    /// <summary>
    /// One pass of the migration: the assignments of the <c>Access</c> app role made equal to the access group — the
    /// missing ones created, the extra ones removed — each change audited with the actor <see cref="Actor"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Removing matters as much as adding: without it, somebody taken out of the group in the Entra portal during the
    /// migration would get their access back the day the gate becomes the assignments.
    /// </para>
    /// <para>
    /// Idempotent: a pass over a migrated tenant changes nothing, and two instances running at once only repeat each
    /// other's work — no lock and no "done" mark. Only the access app role of the configured application is touched;
    /// never the group, "Assignment required", or the roles in the database. People with roles who are not in the group
    /// are not assigned: they have no access today either.
    /// </para>
    /// <para>
    /// An empty group with assignments left is not emptied: it is far likelier to be the wrong group id than a group
    /// everybody left, and emptying would lock everyone out the day the gate changes. It is logged instead.
    /// </para>
    /// </remarks>
    internal sealed class GateMigration
    {
        /// <summary>Who the audit log names for the sync's changes.</summary>
        public static readonly AuditActor Actor = new(null, "system:migration");

        private readonly IAccessDirectory _group;
        private readonly IAccessAssignments _assignments;
        private readonly IAuditLog _audit;
        private readonly Func<CancellationToken, Task> _save;
        private readonly ILogger _logger;

        /// <param name="group">The access group, read.</param>
        /// <param name="assignments">The assignments, written.</param>
        /// <param name="audit">Where each change is recorded.</param>
        /// <param name="save">Saves what <paramref name="audit"/> staged.</param>
        /// <param name="logger">Where the pass is summed up.</param>
        public GateMigration(IAccessDirectory group, IAccessAssignments assignments, IAuditLog audit, Func<CancellationToken, Task> save, ILogger logger)
        {
            _group = group;
            _assignments = assignments;
            _audit = audit;
            _save = save;
            _logger = logger;
        }

        public async Task<GateMigrationResult> RunAsync(CancellationToken ct)
        {
            var members = (await _group.ListWithAccessAsync(ct))
                .ToDictionary(m => m.User.ObjectId, m => m.User.Label, StringComparer.OrdinalIgnoreCase);
            var assigned = await _assignments.ListAsync(ct);
            var assignedIds = assigned.Select(a => a.PrincipalId).ToHashSet(StringComparer.OrdinalIgnoreCase);

            int added = 0, removed = 0, failed = 0;

            foreach (var (objectId, label) in members.Where(m => !assignedIds.Contains(m.Key)))
            {
                if (await TryAsync(() => _assignments.AssignAsync(objectId, ct), "assigning", objectId))
                {
                    Audit("access.migration.assigned", objectId, label);
                    added++;
                }
                else failed++;
            }

            var extra = assigned.Where(a => !members.ContainsKey(a.PrincipalId)).ToList();
            if (members.Count == 0 && extra.Count > 0)
            {
                _logger.LogWarning(
                    "Access gate migration: the access group is empty and {Count} people are assigned. Nothing is removed: check Directory:GroupId.",
                    extra.Count);
            }
            else
            {
                foreach (var assignment in extra)
                {
                    if (await TryAsync(() => _assignments.RemoveAsync(assignment.AssignmentId, ct), "unassigning", assignment.PrincipalId))
                    {
                        Audit("access.migration.unassigned", assignment.PrincipalId, assignment.PrincipalId);
                        removed++;
                    }
                    else failed++;
                }
            }

            if (added + removed > 0)
                await _save(ct);

            var result = new GateMigrationResult(added, removed, failed);
            if (added + removed + failed > 0)
                _logger.LogInformation(
                    "Access gate migration: {Assigned} assigned, {Unassigned} unassigned, {Failed} failed ({Members} in the group).",
                    added, removed, failed, members.Count);
            return result;
        }

        private void Audit(string action, string objectId, string label) =>
            _audit.Record(Actor, new AuditEntry(action, "user", objectId, label, JsonSerializer.Serialize(new { gate = "Migrating" })));

        private async Task<bool> TryAsync(Func<Task> change, string what, string objectId)
        {
            try
            {
                await change();
                return true;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogError(ex, "Access gate migration: {What} {ObjectId} failed; the next pass tries again.", what, objectId);
                return false;
            }
        }
    }
}
