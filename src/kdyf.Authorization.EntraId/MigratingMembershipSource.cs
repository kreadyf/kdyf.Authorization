using Microsoft.Extensions.Logging;
using kdyf.Authorization.Abstractions;

namespace kdyf.Authorization.EntraId
{
    /// <summary>
    /// <see cref="IMembershipSource"/> for <see cref="AccessGate.Migrating"/>: the access group still decides, and the
    /// assignments to the Enterprise application are read alongside and compared — every difference is a log warning.
    /// </summary>
    /// <remarks>
    /// <para>
    /// What tells when the migration is done: once these warnings stay at zero for days, the assignments say what the
    /// group says and the gate can move to <see cref="AccessGate.AppAssignment"/>. Nobody loses access in the meantime,
    /// because the answer is always the group's.
    /// </para>
    /// <para>
    /// A failure of the assignment side is logged and does not deny: the group is the gate. A failure of the group side
    /// throws, as it always did.
    /// </para>
    /// </remarks>
    public sealed class MigratingMembershipSource : IMembershipSource
    {
        private readonly GraphMembershipSource _group;
        private readonly GraphAppAssignmentMembershipSource _assignments;
        private readonly ILogger<MigratingMembershipSource> _logger;

        public MigratingMembershipSource(
            GraphMembershipSource group, GraphAppAssignmentMembershipSource assignments, ILogger<MigratingMembershipSource> logger)
        {
            _group = group;
            _assignments = assignments;
            _logger = logger;
        }

        public async Task<Membership?> GetMembershipAsync(string subjectId, CancellationToken cancellationToken = default)
        {
            var groupCall = _group.GetMembershipAsync(subjectId, cancellationToken);
            var assignmentCall = CompareAsync(subjectId, cancellationToken);

            var decided = await groupCall;
            var assigned = await assignmentCall;

            if (assigned.Read && (decided?.IsMember == true) != assigned.IsMember)
                _logger.LogWarning(
                    "Access gate migration: {SubjectId} is {Group} the access group but {Assignment} to the application. The group decides.",
                    subjectId,
                    decided?.IsMember == true ? "in" : "not in",
                    assigned.IsMember ? "assigned" : "not assigned");

            return decided;
        }

        public Task<DirectoryIdentity?> FindByEmailAsync(string email, CancellationToken cancellationToken = default) =>
            _group.FindByEmailAsync(email, cancellationToken);

        private async Task<(bool Read, bool IsMember)> CompareAsync(string subjectId, CancellationToken cancellationToken)
        {
            try
            {
                return (true, (await _assignments.GetMembershipAsync(subjectId, cancellationToken))?.IsMember == true);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogWarning(ex, "Access gate migration: the assignment of {SubjectId} could not be read; the group decides.", subjectId);
                return (false, false);
            }
        }
    }
}
