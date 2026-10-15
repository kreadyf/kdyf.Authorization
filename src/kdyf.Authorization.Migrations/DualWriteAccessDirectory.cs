using Microsoft.Extensions.Logging;
using kdyf.Authorization.Administration.Abstractions;
using kdyf.Authorization.Administration.EntraId;

namespace kdyf.Authorization.EntraId.Migration
{
    /// <summary>
    /// The access directory while the gate migrates: it reads the access group, which still decides, and applies every
    /// grant and revocation to the group AND to the assignments to the Enterprise application.
    /// </summary>
    /// <remarks>
    /// The group first: it is the gate, so its change is the one the administrator's answer depends on, and its failure
    /// fails the call as it always did. The assignment second: if it fails the group change stands, the error is logged,
    /// and the next sync puts the assignment right (<see cref="GateMigration"/>).
    /// </remarks>
    public sealed class DualWriteAccessDirectory : IMigratingAccessDirectory
    {
        private readonly IAccessDirectory _group;
        private readonly IAccessDirectory _assignments;
        private readonly ILogger<DualWriteAccessDirectory> _logger;

        /// <param name="group">The access group: what is read, and written first.</param>
        /// <param name="assignments">The assignments to the Enterprise application: written second.</param>
        /// <param name="logger">Where a failed second write goes.</param>
        public DualWriteAccessDirectory(IAccessDirectory group, IAccessDirectory assignments, ILogger<DualWriteAccessDirectory> logger)
        {
            _group = group;
            _assignments = assignments;
            _logger = logger;
        }

        public Task<IReadOnlyList<DirectoryAccount>> ListWithAccessAsync(CancellationToken cancellationToken = default) =>
            _group.ListWithAccessAsync(cancellationToken);

        public Task<DirectoryAccount?> GetUserAsync(string objectId, CancellationToken cancellationToken = default) =>
            _group.GetUserAsync(objectId, cancellationToken);

        public Task<IReadOnlyList<DirectoryAccount>> GetUsersAsync(IReadOnlyCollection<string> objectIds, CancellationToken cancellationToken = default) =>
            _group.GetUsersAsync(objectIds, cancellationToken);

        public Task<bool> HasAccessAsync(string objectId, CancellationToken cancellationToken = default) =>
            _group.HasAccessAsync(objectId, cancellationToken);

        public async Task GrantAsync(string objectId, CancellationToken cancellationToken = default)
        {
            await _group.GrantAsync(objectId, cancellationToken);
            await Second(() => _assignments.GrantAsync(objectId, cancellationToken), "assigning", objectId);
        }

        public async Task RevokeAsync(string objectId, CancellationToken cancellationToken = default)
        {
            await _group.RevokeAsync(objectId, cancellationToken);
            await Second(() => _assignments.RevokeAsync(objectId, cancellationToken), "unassigning", objectId);
        }

        private async Task Second(Func<Task> write, string what, string objectId)
        {
            try
            {
                await write();
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogError(ex,
                    "Access gate migration: the group was changed for {ObjectId}, but {What} the application failed; the next sync puts it right.",
                    objectId, what);
            }
        }
    }
}
