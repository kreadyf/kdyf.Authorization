using kdyf.Authorization.Administration.Models;
using kdyf.Authorization.Administration.Persistence;
using kdyf.Authorization.Administration.Validation;
using Microsoft.EntityFrameworkCore;

namespace kdyf.Authorization.Administration
{
    /// <summary>Query over the audit log. Read-only: nobody rewrites history.</summary>
    public interface IAuditAdminService
    {
        Task<ValidationResult<PagedResult<AuditEntryResponse>>> ListAsync(
            AuditFilter filter, int skip, int take, CancellationToken ct);
    }

    /// <inheritdoc cref="IAuditAdminService"/>
    /// <typeparam name="TContext">Consumer's DbContext with the administration model applied.</typeparam>
    public sealed class AuditAdminService<TContext> : IAuditAdminService where TContext : DbContext
    {
        /// <summary>Page cap: the history grows without end and nobody looks at a thousand rows at once.</summary>
        private const int MaxTake = 500;

        private readonly TContext _context;

        public AuditAdminService(TContext context) => _context = context;

        public async Task<ValidationResult<PagedResult<AuditEntryResponse>>> ListAsync(
            AuditFilter filter, int skip, int take, CancellationToken ct)
        {
            var query = _context.Set<AuditLogEntry>().AsNoTracking();

            if (!string.IsNullOrWhiteSpace(filter.TargetType))
                query = query.Where(e => e.TargetType == filter.TargetType);

            if (!string.IsNullOrWhiteSpace(filter.TargetId))
                query = query.Where(e => e.TargetId == filter.TargetId);

            if (!string.IsNullOrWhiteSpace(filter.ActorObjectId))
                query = query.Where(e => e.ActorObjectId == filter.ActorObjectId);

            if (!string.IsNullOrWhiteSpace(filter.Action))
                query = query.Where(e => e.Action == filter.Action);

            if (filter.From.HasValue)
                query = query.Where(e => e.OccurredAt >= filter.From.Value);

            // Up to the END of that day: whoever filters "up to the 22nd" expects to see the 22nd.
            if (filter.To.HasValue)
            {
                var until = filter.To.Value.Date.AddDays(1);
                query = query.Where(e => e.OccurredAt < until);
            }

            if (!string.IsNullOrWhiteSpace(filter.SearchBy))
            {
                var term = filter.SearchBy.Trim();
                query = query.Where(e => e.ActorEmail.Contains(term) || e.TargetLabel.Contains(term));
            }

            var totalCount = await query.CountAsync(ct);

            // Most recent first: that is how a log is read.
            var page = await query
                .OrderByDescending(e => e.OccurredAt)
                .ThenByDescending(e => e.AuditLogId)
                .Skip(Math.Max(0, skip))
                .Take(Math.Clamp(take, 1, MaxTake))
                .Select(e => new AuditEntryResponse
                {
                    AuditLogId = e.AuditLogId,
                    OccurredAt = e.OccurredAt,
                    ActorObjectId = e.ActorObjectId,
                    ActorEmail = e.ActorEmail,
                    Action = e.Action,
                    TargetType = e.TargetType,
                    TargetId = e.TargetId,
                    TargetLabel = e.TargetLabel,
                    Details = e.Details
                })
                .ToListAsync(ct);

            return Outcome.Ok(new PagedResult<AuditEntryResponse>
            {
                TotalCount = totalCount,
                Skip = skip,
                Take = take,
                Count = page.Count,
                Result = page
            });
        }
    }
}
