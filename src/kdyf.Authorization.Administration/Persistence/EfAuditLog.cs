using kdyf.Authorization.Administration.Abstractions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace kdyf.Authorization.Administration.Persistence
{
    /// <summary>
    /// <see cref="IAuditLog"/> over the consumer's <typeparamref name="TContext"/>.
    /// </summary>
    /// <remarks>
    /// Adds the entry to the SAME context the caller saves, and does not call SaveChanges itself: a
    /// token change and its entry commit together, and an Entra change is recorded in the save that
    /// follows Graph's confirmation.
    /// </remarks>
    internal sealed class EfAuditLog<TContext> : IAuditLog where TContext : DbContext
    {
        private readonly TContext _db;

        public EfAuditLog(TContext db) => _db = db;

        public void Record(AuditActor actor, AuditEntry entry)
        {
            _db.Add(new AuditLogEntry
            {
                OccurredAt = DateTime.UtcNow,
                ActorObjectId = actor.ObjectId,
                ActorEmail = actor.Email,
                Action = entry.Action,
                TargetType = entry.TargetType,
                TargetId = entry.TargetId,
                TargetLabel = entry.TargetLabel,
                Details = entry.Details
            });
        }
    }

    /// <summary>Registration of the Entity Framework audit log.</summary>
    public static class EfAuditLogExtensions
    {
        /// <summary>
        /// Registers <see cref="IAuditLog"/> against the given <typeparamref name="TContext"/>
        /// (which must have <see cref="AdministrationModelBuilderExtensions.ApplyAdministrationModel"/> applied).
        /// </summary>
        public static IServiceCollection AddEfAuditLog<TContext>(this IServiceCollection services)
            where TContext : DbContext
        {
            services.AddScoped<IAuditLog, EfAuditLog<TContext>>();
            return services;
        }
    }
}
