using Microsoft.EntityFrameworkCore;
using AuthorizationModel = kdyf.Authorization.EntityFrameworkCore.ModelBuilderExtensions;

namespace kdyf.Authorization.Administration.Persistence
{
    /// <summary>
    /// Registers the administration model (schema <c>auth</c>) in the consumer's
    /// <see cref="ModelBuilder"/>: the audit log.
    /// </summary>
    /// <remarks>
    /// It goes on the SAME <see cref="DbContext"/> as the authorization model, after
    /// <c>ApplyAuthorizationModel()</c>: a token change and its audit entry share one
    /// <c>SaveChanges</c>, so both commit or neither does.
    /// </remarks>
    public static class AdministrationModelBuilderExtensions
    {
        /// <summary>
        /// Configures the administration entities. Call from <c>OnModelCreating</c>, after
        /// <c>ApplyAuthorizationModel()</c>, with the same <paramref name="schema"/>.
        /// </summary>
        public static ModelBuilder ApplyAdministrationModel(this ModelBuilder modelBuilder, string schema = AuthorizationModel.DefaultSchema)
        {
            modelBuilder.Entity<AuditLogEntry>(e =>
            {
                e.ToTable("AuditLog", schema);
                e.HasKey(x => x.AuditLogId);
                e.Property(x => x.AuditLogId).HasColumnName("AuditLogId");
                e.Property(x => x.OccurredAt).HasColumnName("occurredAt");
                e.Property(x => x.ActorObjectId).HasColumnName("actorObjectId").HasMaxLength(50);
                e.Property(x => x.ActorEmail).HasColumnName("actorEmail").HasMaxLength(256).IsRequired();
                e.Property(x => x.Action).HasColumnName("action").HasMaxLength(40).IsRequired();
                e.Property(x => x.TargetType).HasColumnName("targetType").HasMaxLength(20).IsRequired();
                // An object id, a token id, or a role's value — up to 100.
                e.Property(x => x.TargetId).HasColumnName("targetId").HasMaxLength(100);
                e.Property(x => x.TargetLabel).HasColumnName("targetLabel").HasMaxLength(256).IsRequired();
                e.Property(x => x.Details).HasColumnName("details");

                // The three axes of the questions asked of it: about whom, when, and by whom.
                e.HasIndex(x => new { x.TargetType, x.TargetId }).HasDatabaseName("IX_AuditLog_Target");
                e.HasIndex(x => x.OccurredAt).HasDatabaseName("IX_AuditLog_OccurredAt");
                e.HasIndex(x => x.ActorObjectId).HasDatabaseName("IX_AuditLog_ActorObjectId");
            });

            return modelBuilder;
        }
    }
}
