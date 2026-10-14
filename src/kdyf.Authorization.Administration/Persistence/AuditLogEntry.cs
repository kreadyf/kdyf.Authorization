namespace kdyf.Authorization.Administration.Persistence
{
    /// <summary>
    /// One line of the audit log. Only ever inserted: never updated or deleted.
    /// </summary>
    public class AuditLogEntry
    {
        public long AuditLogId { get; set; }

        public DateTime OccurredAt { get; set; }

        /// <summary>The administrator's immutable Entra object id. The e-mail next to it is frozen, this
        /// is what still identifies them after a rename.</summary>
        public string? ActorObjectId { get; set; }

        public string ActorEmail { get; set; } = string.Empty;

        public string Action { get; set; } = string.Empty;

        public string TargetType { get; set; } = string.Empty;

        /// <summary>A user's Entra object id, or a token's id.</summary>
        public string? TargetId { get; set; }

        public string TargetLabel { get; set; } = string.Empty;

        /// <summary>JSON with the delta of the change.</summary>
        public string? Details { get; set; }
    }
}
