namespace kdyf.Authorization.Administration.Persistence
{
    /// <summary>
    /// One line of the audit log. Only ever inserted: never updated or deleted.
    /// </summary>
    public class AuditLogEntry
    {
        /// <summary>The entry's id, assigned on insert.</summary>
        public long AuditLogId { get; set; }

        /// <summary>When the change was recorded, in UTC.</summary>
        public DateTime OccurredAt { get; set; }

        /// <summary>The administrator's immutable Entra object id. The e-mail next to it is frozen, this
        /// is what still identifies them after a rename.</summary>
        public string? ActorObjectId { get; set; }

        /// <summary>The administrator's e-mail, frozen at the time.</summary>
        public string ActorEmail { get; set; } = string.Empty;

        /// <summary>What was done, e.g. <c>access.granted</c> or <c>pat.created</c>.</summary>
        public string Action { get; set; } = string.Empty;

        /// <summary>The kind of target, e.g. <c>user</c>, <c>role</c> or <c>pat</c>.</summary>
        public string TargetType { get; set; } = string.Empty;

        /// <summary>A user's Entra object id, or a token's id.</summary>
        public string? TargetId { get; set; }

        /// <summary>E-mail or name of the target, frozen at the time: it survives the object.</summary>
        public string TargetLabel { get; set; } = string.Empty;

        /// <summary>JSON with the delta of the change.</summary>
        public string? Details { get; set; }
    }
}
