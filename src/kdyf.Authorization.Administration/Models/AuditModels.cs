namespace kdyf.Authorization.Administration.Models
{
    /// <summary>
    /// A page of results.
    /// </summary>
    /// <remarks>
    /// Declared here so the library does not depend on any type of the consumer. It is what a 200
    /// from <c>/auth/audit/{skip}/{take}</c> returns, as is.
    /// </remarks>
    public class PagedResult<T>
    {
        public int TotalCount { get; set; }
        public int Skip { get; set; }
        public int Take { get; set; }
        public int Count { get; set; }
        public IEnumerable<T> Result { get; set; } = Array.Empty<T>();
    }

    /// <summary>Audit log filter. All optional: with nothing set, the full history.</summary>
    public class AuditFilter
    {
        /// <summary><c>user</c> or <c>pat</c>.</summary>
        public string? TargetType { get; set; }

        /// <summary>A user's Entra object id or a token's id. Answers "what has happened to this person?".</summary>
        public string? TargetId { get; set; }

        /// <summary>The administrator's Entra object id. Answers "what has this person done?".</summary>
        public string? ActorObjectId { get; set; }

        /// <summary>Exact action (<c>access.roles.changed</c>…).</summary>
        public string? Action { get; set; }

        /// <summary>Free text over the actor and the target e-mails and labels.</summary>
        public string? SearchBy { get; set; }

        public DateTime? From { get; set; }
        public DateTime? To { get; set; }
    }

    public class AuditEntryResponse
    {
        public long AuditLogId { get; set; }
        public DateTime OccurredAt { get; set; }
        public string? ActorObjectId { get; set; }
        public string ActorEmail { get; set; } = string.Empty;
        public string Action { get; set; } = string.Empty;
        public string TargetType { get; set; } = string.Empty;
        public string? TargetId { get; set; }
        public string TargetLabel { get; set; } = string.Empty;

        /// <summary>JSON with the delta of the change, exactly as it was stored.</summary>
        public string? Details { get; set; }
    }
}
