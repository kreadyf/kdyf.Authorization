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
        /// <summary>How many entries match the filter, across all pages.</summary>
        public int TotalCount { get; set; }
        /// <summary>The <c>skip</c> that was asked for.</summary>
        public int Skip { get; set; }
        /// <summary>The <c>take</c> that was asked for (the page itself is capped).</summary>
        public int Take { get; set; }
        /// <summary>How many entries this page holds.</summary>
        public int Count { get; set; }
        /// <summary>The entries of this page.</summary>
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

        /// <summary>Entries at or after this moment (UTC, as stored).</summary>
        public DateTime? From { get; set; }
        /// <summary>Entries up to the END of this day: the time of day is ignored.</summary>
        public DateTime? To { get; set; }
    }

    /// <summary>One entry of the audit log.</summary>
    public class AuditEntryResponse
    {
        /// <summary>The entry's id.</summary>
        public long AuditLogId { get; set; }
        /// <summary>When the change was recorded, in UTC.</summary>
        public DateTime OccurredAt { get; set; }
        /// <summary>The administrator's immutable Entra object id.</summary>
        public string? ActorObjectId { get; set; }
        /// <summary>The administrator's e-mail, frozen at the time.</summary>
        public string ActorEmail { get; set; } = string.Empty;
        /// <summary>What was done, e.g. <c>access.granted</c> or <c>pat.created</c>.</summary>
        public string Action { get; set; } = string.Empty;
        /// <summary>The kind of target, e.g. <c>user</c>, <c>role</c> or <c>pat</c>.</summary>
        public string TargetType { get; set; } = string.Empty;
        /// <summary>A user's Entra object id, a role's value or a token's id.</summary>
        public string? TargetId { get; set; }
        /// <summary>E-mail or name of the target, frozen at the time: it survives the object.</summary>
        public string TargetLabel { get; set; } = string.Empty;

        /// <summary>JSON with the delta of the change, exactly as it was stored.</summary>
        public string? Details { get; set; }
    }
}
