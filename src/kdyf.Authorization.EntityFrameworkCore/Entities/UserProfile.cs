namespace kdyf.Authorization.EntityFrameworkCore.Entities
{
    /// <summary>
    /// What the application keeps about a person beyond their roles: whether it suspended them, when they were last
    /// seen, and, for people imported from the legacy schema, their old numeric id.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Optional by design: <b>no row means an active person</b>. Rows appear when somebody is seen (the last access),
    /// suspended, or imported. Who the person is (name, e-mail, enabled account) still lives in Entra; the e-mail and
    /// name here are a copy for the screens and the audit, refreshed when the person is seen.
    /// </para>
    /// <para>Suspending is the application's own "no": Entra may still let the person sign in, and they hold nothing.</para>
    /// </remarks>
    public class UserProfile
    {
        /// <summary>The person's Entra object id, as <see cref="UserRole.Normalize"/> writes it.</summary>
        public string ObjectId { get; set; } = string.Empty;

        /// <summary>Their id in the legacy <c>auth.[User]</c> table, for the people imported from it.</summary>
        public int? LegacyUserId { get; set; }

        /// <summary>A copy of the person's e-mail, for the screens and the audit. Entra holds the real one.</summary>
        public string? Email { get; set; }

        /// <summary>A copy of the person's name, for the screens and the audit. Entra holds the real one.</summary>
        public string? DisplayName { get; set; }

        /// <summary>False: suspended by the application. They hold nothing, with a session or with a token.</summary>
        public bool IsActive { get; set; } = true;

        /// <summary>When the row was created (UTC).</summary>
        public DateTime CreatedAt { get; set; }

        /// <summary>The last time they used the application with their own session (not a token, not somebody looking them up), to the minutes of the throttle.</summary>
        public DateTime? LastLoginAt { get; set; }
    }
}
