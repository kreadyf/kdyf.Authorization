using kdyf.Authorization.Abstractions;

namespace kdyf.Authorization.Administration.Abstractions
{
    /// <summary>
    /// Who made the change: the real administrator, by their immutable Entra id, and their e-mail
    /// frozen at the time (people are renamed, and leave).
    /// </summary>
    public sealed record AuditActor(string? ObjectId, string Email)
    {
        public static AuditActor From(UserIdentity identity) =>
            new(identity.SubjectId, identity.Email ?? identity.SubjectId ?? "(unknown)");
    }

    /// <summary>
    /// A change in who can do what.
    /// </summary>
    /// <param name="Action"><c>access.granted</c>, <c>access.roles.changed</c>, <c>access.revoked</c>,
    /// <c>role.created</c>, <c>directory.invited</c>, <c>pat.created</c>…</param>
    /// <param name="TargetType"><c>user</c>, <c>role</c> or <c>pat</c>.</param>
    /// <param name="TargetId">The Entra object id of a user, or the id of a token.</param>
    /// <param name="TargetLabel">E-mail or name, frozen: it survives the object.</param>
    /// <param name="Details">
    /// JSON with the DELTA, not the final state. "now has [Admin, Editor]" does not say what changed;
    /// <c>{"added":["Portal.Admin"]}</c> does — and that is the question that ends up being asked.
    /// </param>
    public sealed record AuditEntry(
        string Action,
        string TargetType,
        string? TargetId,
        string TargetLabel,
        string? Details = null);

    /// <summary>
    /// Log of access changes.
    /// </summary>
    /// <remarks>
    /// <see cref="Record"/> does NOT persist: it leaves the entry staged for the caller's
    /// <c>SaveChanges</c>, so a change in the database and its entry are one transaction. A change to the
    /// access group cannot be — Graph is not part of the database transaction — so the services record it
    /// with the database change it goes with, and report plainly when the Graph half failed.
    ///
    /// Secrets are never recorded: not the plaintext token, not its hash, not an invitation link.
    /// </remarks>
    public interface IAuditLog
    {
        void Record(AuditActor actor, AuditEntry entry);
    }
}
