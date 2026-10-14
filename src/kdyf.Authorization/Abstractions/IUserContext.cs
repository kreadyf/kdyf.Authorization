namespace kdyf.Authorization.Abstractions
{
    /// <summary>
    /// Who the current request is FOR. The one place application code should ask "whose rows are
    /// these?" — inject this instead of reaching into <c>HttpContext.User</c> or reading claims by
    /// hand.
    /// </summary>
    /// <remarks>
    /// <para>
    /// It exists because an application has two identity questions, and they are easy to answer in
    /// two different places by accident: authorization asks "may this caller do X?" (the permission
    /// system), and every scoped query asks "whose data is this?". When those two read from
    /// different sources, a feature like user simulation fixes one and silently leaves the other
    /// showing the administrator's own data behind somebody else's menu.
    /// </para>
    /// <para>
    /// Here they cannot diverge: this reads the SAME <see cref="System.Security.Claims.ClaimsPrincipal"/>
    /// the authorization handler reads, through the same <see cref="IUserIdentityResolver"/>. Swap
    /// the principal once and both answers follow — which is exactly what
    /// <c>SimulationClaimsTransformation</c> does.
    /// </para>
    /// </remarks>
    public interface IUserContext
    {
        /// <summary>False for an anonymous request, and for a principal carrying none of the
        /// configured identity claims. Both mean nothing may be scoped to anyone.</summary>
        bool IsAuthenticated { get; }

        /// <summary>The user's e-mail, normalised the way the permission store compares it
        /// (trimmed, lower-case). Null for a non-person principal such as a PAT.</summary>
        string? Email { get; }

        /// <summary>The immutable subject id ('oid' in Entra). Null when the token carries none.</summary>
        string? SubjectId { get; }

        /// <summary>
        /// True when this request is being served AS somebody else. Useful for a banner, an audit
        /// line, or refusing an action that should never be taken on a borrowed identity.
        /// </summary>
        bool IsSimulating { get; }

        /// <summary>
        /// The e-mail of whoever actually signed in. Equal to <see cref="Email"/> normally; during a
        /// simulation it is the administrator behind it — the honest answer to "who did this".
        /// </summary>
        string? RealEmail { get; }

        /// <summary>
        /// The immutable id ('oid') of whoever actually signed in. Equal to <see cref="SubjectId"/> normally;
        /// during a simulation it is the administrator's — the key that survives a renamed e-mail.
        /// </summary>
        string? RealSubjectId { get; }
    }
}
