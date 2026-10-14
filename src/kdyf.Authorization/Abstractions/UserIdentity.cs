namespace kdyf.Authorization.Abstractions
{
    /// <summary>
    /// Identity of a user, resolved from the token claims.
    /// </summary>
    /// <param name="SubjectId">
    /// Immutable subject identifier ('oid' claim in Azure AD). It is the primary identity:
    /// it does not change even if the user changes email.
    /// </param>
    /// <param name="Email">
    /// User's email. Used to onboard and to locate the user the first time,
    /// but it is mutable: it must not be used as the primary key in the store.
    /// </param>
    public sealed record UserIdentity(string? SubjectId, string? Email)
    {
        /// <summary>
        /// Stable key for caching. Prefers the SubjectId because it is immutable.
        /// </summary>
        public string CacheKey => SubjectId ?? Email ?? string.Empty;

        /// <summary>
        /// An identity without SubjectId or Email identifies no one and cannot be authorized.
        /// </summary>
        public bool IsEmpty => string.IsNullOrWhiteSpace(SubjectId) && string.IsNullOrWhiteSpace(Email);
    }
}
