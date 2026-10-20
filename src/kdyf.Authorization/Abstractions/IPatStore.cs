namespace kdyf.Authorization.Abstractions
{
    /// <summary>
    /// Resolves a Personal Access Token by the hash of its secret. Implemented by the consumer
    /// (e.g. against EF Core). Returns <c>null</c> if the token does not exist, is disabled or expired.
    /// </summary>
    public interface IPatStore
    {
        /// <summary>
        /// The token whose secret hashes to <paramref name="tokenHash"/> (SHA-256 of its UTF-8 bytes, as
        /// <see cref="Authentication.PatToken.Hash"/> computes it), or null when there is none, or it is disabled or
        /// expired.
        /// </summary>
        /// <remarks>A store failure should throw, not return null: the PAT handler then fails the authentication.</remarks>
        Task<PatPrincipal?> ResolveAsync(byte[] tokenHash, CancellationToken cancellationToken = default);
    }

    /// <summary>Effective data of a valid PAT: its name and its permission codes (union of its roles).</summary>
    public sealed record PatPrincipal(string Name, IReadOnlySet<string> PermissionCodes);
}
