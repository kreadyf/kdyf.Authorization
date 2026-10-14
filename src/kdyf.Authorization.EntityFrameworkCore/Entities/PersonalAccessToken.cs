namespace kdyf.Authorization.EntityFrameworkCore.Entities
{
    /// <summary>
    /// Personal Access Token: a machine/integration credential owned by a person.
    /// Only the token's SHA-256 hash (<see cref="TokenHash"/>) is persisted, never the plaintext.
    /// </summary>
    public class PersonalAccessToken
    {
        public int PersonalAccessTokenId { get; set; }

        /// <summary>Human-readable label for the token.</summary>
        public string Name { get; set; } = string.Empty;

        /// <summary>SHA-256 (32 bytes) of the token. The plaintext is shown only once, at creation.</summary>
        public byte[] TokenHash { get; set; } = Array.Empty<byte>();

        /// <summary>First characters of the token, to identify it in the UI without revealing the secret.</summary>
        public string? TokenPrefix { get; set; }

        /// <summary>
        /// The owner's immutable Entra object id ('oid'). There is no user table to point at: people
        /// live in Entra, and the token is worth what the owner holds right now (group membership and roles).
        /// </summary>
        public string OwnerObjectId { get; set; } = string.Empty;

        /// <summary>The owner's e-mail when the token was created, frozen for the listing. Display only:
        /// nothing is resolved by it.</summary>
        public string OwnerLabel { get; set; } = string.Empty;

        /// <summary>Kill switch: false = disabled (equivalent to revoked).</summary>
        public bool IsActive { get; set; } = true;

        /// <summary>Expiration (UTC). Null = never expires.</summary>
        public DateTime? ExpiresAt { get; set; }

        public DateTime CreatedAt { get; set; }

        public DateTime? LastUsedAt { get; set; }

        // A token has NO roles of its own on purpose: it grants what its owner can do at that moment,
        // resolved through OwnerObjectId on every request. Storing them here is what used to let a
        // token keep permissions its owner had already lost.
    }
}
