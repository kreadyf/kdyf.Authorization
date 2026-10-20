namespace kdyf.Authorization.Administration.Models
{
    /// <summary>
    /// Request to create a Personal Access Token.
    /// </summary>
    /// <remarks>
    /// There is no role list: a token grants what its OWNER can do at any given moment. To get a narrow
    /// token, give it a narrow owner — a service account in the access group holding a single role.
    /// </remarks>
    public class CreatePatRequest
    {
        /// <summary>A name to recognise the token by. Required.</summary>
        public string Name { get; set; } = string.Empty;

        /// <summary>Expiration. Null = never expires. Normalized to UTC on save.</summary>
        public DateTime? ExpiresAt { get; set; }

        /// <summary>
        /// Entra object id of the owner. Null = whoever is creating it. Naming somebody else is reserved for
        /// administrators, only for an owner who holds nothing beyond the administrator, and exists so an
        /// unattended integration can hold its own credential instead of borrowing a person's.
        /// </summary>
        public string? OwnerObjectId { get; set; }
    }

    /// <summary>
    /// Creation response: includes the token IN PLAINTEXT only once. It cannot be recovered afterwards;
    /// only its hash remains in the database.
    /// </summary>
    public class CreatePatResponse
    {
        /// <summary>The token's id: what the other token calls take.</summary>
        public int PersonalAccessTokenId { get; set; }
        /// <summary>The token's name.</summary>
        public string Name { get; set; } = string.Empty;

        /// <summary>Plaintext token. Show to the user only once; it is never exposed again.</summary>
        public string Token { get; set; } = string.Empty;

        /// <summary>First characters of the token, to recognise it later without the secret.</summary>
        public string? TokenPrefix { get; set; }
        /// <summary>Expiration in UTC. Null: never expires.</summary>
        public DateTime? ExpiresAt { get; set; }

        /// <summary>Entra object id of the owner, whose access the token grants.</summary>
        public string OwnerObjectId { get; set; } = string.Empty;
        /// <summary>The owner's e-mail (or label) at creation.</summary>
        public string OwnerEmail { get; set; } = string.Empty;

        /// <summary>What it can do right now, taken from the owner. Informative: it changes with them.</summary>
        public List<string> Permissions { get; set; } = new();
    }

    /// <summary>A PAT in the listing (without the secret: only the prefix).</summary>
    public class PatResponse
    {
        /// <summary>The token's id.</summary>
        public int PersonalAccessTokenId { get; set; }
        /// <summary>The token's name.</summary>
        public string Name { get; set; } = string.Empty;
        /// <summary>First characters of the token, to recognise it without the secret.</summary>
        public string? TokenPrefix { get; set; }

        /// <summary>Entra object id of the owner, whose access the token grants.</summary>
        public string OwnerObjectId { get; set; } = string.Empty;

        /// <summary>The owner's e-mail when the token was created.</summary>
        public string OwnerEmail { get; set; } = string.Empty;

        /// <summary>The token's own switch, independent from the owner's.</summary>
        public bool IsActive { get; set; }

        /// <summary>
        /// False when the owner holds no access right now (out of the group, disabled, gone): the token then
        /// grants nothing even though <see cref="IsActive"/> is true. Without it the listing would show it
        /// as working.
        /// </summary>
        public bool OwnerHasAccess { get; set; }

        /// <summary>Expiration in UTC. Null: never expires.</summary>
        public DateTime? ExpiresAt { get; set; }
        /// <summary>When the token was created, in UTC.</summary>
        public DateTime CreatedAt { get; set; }
        /// <summary>When it was last used, or null if never. Recorded with a throttle, so approximate.</summary>
        public DateTime? LastUsedAt { get; set; }

        /// <summary>What it grants right now: the owner's effective permissions.</summary>
        public List<string> Permissions { get; set; } = new();
    }
}
