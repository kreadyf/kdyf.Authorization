namespace kdyf.Authorization.AspNetCore
{
    /// <summary>
    /// What the composition itself reads from the library's section (<c>KdyfAuthorization</c> unless the host names
    /// another one): how permissions are cached.
    /// </summary>
    /// <remarks>
    /// <para>
    /// ONE section for everything, but each part is read by whoever owns it: the database by
    /// <c>UseEntityFrameworkStore</c> (<c>ConnectionStringName</c>, <c>Schema</c>), the identity provider by
    /// <c>UseEntraId</c> (<c>EntraId</c>, <c>Directory</c>). Its values may come from several sources: .NET merges
    /// configuration key by key, so secrets go in user secrets, environment variables or Key Vault.
    /// </para>
    /// <para>
    /// What is NOT here, on purpose: which permissions and policies exist and what every member holds (classes
    /// of the host, passed to the builder), the roles and who holds them (the database, administered from the
    /// application), the authentication schemes and the fallback policy (fixed by the library, so a
    /// configuration mistake can never open an endpoint).
    /// </para>
    /// </remarks>
    public sealed class KdyfAuthorizationOptions
    {
        /// <summary>The section read when the host names none.</summary>
        public const string DefaultSectionName = "KdyfAuthorization";

        /// <summary>How permissions are cached.</summary>
        public KdyfAuthorizationSettings Authorization { get; set; } = new();
    }

    /// <summary><c>Authorization</c>.</summary>
    public sealed class KdyfAuthorizationSettings
    {
        /// <summary>
        /// How long a person's effective permissions are cached. It is the MAXIMUM PROPAGATION TIME of a
        /// change made in the identity provider (somebody taken out of the access group, an account disabled) or
        /// directly in the tables, and of any change on the instances that did not serve it. Changes made through
        /// the administration are effective at once on the instance that made them.
        /// </summary>
        public TimeSpan CacheDuration { get; set; } = TimeSpan.FromMinutes(2);

        /// <summary>
        /// How long an EMPTY result is cached. Much shorter on purpose: otherwise somebody just given access
        /// keeps getting 403 for the whole cache duration and the change looks failed.
        /// </summary>
        public TimeSpan EmptyResultCacheDuration { get; set; } = TimeSpan.FromSeconds(30);
    }
}
