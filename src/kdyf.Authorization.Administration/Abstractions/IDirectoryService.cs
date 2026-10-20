namespace kdyf.Authorization.Administration.Abstractions
{
    /// <summary>A person as the identity provider's directory knows them.</summary>
    /// <param name="ObjectId">Immutable identifier in the directory (the 'oid'). The only key anything
    /// is resolved by: the e-mail of a guest is not a reliable one.</param>
    /// <param name="DisplayName">Name to show. May be null for a guest who has not redeemed yet.</param>
    /// <param name="Email">Real e-mail address. For guests it lives in 'mail', NOT in the UPN.</param>
    /// <param name="UserPrincipalName">Sign-in name. For a guest it has the
    /// <c>person_domain.com#EXT#@tenant.onmicrosoft.com</c> shape, which is why it is not the e-mail.</param>
    /// <param name="IsGuest">True for external users invited through B2B.</param>
    public sealed record DirectoryUser(
        string ObjectId,
        string? DisplayName,
        string? Email,
        string? UserPrincipalName,
        bool IsGuest)
    {
        /// <summary>What to call them in a log line or an audit entry: e-mail, else UPN, else the id.</summary>
        public string Label => Email ?? UserPrincipalName ?? ObjectId;
    }

    /// <summary>Result of inviting an external user.</summary>
    /// <param name="User">The guest, ALREADY created in the directory: B2B creates the object when
    /// invited, not when the invitation is redeemed.</param>
    /// <param name="RedeemUrl">Link the person must follow to redeem.</param>
    /// <param name="EmailSent">Whether the directory e-mailed the invitation. When false, delivering the
    /// <paramref name="RedeemUrl"/> is the application's job.</param>
    public sealed record DirectoryInvitation(DirectoryUser User, string? RedeemUrl, bool EmailSent);

    /// <summary>The directory rejected the operation. Carries a message fit to show to an administrator.</summary>
    public sealed class DirectoryException : Exception
    {
        /// <summary>Creates the exception with the message to show and, optionally, the underlying error.</summary>
        public DirectoryException(string message, Exception? inner = null) : base(message, inner) { }
    }

    /// <summary>
    /// People in the identity provider's directory: finding somebody to give access to, and inviting an
    /// external person.
    /// </summary>
    /// <remarks>
    /// Being in the directory grants nothing. Access is membership of the access group
    /// (<see cref="IAccessDirectory"/>) plus the roles the application gives; this only answers "who is
    /// this person".
    /// </remarks>
    public interface IDirectoryService
    {
        /// <summary>People in the tenant whose name, e-mail or sign-in name matches.</summary>
        Task<IReadOnlyList<DirectoryUser>> SearchAsync(string search, CancellationToken cancellationToken = default);

        /// <summary>The person with this e-mail anywhere in the tenant, or null.</summary>
        Task<DirectoryUser?> FindByEmailAsync(string email, CancellationToken cancellationToken = default);

        /// <summary>Invites an external user as a guest. The object is created right away.</summary>
        Task<DirectoryInvitation> InviteAsync(string email, string? displayName, CancellationToken cancellationToken = default);
    }
}
