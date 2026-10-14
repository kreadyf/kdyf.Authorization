namespace kdyf.Authorization.Administration.Models
{
    /// <summary>Somebody from the directory, as the administration screen sees them.</summary>
    public class DirectoryUserResponse
    {
        /// <summary>Immutable identifier in the directory (the 'oid'): what <c>PUT users/{objectId}/roles</c> takes.</summary>
        public string ObjectId { get; set; } = string.Empty;

        public string? DisplayName { get; set; }

        /// <summary>Real address. For a guest this is NOT their sign-in name.</summary>
        public string? Email { get; set; }

        public string? UserPrincipalName { get; set; }

        /// <summary>External user invited through B2B.</summary>
        public bool IsGuest { get; set; }

        /// <summary>In the access group already: they can sign in, with the base access at least.</summary>
        public bool IsMember { get; set; }

        /// <summary>The roles they hold on this application.</summary>
        public List<string> Roles { get; set; } = new();
    }

    /// <summary>Bring a person into the access group — inviting them first when they are not in the tenant.</summary>
    public class InviteRequest
    {
        public string Email { get; set; } = string.Empty;
        public string? DisplayName { get; set; }
    }

    public class InviteResponse
    {
        /// <summary>The person: the existing directory user, or the guest just created. Now in the access group.</summary>
        public DirectoryUserResponse User { get; set; } = new();

        /// <summary>False when somebody with that e-mail was already in the directory: nobody was invited.</summary>
        public bool WasInvited { get; set; }

        /// <summary>Whether the invitation e-mail went out (only meaningful when <see cref="WasInvited"/>).</summary>
        public bool InvitationEmailSent { get; set; }

        /// <summary>
        /// Link the invited person must follow to redeem. Present only when the e-mail could not be sent:
        /// then the administrator passes it on by hand.
        /// </summary>
        public string? RedeemUrl { get; set; }
    }
}
