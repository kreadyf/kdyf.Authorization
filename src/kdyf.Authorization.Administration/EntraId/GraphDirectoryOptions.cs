namespace kdyf.Authorization.Administration.EntraId
{
    /// <summary>
    /// How the directory search and the B2B invitations behave. The Graph credential itself is
    /// <c>EntraGraphOptions</c>, shared with authorization.
    /// </summary>
    public sealed class GraphDirectoryOptions
    {
        /// <summary>Where the invited person lands after redeeming. Usually the application's home.</summary>
        public string InviteRedirectUrl { get; set; } = string.Empty;

        /// <summary>
        /// Whether the directory sends the invitation e-mail itself. False leaves the sending to the
        /// application, which then has to deliver the <c>RedeemUrl</c> the invitation returns.
        /// </summary>
        public bool SendInvitationMessage { get; set; } = true;

        /// <summary>How many people a search returns at most.</summary>
        public int MaxSearchResults { get; set; } = 25;
    }
}
