namespace kdyf.Authorization.Administration.Abstractions
{
    /// <summary>What the invited person has to be told.</summary>
    /// <param name="Email">Address the invitation was issued for.</param>
    /// <param name="DisplayName">Name to greet them by, when it is known.</param>
    /// <param name="RedeemUrl">Link that redeems the invitation. Without it there is nothing to send.</param>
    public sealed record InvitationNotice(string Email, string? DisplayName, string RedeemUrl);

    /// <summary>
    /// Delivers the invitation to the invited person.
    /// </summary>
    /// <remarks>
    /// It exists so the application can send the email itself instead of leaving it to the
    /// directory: that way the message carries its own wording and branding, and the person gets
    /// ONE invitation rather than two. Optional — with no notifier registered the invitation still
    /// works and the redeem link comes back in the response for the administrator to pass along.
    /// </remarks>
    public interface IInvitationNotifier
    {
        Task SendAsync(InvitationNotice notice, CancellationToken cancellationToken = default);
    }
}
