using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using kdyf.Authorization.Administration.Abstractions;
using kdyf.Authorization.Administration.Notifications;

namespace kdyf.Authorization.Administration.Test;

/// <summary>
/// The invitation email: whose name it carries, and what can get into its HTML.
/// </summary>
/// <remarks>
/// The body is built without sending anything; the SMTP part is the BCL's and needs a server.
/// </remarks>
[TestClass]
public sealed class SmtpInvitationNotifierTests
{
    /// <summary>
    /// In kdyf.auth the default named one client, so any other application sent its invitations under
    /// that client's brand. The name is now the application's, and nothing else is hard-coded.
    /// </summary>
    [TestMethod]
    public void The_email_carries_the_configured_application_name_and_no_other()
    {
        var options = new SmtpInvitationOptions { ApplicationName = "Contoso Portal" };

        var body = Notifier(options).BuildBody(new InvitationNotice("ana@contoso.com", "Ana", "https://redeem.example/x"));

        StringAssert.Contains(body, "Contoso Portal");
        Assert.IsFalse(body.Contains("Acme", StringComparison.OrdinalIgnoreCase), "Another client's brand leaked into the email.");
        Assert.AreEqual("Contoso Portal", options.EffectiveFromName);
        Assert.AreEqual("You have been invited to Contoso Portal", options.EffectiveSubject);
    }

    [TestMethod]
    public void Explicit_sender_and_subject_win_over_the_derived_ones()
    {
        var options = new SmtpInvitationOptions { ApplicationName = "Contoso Portal", FromName = "Contoso", Subject = "Access" };

        Assert.AreEqual("Contoso", options.EffectiveFromName);
        Assert.AreEqual("Access", options.EffectiveSubject);
    }

    /// <summary>
    /// The display name is typed by an administrator. Inserted raw, it could put a link to
    /// anywhere into an email that arrives looking like the application's own.
    /// </summary>
    [TestMethod]
    public void A_display_name_with_markup_arrives_as_text()
    {
        var body = Notifier(new SmtpInvitationOptions()).BuildBody(
            new InvitationNotice("x@contoso.com", "<a href=\"https://evil.example\">click</a>", "https://redeem.example/x"));

        Assert.IsFalse(body.Contains("<a href=\"https://evil.example\">", StringComparison.Ordinal));
        StringAssert.Contains(body, "&lt;a href=&quot;https://evil.example&quot;&gt;");
    }

    [TestMethod]
    public void The_redeem_link_is_in_the_body()
    {
        var body = Notifier(new SmtpInvitationOptions()).BuildBody(
            new InvitationNotice("x@contoso.com", null, "https://redeem.example/x?a=1&b=2"));

        // Encoded for the attribute: &amp; is how an '&' is written inside href="…".
        StringAssert.Contains(body, "https://redeem.example/x?a=1&amp;b=2");
    }

    private static SmtpInvitationNotifier Notifier(SmtpInvitationOptions options) =>
        new(Options.Create(options), NullLogger<SmtpInvitationNotifier>.Instance);
}
