using kdyf.Authorization.Administration.Abstractions;
using System.Net;
using System.Net.Mail;
using kdyf.Authorization.Abstractions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace kdyf.Authorization.Administration.Notifications
{
    /// <summary>
    /// Sends the invitation over SMTP.
    /// </summary>
    /// <remarks>
    /// Uses <see cref="SmtpClient"/> from the BCL on purpose: it keeps the package free of new
    /// dependencies, and one message with no attachments needs nothing that MailKit would add.
    /// </remarks>
    public sealed class SmtpInvitationNotifier : IInvitationNotifier
    {
        // Default template: email-compatible HTML (table + inline styles, no stylesheets or external
        // images, which clients block). Neutral colors: each application's branding goes in
        // SmtpAuthClient:BodyTemplate, not here.
        // Placeholders: {ApplicationName}, {Greeting} (" Name" or empty), {DisplayName}, {RedeemUrl}.
        private const string DefaultBody =
            """
            <div style="display:none;max-height:0;overflow:hidden;opacity:0;">You have been invited to {ApplicationName}. Accept to get access.</div>
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#f5f7f8;padding:24px 0;font-family:'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
              <tr>
                <td align="center">
                  <table role="presentation" width="600" cellpadding="0" cellspacing="0" style="width:600px;max-width:100%;background-color:#ffffff;border:1px solid #e0e5e7;border-radius:10px;overflow:hidden;">
                    <tr>
                      <td style="background-color:#334155;padding:20px 32px;">
                        <span style="color:#ffffff;font-size:20px;font-weight:700;">{ApplicationName}</span>
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:32px;color:#263238;font-size:15px;line-height:1.6;">
                        <p style="margin:0 0 16px;">Hello{Greeting},</p>
                        <p style="margin:0 0 24px;">You have been given access to <strong>{ApplicationName}</strong>. Click the button below to accept the invitation and sign in.</p>
                        <table role="presentation" cellpadding="0" cellspacing="0" style="margin:0 0 24px;">
                          <tr>
                            <td align="center" bgcolor="#2563eb" style="border-radius:6px;">
                              <a href="{RedeemUrl}" style="display:inline-block;padding:12px 28px;color:#ffffff;font-size:15px;font-weight:600;text-decoration:none;border-radius:6px;">Accept the invitation</a>
                            </td>
                          </tr>
                        </table>
                        <p style="margin:0 0 8px;color:#607d8b;font-size:13px;">If the button does not work, copy this link into your browser:</p>
                        <p style="margin:0;word-break:break-all;"><a href="{RedeemUrl}" style="color:#455a64;font-size:13px;">{RedeemUrl}</a></p>
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:20px 32px;border-top:1px solid #eceff1;color:#90a4ae;font-size:12px;">
                        You received this because an administrator granted you access to {ApplicationName}. If you were not expecting this, you can ignore this email.
                      </td>
                    </tr>
                  </table>
                </td>
              </tr>
            </table>
            """;

        private readonly SmtpInvitationOptions _options;
        private readonly ILogger<SmtpInvitationNotifier> _logger;

        /// <summary>Creates the notifier over the bound <see cref="SmtpInvitationOptions"/>.</summary>
        public SmtpInvitationNotifier(IOptions<SmtpInvitationOptions> options, ILogger<SmtpInvitationNotifier> logger)
        {
            _options = options.Value;
            _logger = logger;
        }

        /// <summary>
        /// Sends one HTML message to the invited address with the redeem link. Throws when SMTP is not
        /// configured (<see cref="SmtpInvitationOptions.IsConfigured"/>) or the server refuses; the redeem link is never logged.
        /// </summary>
        public async Task SendAsync(InvitationNotice notice, CancellationToken cancellationToken = default)
        {
            if (!_options.IsConfigured)
                throw new InvalidOperationException(
                    $"SMTP is not configured: the '{SmtpInvitationOptions.SectionName}' section needs Host, Username and Password.");

            using var client = new SmtpClient(_options.Host, _options.Port)
            {
                EnableSsl = _options.EnableSsl,
                DeliveryMethod = SmtpDeliveryMethod.Network,
                // Must be set BEFORE Credentials: setting it afterwards wipes them and the server
                // answers with an anonymous-relay rejection that says nothing about the cause.
                UseDefaultCredentials = false,
                Credentials = new NetworkCredential(_options.Username, _options.Password),
                Timeout = _options.Timeout
            };

            var from = string.IsNullOrWhiteSpace(_options.From) ? _options.Username : _options.From;

            using var message = new MailMessage
            {
                From = new MailAddress(from, _options.EffectiveFromName),
                Subject = _options.EffectiveSubject,
                Body = BuildBody(notice),
                IsBodyHtml = true
            };
            message.To.Add(new MailAddress(notice.Email, notice.DisplayName));

            await client.SendMailAsync(message, cancellationToken);

            // The redeem link is not logged: it is a credential — whoever follows it redeems the invitation.
            _logger.LogInformation("Invitation sent to {Email}", notice.Email);
        }

        /// <remarks>
        /// Every value is HTML-encoded before it goes in. The display name is typed by an
        /// administrator (or comes from the directory), and inserted raw it could put markup — a
        /// link to anywhere — into an email that arrives looking like the application's own.
        /// </remarks>
        internal string BuildBody(InvitationNotice notice)
        {
            var template = string.IsNullOrWhiteSpace(_options.BodyTemplate) ? DefaultBody : _options.BodyTemplate;
            var name = notice.DisplayName ?? string.Empty;

            return template
                .Replace("{ApplicationName}", WebUtility.HtmlEncode(_options.ApplicationName))
                .Replace("{Greeting}", string.IsNullOrWhiteSpace(name) ? string.Empty : " " + WebUtility.HtmlEncode(name))
                .Replace("{DisplayName}", WebUtility.HtmlEncode(name))
                .Replace("{RedeemUrl}", WebUtility.HtmlEncode(notice.RedeemUrl));
        }
    }
}
