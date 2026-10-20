namespace kdyf.Authorization.Administration.Notifications
{
    /// <summary>
    /// SMTP server used to send the invitations (appsettings section <c>SmtpAuthClient</c> by convention).
    /// </summary>
    public sealed class SmtpInvitationOptions
    {
        /// <summary>The configuration section the options are bound from by convention.</summary>
        public const string SectionName = "SmtpAuthClient";

        /// <summary>SMTP server host name. Required.</summary>
        public string Host { get; set; } = string.Empty;
        /// <summary>SMTP server port. Defaults to 587.</summary>
        public int Port { get; set; } = 587;

        /// <summary>With port 587 this means STARTTLS, which is what Gmail and most servers expect.</summary>
        public bool EnableSsl { get; set; } = true;

        /// <summary>Account to authenticate with. Required; also the default sender address.</summary>
        public string Username { get; set; } = string.Empty;

        /// <summary>Comes from the deployment. With Gmail it is an App Password, not the account one.</summary>
        public string Password { get; set; } = string.Empty;

        /// <summary>Timeout of one send, in milliseconds. Defaults to 20000.</summary>
        public int Timeout { get; set; } = 20000;

        /// <summary>
        /// Sender address. Defaults to <see cref="Username"/>. Beware: some providers (Gmail among
        /// them) rewrite it to the authenticated account unless the alias is verified.
        /// </summary>
        public string? From { get; set; }

        /// <summary>
        /// The application's name as the invited person should read it, e.g. <c>Contoso Portal</c>.
        /// The default sender name and subject derive from it, and the default body shows it.
        /// </summary>
        /// <remarks>
        /// In kdyf.auth.Access.AspNetCore the name was written into the defaults (a client's name), so any
        /// other application that turned the notifier on sent its invitations under another
        /// client's brand. Set it per application.
        /// </remarks>
        public string ApplicationName { get; set; } = "the application";

        /// <summary>Sender display name. Defaults to <see cref="ApplicationName"/>.</summary>
        public string? FromName { get; set; }

        /// <summary>Defaults to "You have been invited to {ApplicationName}".</summary>
        public string? Subject { get; set; }

        /// <summary>
        /// HTML body. Supports the placeholders <c>{ApplicationName}</c>, <c>{Greeting}</c>,
        /// <c>{DisplayName}</c> and <c>{RedeemUrl}</c>, all HTML-encoded on the way in.
        /// Left empty, a plain default message is used.
        /// </summary>
        public string? BodyTemplate { get; set; }

        internal string EffectiveFromName => string.IsNullOrWhiteSpace(FromName) ? ApplicationName : FromName;

        internal string EffectiveSubject => string.IsNullOrWhiteSpace(Subject) ? $"You have been invited to {ApplicationName}" : Subject;

        /// <summary>Whether <see cref="Host"/>, <see cref="Username"/> and <see cref="Password"/> are all set: without them nothing can be sent.</summary>
        public bool IsConfigured =>
            !string.IsNullOrWhiteSpace(Host) &&
            !string.IsNullOrWhiteSpace(Username) &&
            !string.IsNullOrWhiteSpace(Password);
    }
}
