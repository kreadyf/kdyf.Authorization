using Microsoft.Extensions.Options;

namespace kdyf.Authorization.EntraId
{
    /// <summary>
    /// What <c>UseEntraId</c> reads from the library's section: <c>EntraId</c> (the application that issues the tokens)
    /// and <c>Directory</c> (Microsoft Graph and the access group).
    /// </summary>
    public sealed class EntraIdAuthorizationOptions
    {
        /// <summary>The Entra ID application that issues the tokens this API validates.</summary>
        public EntraIdApplicationOptions EntraId { get; set; } = new();

        /// <summary>Microsoft Graph: the access group, searching and inviting people.</summary>
        public EntraDirectoryOptions Directory { get; set; } = new();
    }

    /// <summary><c>EntraId</c>. The keys are the ones Microsoft.Identity.Web reads.</summary>
    public sealed class EntraIdApplicationOptions
    {
        /// <summary>The Entra sign-in authority. Required; defaults to the public cloud.</summary>
        public string Instance { get; set; } = "https://login.microsoftonline.com/";

        /// <summary>Directory (tenant) ID.</summary>
        public string? TenantId { get; set; }

        /// <summary>Application (client) ID of the API's app registration.</summary>
        public string? ClientId { get; set; }

        /// <summary>Application ID URI of the API. Empty uses the default, <c>api://{ClientId}</c>.</summary>
        public string? Audience { get; set; }
    }

    /// <summary>Who may use the application at all: what <c>Directory:Gate</c> names.</summary>
    public enum AccessGate
    {
        /// <summary>The members of the access group (<c>GroupId</c>). The default.</summary>
        Group,

        /// <summary>
        /// The access group still decides; the assignments to the Enterprise application are kept equal to it and the
        /// two are compared on every resolution. Needs <c>GroupId</c>, <c>ServicePrincipalId</c> and <c>AccessAppRoleId</c>.
        /// </summary>
        Migrating,

        /// <summary>The users assigned the <c>Access</c> app role on the Enterprise application.</summary>
        AppAssignment,
    }

    /// <summary>
    /// <c>Directory</c>: the access gate (a group, or assignments to the Enterprise application), the Microsoft Graph
    /// credential, and how invitations behave.
    /// </summary>
    /// <remarks>
    /// Required: the access group decides who may use the application, so without Graph nobody can be
    /// authorized. The tenant and the client are inherited from <c>EntraId</c> unless set here.
    /// </remarks>
    public sealed class EntraDirectoryOptions
    {
        /// <summary>Who may use the application: the access group (default), assignments, or the migration between them.</summary>
        public AccessGate Gate { get; set; } = AccessGate.Group;

        /// <summary>
        /// Object id of the Entra security group whose members may use the application (directly or through a
        /// nested group). Not a secret. Required with <see cref="AccessGate.Group"/> and <see cref="AccessGate.Migrating"/>.
        /// </summary>
        public string? GroupId { get; set; }

        /// <summary>
        /// Object id of the Enterprise application (service principal) people are assigned to. Not a secret. Required with
        /// <see cref="AccessGate.Migrating"/> and <see cref="AccessGate.AppAssignment"/>. Always from configuration, never
        /// from a request: it is what every assignment is made on.
        /// </summary>
        public string? ServicePrincipalId { get; set; }

        /// <summary>
        /// Id of the app role <c>Access</c> on that application: only an assignment with this role gives access. Required
        /// with <see cref="AccessGate.Migrating"/> and <see cref="AccessGate.AppAssignment"/>.
        /// </summary>
        public string? AccessAppRoleId { get; set; }

        /// <summary>While migrating: how often the assignments are brought in line with the group. Default 10 minutes.</summary>
        public TimeSpan MigrationSyncInterval { get; set; } = TimeSpan.FromMinutes(10);

        /// <summary>Only when Graph uses another tenant than <c>EntraId</c>.</summary>
        public string? TenantId { get; set; }

        /// <summary>Only when Graph uses another app registration than <c>EntraId</c>.</summary>
        public string? ClientId { get; set; }

        /// <summary>Secret of that app registration. SECRET. Required.</summary>
        public string? ClientSecret { get; set; }

        /// <summary>Where an invited guest lands after accepting. Usually the application's URL. Needed only to invite.</summary>
        public string? InviteRedirectUrl { get; set; }

        /// <summary>Whether Entra sends the invitation e-mail itself.</summary>
        public bool SendInvitationMessage { get; set; } = true;
    }

    /// <summary>
    /// Validates <see cref="EntraIdAuthorizationOptions"/> when the host starts (<c>ValidateOnStart</c>): a host with a
    /// broken identity configuration refuses to start, and the message names the key and where to set it.
    /// </summary>
    /// <remarks>
    /// Without this, a missing <c>EntraId:ClientId</c> goes unnoticed until the first request that carries a token,
    /// and a missing Graph secret until the first request — which then denies everybody.
    /// </remarks>
    internal sealed class EntraIdAuthorizationOptionsValidator : IValidateOptions<EntraIdAuthorizationOptions>
    {
        private readonly string _section;

        public EntraIdAuthorizationOptionsValidator(string section) => _section = section;

        public ValidateOptionsResult Validate(string? name, EntraIdAuthorizationOptions options)
        {
            var errors = new List<string>();
            var entra = options.EntraId;
            var directory = options.Directory;

            if (string.IsNullOrWhiteSpace(entra.Instance))
                errors.Add($"{_section}:EntraId:Instance is empty. Leave it out to use https://login.microsoftonline.com/.");

            if (!Guid.TryParse(entra.TenantId, out _))
                errors.Add($"{_section}:EntraId:TenantId is missing or not a GUID: the Directory (tenant) ID of the Entra tenant.");

            if (!Guid.TryParse(entra.ClientId, out _))
                errors.Add($"{_section}:EntraId:ClientId is missing or not a GUID: the Application (client) ID of the API's app registration.");

            var gate = directory.Gate;
            if (gate is AccessGate.Group or AccessGate.Migrating && !Guid.TryParse(directory.GroupId, out _))
                errors.Add($"{_section}:Directory:GroupId is missing or not a GUID: the Object ID of the Entra security group whose members may use the application "
                           + $"(Directory:Gate is {gate}).");

            if (gate is AccessGate.Migrating or AccessGate.AppAssignment)
            {
                if (!Guid.TryParse(directory.ServicePrincipalId, out _))
                    errors.Add($"{_section}:Directory:ServicePrincipalId is missing or not a GUID: the Object ID of the Enterprise application people are assigned to "
                               + $"(Directory:Gate is {gate}).");
                if (!Guid.TryParse(directory.AccessAppRoleId, out _))
                    errors.Add($"{_section}:Directory:AccessAppRoleId is missing or not a GUID: the id of the app role Access on that application "
                               + $"(Directory:Gate is {gate}).");
            }

            if (gate == AccessGate.Migrating && (directory.MigrationSyncInterval < TimeSpan.FromMinutes(1) || directory.MigrationSyncInterval > TimeSpan.FromDays(1)))
                errors.Add($"{_section}:Directory:MigrationSyncInterval is {directory.MigrationSyncInterval}: it must be between 1 minute and 1 day.");

            if (string.IsNullOrWhiteSpace(directory.ClientSecret))
                errors.Add($"{_section}:Directory:ClientSecret is missing. Who has access is read through Graph: without a Graph credential nobody can be authorized. "
                           + $"Locally: dotnet user-secrets set \"{_section}:Directory:ClientSecret\" \"<secret>\" --project <host project>.");

            if (!string.IsNullOrWhiteSpace(directory.TenantId) && !Guid.TryParse(directory.TenantId, out _))
                errors.Add($"{_section}:Directory:TenantId is not a GUID. Leave it out to use EntraId:TenantId.");

            if (!string.IsNullOrWhiteSpace(directory.ClientId) && !Guid.TryParse(directory.ClientId, out _))
                errors.Add($"{_section}:Directory:ClientId is not a GUID. Leave it out to use EntraId:ClientId.");

            return errors.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(errors);
        }
    }
}
