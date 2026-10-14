namespace kdyf.Authorization.EntraId
{
    /// <summary>
    /// How to reach Microsoft Graph, and what decides who may use the application: a group, or assignments to the
    /// Enterprise application.
    /// </summary>
    /// <remarks>
    /// The credential is the application's own (client credentials): what it may read and change is
    /// decided by the application permissions granted to <see cref="ClientId"/> with admin consent,
    /// not by whoever is using the screen. See the README for the list.
    /// </remarks>
    public sealed class EntraGraphOptions
    {
        /// <summary>Tenant the credential authenticates against.</summary>
        public string TenantId { get; set; } = string.Empty;

        /// <summary>App registration whose credential calls Graph.</summary>
        public string ClientId { get; set; } = string.Empty;

        /// <summary>Secret of that app registration. SECRET: from user secrets, environment or Key Vault.</summary>
        public string ClientSecret { get; set; } = string.Empty;

        /// <summary>
        /// Object id of the Entra security group whose members may use the application — directly or through a
        /// nested group.
        /// </summary>
        public string GroupId { get; set; } = string.Empty;

        /// <summary>Who may use the application. See <see cref="AccessGate"/>.</summary>
        public AccessGate Gate { get; set; } = AccessGate.Group;

        /// <summary>Object id of the Enterprise application (service principal) people are assigned to.</summary>
        public string ServicePrincipalId { get; set; } = string.Empty;

        /// <summary>Id of the app role whose assignment gives access.</summary>
        public string AccessAppRoleId { get; set; } = string.Empty;

        /// <summary>The gate reads the access group.</summary>
        public bool UsesGroup => Gate is AccessGate.Group or AccessGate.Migrating;

        /// <summary>The gate reads the assignments to the Enterprise application.</summary>
        public bool UsesAssignments => Gate is AccessGate.Migrating or AccessGate.AppAssignment;

        /// <summary>Base address of Graph. Only changes for sovereign clouds.</summary>
        public string GraphBaseUrl { get; set; } = "https://graph.microsoft.com/v1.0/";

        /// <summary>Everything needed to talk to Graph is set.</summary>
        public bool IsConfigured =>
            !string.IsNullOrWhiteSpace(TenantId) &&
            !string.IsNullOrWhiteSpace(ClientId) &&
            !string.IsNullOrWhiteSpace(ClientSecret) &&
            (!UsesGroup || GraphClient.IsObjectId(GroupId)) &&
            (!UsesAssignments || (GraphClient.IsObjectId(ServicePrincipalId) && GraphClient.IsObjectId(AccessAppRoleId)));
    }
}
