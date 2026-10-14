namespace kdyf.Authorization.Administration
{
    /// <summary>
    /// Default permission codes the administration services fall back to when the host does not
    /// configure them.
    /// </summary>
    /// <remarks>
    /// In kdyf.auth.Access.AspNetCore these were the policy names of the MVC controllers. The policy names
    /// are now <see cref="AccessPolicyNames"/>, with their requirements chosen by the host. What
    /// remains here is <see cref="Admin"/> as the fallback for
    /// <c>PermissionAuthorizationOptions.AdministrationPermissionCode</c> when no options are
    /// registered — which a real host always does.
    /// </remarks>
    public static class AuthPolicies
    {
        /// <summary>Base access: being registered. Enables self-service (managing one's own resources).</summary>
        public const string Base = "Default";

        /// <summary>Administration: manage users/roles and the resources of all users.</summary>
        public const string Admin = "DataAdministration";
    }
}
