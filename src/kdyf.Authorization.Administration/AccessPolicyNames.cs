namespace kdyf.Authorization.Administration
{
    /// <summary>
    /// The names of the policies that guard the administration, fixed so a controller can name them in an
    /// attribute (<c>[Authorize(Policy = AccessPolicyNames.Administration)]</c>).
    /// </summary>
    /// <remarks>
    /// Which permission each one demands is still the host's decision: <c>AddKdyfAuthorization</c> registers these
    /// names with the requirements of the policies given to <c>AdministeredBy</c> and <c>TokensManagedBy</c>.
    /// So the attribute is a constant, and the door it names is the host's.
    /// </remarks>
    public static class AccessPolicyNames
    {
        /// <summary>Administering access: people, roles, the permission catalog, the directory, the audit log.</summary>
        public const string Administration = "kdyf.Authorization.Administration";

        /// <summary>Managing one's own personal access tokens (an administrator sees everyone's).</summary>
        public const string PersonalAccessTokens = "kdyf.Authorization.PersonalAccessTokens";
    }
}
