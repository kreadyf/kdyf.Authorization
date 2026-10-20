namespace kdyf.Authorization.AspNetCore
{
    /// <summary>The names of the policies <c>AddKdyfAuthorization</c> registers besides the fallback and default ones.</summary>
    public static class KdyfAuthorizationPolicies
    {
        /// <summary>
        /// A session (an Entra token or a personal access token), without the access gate. For endpoints that must answer
        /// somebody who is not let in — who am I, what may I do — never for anything that reads or changes data.
        /// </summary>
        public const string SignedIn = "kdyf.signed-in";
    }
}
