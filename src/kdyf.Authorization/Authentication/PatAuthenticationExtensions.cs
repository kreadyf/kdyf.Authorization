using Microsoft.AspNetCore.Authentication;

namespace kdyf.Authorization.Authentication
{
    /// <summary>Registration of the personal access token (PAT) authentication scheme.</summary>
    public static class PatAuthenticationExtensions
    {
        /// <summary>
        /// Registers the PAT authentication scheme (<c>Authorization: PAT &lt;token&gt;</c>).
        /// The consumer must also register an <c>IPatStore</c> implementation.
        /// </summary>
        public static AuthenticationBuilder AddPat(
            this AuthenticationBuilder builder,
            string scheme = PatAuthenticationHandler.SchemeName)
            => builder.AddScheme<PatAuthenticationOptions, PatAuthenticationHandler>(scheme, _ => { });
    }
}
