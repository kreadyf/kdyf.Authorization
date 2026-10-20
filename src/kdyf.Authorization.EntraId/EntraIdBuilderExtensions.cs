using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Identity.Web;
using kdyf.Authorization.Hosting;

namespace kdyf.Authorization.EntraId
{
    /// <summary>Registration of Microsoft Entra ID as the identity provider on the authorization builder.</summary>
    public static class EntraIdBuilderExtensions
    {
        /// <summary>
        /// Microsoft Entra ID as the identity provider: people sign in with an Entra token, and who may use the
        /// application at all is the access group, read through Microsoft Graph.
        /// </summary>
        /// <remarks>
        /// <para>Reads, from the library's section, <c>EntraId</c> (the keys Microsoft.Identity.Web reads) and
        /// <c>Directory</c> (the access group and the Graph credential). Both are validated when the host starts.</para>
        /// <para>The token's own <c>groups</c> and <c>roles</c> claims authorize nobody: membership is read on the
        /// server, so a removal takes the cache duration, not the token's lifetime.</para>
        /// </remarks>
        public static TBuilder UseEntraId<TBuilder>(this TBuilder builder)
            where TBuilder : IKdyfAuthorizationBuilder
        {
            ArgumentNullException.ThrowIfNull(builder);

            builder.AddProvider(nameof(UseEntraId), context =>
            {
                var services = context.Services;

                services.AddOptions<EntraIdAuthorizationOptions>()
                    .Bind(context.Section)
                    .ValidateOnStart();
                services.AddSingleton<IValidateOptions<EntraIdAuthorizationOptions>>(new EntraIdAuthorizationOptionsValidator(context.Section.Path));

                // People: the Entra ID JWT.
                context.Authentication.AddMicrosoftIdentityWebApi(context.Section.GetSection(nameof(EntraIdAuthorizationOptions.EntraId)));
                context.SetUserScheme(JwtBearerDefaults.AuthenticationScheme);

                // Who may use the application at all: the access group in Entra, through Graph.
                services.AddEntraGroupMembership();
                services.AddOptions<EntraGraphOptions>()
                    .Configure<IOptions<EntraIdAuthorizationOptions>>((graph, entra) => CopyGraph(entra.Value, graph));
            });

            return builder;
        }

        /// <summary>
        /// Fills the Graph options: the credential and the access group from <c>Directory</c>, inheriting the tenant
        /// and the client from <c>EntraId</c> unless set.
        /// </summary>
        internal static void CopyGraph(EntraIdAuthorizationOptions entra, EntraGraphOptions graph)
        {
            var directory = entra.Directory;
            graph.TenantId = FirstSet(directory.TenantId, entra.EntraId.TenantId);
            graph.ClientId = FirstSet(directory.ClientId, entra.EntraId.ClientId);
            graph.ClientSecret = directory.ClientSecret ?? string.Empty;
            graph.GroupId = directory.GroupId?.Trim() ?? string.Empty;
            graph.Gate = directory.Gate;
            graph.ServicePrincipalId = directory.ServicePrincipalId?.Trim() ?? string.Empty;
            graph.AccessAppRoleId = directory.AccessAppRoleId?.Trim() ?? string.Empty;
        }

        private static string FirstSet(string? preferred, string? fallback) =>
            !string.IsNullOrWhiteSpace(preferred) ? preferred : fallback ?? string.Empty;
    }
}
