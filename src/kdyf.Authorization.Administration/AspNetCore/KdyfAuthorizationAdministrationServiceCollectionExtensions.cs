using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using kdyf.Authorization.Administration;
using kdyf.Authorization.Administration.AspNetCore;
using kdyf.Authorization.Administration.EntraId;
using kdyf.Authorization.AspNetCore;
using kdyf.Authorization;
using kdyf.Authorization.EntityFrameworkCore;
using kdyf.Authorization.EntraId;

// Top-level namespace on purpose: the host finds it with the usings it already has.
namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>Registers the administration of access in the host's services.</summary>
    public static class KdyfAuthorizationAdministrationServiceCollectionExtensions
    {
        /// <summary>
        /// The administration of access, on top of <c>AddKdyfAuthorization</c> and from the same section.
        /// </summary>
        /// <remarks>
        /// <para>Registers:</para>
        /// <list type="bullet">
        /// <item><see cref="AdministrationDbContext"/>: the authorization tables and the audit log on one
        /// context, so a change and its audit entry share a transaction. Same database and provider as
        /// <c>UseEntityFrameworkStore</c>.</item>
        /// <item>The administration services (access, tokens, directory, audit), the access group and the directory
        /// through Microsoft Graph (<c>Directory</c>), and the audit log as the place simulations are recorded.</item>
        /// <item>The policies of the administration and the tokens under their fixed names
        /// (<see cref="AccessPolicyNames"/>), with the requirements of the policies the host chose.</item>
        /// </list>
        /// <para>No endpoints: the host exposes them, guarded by <see cref="AccessPolicyNames"/>.</para>
        /// </remarks>
        /// <param name="services">The host's services, where <c>AddKdyfAuthorization</c> is already registered.</param>
        /// <param name="configure">The decisions that belong to code: see <see cref="KdyfAuthorizationAdministrationBuilder"/>.</param>
        public static IServiceCollection AddKdyfAuthorizationAdministration(
            this IServiceCollection services,
            Action<KdyfAuthorizationAdministrationBuilder> configure)
        {
            ArgumentNullException.ThrowIfNull(configure);

            var builder = new KdyfAuthorizationAdministrationBuilder();
            configure(builder);
            builder.EnsureComplete();

            // The authorization this composes on. Its options are one instance, built at registration: the
            // administration code goes on it, because the administration services read it from there.
            var authorization = services.LastOrDefault(d => d.ServiceType == typeof(PermissionAuthorizationOptions))
                                    ?.ImplementationInstance as PermissionAuthorizationOptions
                                ?? throw new InvalidOperationException(
                                    "AddKdyfAuthorizationAdministration composes administration on top of authorization: call AddKdyfAuthorization(...) first.");
            authorization.AdministrationPermissionCode = builder.AdministrationPermissionCode!;

            // The administration writes the tables authorization reads, and invites through Entra: it needs both.
            if (!services.Any(d => d.ServiceType == typeof(EntityFrameworkStore)))
                throw new InvalidOperationException(
                    "AddKdyfAuthorizationAdministration writes the auth.* tables through EF Core: compose authorization with .UseEntityFrameworkStore(...).");
            if (!services.Any(d => d.ServiceType == typeof(IConfigureOptions<EntraIdAuthorizationOptions>)))
                throw new InvalidOperationException(
                    "AddKdyfAuthorizationAdministration administers the access group in Entra: compose authorization with .UseEntraId().");

            // ── Persistence ──────────────────────────────────────────────────────
            services.AddDbContext<AdministrationDbContext>((provider, options) =>
                provider.GetRequiredService<EntityFrameworkStore>().Configure(options, provider));

            // ── Doors ────────────────────────────────────────────────────────────
            //
            // Under fixed names, for the endpoints that expose the administration, with the requirements of the
            // policies the host chose and the schemes of AddKdyfAuthorization.
            var schemes = authorization.AuthenticationSchemes;
            services.Configure<AuthorizationOptions>(options =>
            {
                options.AddPolicy(AccessPolicyNames.Administration, builder.AdministrationPolicy!.Build(schemes));
                options.AddPolicy(AccessPolicyNames.PersonalAccessTokens, builder.TokensPolicy!.Build(schemes));
            });

            // ── Services ─────────────────────────────────────────────────────────
            services.AddAuthAdministration<AdministrationDbContext>();
            services.AddAzureAdAccessAdministration();
            services.AddOptions<GraphDirectoryOptions>()
                .Configure<IOptions<EntraIdAuthorizationOptions>>((directory, entra) =>
                {
                    directory.InviteRedirectUrl = entra.Value.Directory.InviteRedirectUrl ?? string.Empty;
                    directory.SendInvitationMessage = entra.Value.Directory.SendInvitationMessage;
                });

            return services;
        }
    }
}
