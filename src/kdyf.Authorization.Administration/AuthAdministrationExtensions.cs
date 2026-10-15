using kdyf.Authorization.Administration;
using kdyf.Authorization.Administration.Abstractions;
using kdyf.Authorization.Administration.Notifications;
using kdyf.Authorization.Administration.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;

// Top-level namespace on purpose: so the consumer only needs
// 'using Microsoft.Extensions.DependencyInjection;' to find this.
namespace Microsoft.Extensions.DependencyInjection
{
    public static class AuthAdministrationExtensions
    {
        /// <summary>
        /// Registers the administration services (access, personal tokens, directory and audit) against
        /// the consumer's <typeparamref name="TContext"/>, plus the EF audit log they write to.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Only services: no endpoints. The host exposes them with its own API;
        /// <c>AddKdyfAuthorizationAdministration</c> (kdyf.Authorization.Administration) calls this for a host.
        /// </para>
        /// <para>
        /// Requires, already registered: <c>AddPermissionAuthorization().AddAssignedRoles(...)</c> (the role
        /// catalog, the permission store and cache, the administration code); an
        /// <see cref="IAccessDirectory"/> and an <see cref="IDirectoryService"/> (see
        /// <c>AddAzureAdAccessAdministration</c>); and a <typeparamref name="TContext"/> that applies BOTH
        /// <c>ApplyAuthorizationModel()</c> and <c>ApplyAdministrationModel()</c>.
        /// </para>
        /// <para>
        /// <see cref="IAccessChangeNotifier"/> defaults to a log line; register another one to push the
        /// change to open sessions.
        /// </para>
        /// </remarks>
        public static IServiceCollection AddAuthAdministration<TContext>(this IServiceCollection services)
            where TContext : DbContext
        {
            services.AddEfAuditLog<TContext>();
            services.TryAddScoped<IAccessChangeNotifier, LoggingAccessChangeNotifier>();

            // Simulations are recorded in the audit log, replacing the log-only default of the simulation
            // package — whichever of the two was registered first.
            services.RemoveAll<kdyf.Authorization.Abstractions.ISimulationRecorder>();
            services.AddScoped<kdyf.Authorization.Abstractions.ISimulationRecorder, AuditSimulationRecorder<TContext>>();

            // Who is administering: the one place the actor is built, for the library's endpoints and a host's own.
            services.AddHttpContextAccessor();
            services.TryAddScoped<IAdminActorAccessor, HttpContextAdminActorAccessor>();

            services.AddScoped<IAccessAdminService, AccessAdminService<TContext>>();
            services.AddScoped<IPatAdminService, PatAdminService<TContext>>();
            services.AddScoped<IDirectoryAdminService, DirectoryAdminService<TContext>>();
            services.AddScoped<IAuditAdminService, AuditAdminService<TContext>>();

            // Starting, ending and offering a simulation. Answers "not enabled" until simulation is switched on.
            services.AddScoped<ISimulationAdminService, SimulationAdminService>();

            return services;
        }

        /// <summary>
        /// Makes the application send the invitation e-mails itself, over SMTP, instead of leaving them to
        /// the directory.
        /// </summary>
        /// <remarks>
        /// With this registered, the directory must be told NOT to send its own message
        /// (<c>SendInvitationMessage = false</c>), or the invited person gets two e-mails.
        /// The configuration section defaults to <c>SmtpAuthClient</c>.
        /// </remarks>
        public static IServiceCollection AddSmtpInvitationNotifier(
            this IServiceCollection services,
            IConfiguration configuration,
            string sectionName = SmtpInvitationOptions.SectionName)
        {
            services.Configure<SmtpInvitationOptions>(configuration.GetSection(sectionName));
            services.AddScoped<IInvitationNotifier, SmtpInvitationNotifier>();
            return services;
        }
    }
}
