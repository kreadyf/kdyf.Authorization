using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using kdyf.Authorization.AspNetCore;
using kdyf.Authorization;
using kdyf.Authorization.Abstractions;
using kdyf.Authorization.Authentication;
using kdyf.Authorization.Authorization;
using kdyf.Authorization.Hosting;
using kdyf.Authorization.Roles;
using kdyf.Authorization.Simulation;

// Top-level namespace on purpose: the host finds it with the usings it already has.
namespace Microsoft.Extensions.DependencyInjection
{
    public static class KdyfAuthorizationServiceCollectionExtensions
    {
        /// <summary>The default scheme: forwards each request to the identity provider's or the PAT scheme, by its Authorization header.</summary>
        public const string DefaultScheme = "KdyfAuthorization";

        /// <summary>
        /// The security of the host — authentication and authorization — from the <c>KdyfAuthorization</c> configuration
        /// section.
        /// </summary>
        /// <inheritdoc cref="AddKdyfAuthorization(IServiceCollection, IConfiguration, string, Action{KdyfAuthorizationBuilder})"/>
        public static IServiceCollection AddKdyfAuthorization(
            this IServiceCollection services,
            IConfiguration configuration,
            Action<KdyfAuthorizationBuilder> configure) =>
            services.AddKdyfAuthorization(configuration, KdyfAuthorizationOptions.DefaultSectionName, configure);

        /// <summary>
        /// The security of the host — authentication and authorization — from the configuration section
        /// <paramref name="sectionName"/>.
        /// </summary>
        /// <remarks>
        /// <para>Registers, in this order of dependence:</para>
        /// <list type="bullet">
        /// <item>The providers the host chose in <paramref name="configure"/>: where roles, grants and tokens are stored
        /// (<c>UseEntityFrameworkStore</c>), and the identity provider — how people sign in and who may use the
        /// application at all (<c>UseEntraId</c>). Both are required.</item>
        /// <item>Authentication: the identity provider's scheme and personal access tokens, picked per request by the
        /// Authorization header.</item>
        /// <item>The fallback and default policies: a session from either scheme. An endpoint is anonymous
        /// only with an explicit <c>AllowAnonymous()</c>.</item>
        /// <item>Permission-based authorization: nothing for somebody the identity provider does not let in; for
        /// everybody else, what every member holds plus what their roles grant, cached for
        /// <c>Authorization:CacheDuration</c>.</item>
        /// <item>The "whose data is this?" user context. User simulation is turned on apart, by
        /// <see cref="AddKdyfAuthorizationSimulation"/>.</item>
        /// </list>
        /// <para>
        /// No administration and no endpoints. A host that administers access adds
        /// <c>AddKdyfAuthorizationAdministration</c> (kdyf.Authorization.Administration.AspNetCore) on top of this.
        /// </para>
        /// <para>
        /// Every part of the section is validated when the host starts: with a missing or inconsistent value the host
        /// does not start, and the message names the key.
        /// </para>
        /// </remarks>
        /// <param name="services">The host's services.</param>
        /// <param name="configuration">
        /// The host's whole configuration (<c>builder.Configuration</c>), not the section: the database is one of the
        /// application's connection strings, at the root.
        /// </param>
        /// <param name="sectionName">The section the library reads, for instance <c>"Security"</c>.</param>
        /// <param name="configure">The decisions that belong to code: see <see cref="KdyfAuthorizationBuilder"/>.</param>
        public static IServiceCollection AddKdyfAuthorization(
            this IServiceCollection services,
            IConfiguration configuration,
            string sectionName,
            Action<KdyfAuthorizationBuilder> configure)
        {
            ArgumentNullException.ThrowIfNull(configuration);
            ArgumentException.ThrowIfNullOrWhiteSpace(sectionName);
            ArgumentNullException.ThrowIfNull(configure);

            // Handed a section by habit, every key would be looked for one level too deep, and the connection strings
            // would be out of reach: the host would refuse to start with every value "missing". Named here instead.
            if (configuration is IConfigurationSection given)
                throw new ArgumentException(
                    $"AddKdyfAuthorization takes the host's whole configuration (builder.Configuration), not a section ('{given.Path}'): "
                    + "it also reads the connection strings. Name the section with the sectionName parameter.", nameof(configuration));

            var section = configuration.GetSection(sectionName);

            // Where the library's section is, for what is switched on later from it (AddKdyfAuthorizationSimulation).
            services.AddSingleton(new KdyfAuthorizationSection(section));

            var builder = new KdyfAuthorizationBuilder();
            configure(builder);
            builder.EnsureComplete();

            // ── Options ──────────────────────────────────────────────────────────
            //
            // Bound lazily and validated at startup. The cache durations are also read NOW, because they
            // feed options built here.
            services.AddOptions<KdyfAuthorizationOptions>()
                .Bind(section)
                .ValidateOnStart();
            services.AddSingleton<IValidateOptions<KdyfAuthorizationOptions>>(new KdyfAuthorizationOptionsValidator(section.Path));
            var now = section.Get<KdyfAuthorizationOptions>() ?? new KdyfAuthorizationOptions();

            // ── Providers ────────────────────────────────────────────────────────
            //
            // The database and the identity provider, from the packages the host chose. They run first: the identity
            // provider names the scheme people sign in with, and everything below demands it.
            var authentication = services.AddAuthentication(DefaultScheme);
            var context = new KdyfAuthorizationProviderContext(services, configuration, section, authentication, builder.DeclarationAssemblies);
            foreach (var (_, register) in builder.Providers)
                register(context);
            EnsureProviders(services, context);

            string[] schemes = [context.UserScheme!, PatAuthenticationHandler.SchemeName];

            // ── Authentication ───────────────────────────────────────────────────
            //
            // The DEFAULT scheme picks the handler by the Authorization header: "PAT <token>" goes to the personal
            // access token scheme, anything else to the identity provider's. So UseAuthentication authenticates BOTH
            // kinds of caller up front. With the JWT as the only default, a PAT was authenticated only when a policy
            // asked for it — after the simulation middleware, which then never saw it: a simulation header sent with a
            // token was silently ignored instead of refused.
            authentication.AddPolicyScheme(DefaultScheme, "Identity provider token or personal access token", options =>
                options.ForwardDefaultSelector = http =>
                    PatAuthenticationHandler.IsPatHeader(http.Request.Headers.Authorization)
                        ? PatAuthenticationHandler.SchemeName
                        : schemes[0]);
            authentication.AddPat();

            // ── Authorization ────────────────────────────────────────────────────
            //
            // The FALLBACK covers every endpoint with no authorization metadata; the DEFAULT is what a bare
            // RequireAuthorization() uses. Both name BOTH schemes: without PAT here a token arrives anonymous
            // and is rejected as if it did not exist.
            services.AddAuthorizationBuilder()
                .SetFallbackPolicy(new AuthorizationPolicyBuilder(schemes).RequireAuthenticatedUser().Build())
                .SetDefaultPolicy(new AuthorizationPolicyBuilder(schemes).RequireAuthenticatedUser().Build());

            services
                .AddPermissionAuthorization(options =>
                {
                    options.AuthenticationSchemes = schemes;
                    options.MemberPermissionCodes = new HashSet<string>(builder.MemberPermissionCodes, StringComparer.Ordinal);
                    options.CacheDuration = now.Authorization.CacheDuration;
                    options.EmptyResultCacheDuration = now.Authorization.EmptyResultCacheDuration;

                    // The token's own 'roles' and 'groups' claims are NOT what authorizes a person: they are as
                    // old as the token. Membership and roles are read on the server, so a revocation takes
                    // CacheDuration, not the token's lifetime.
                    options.AcceptRoleClaimsForUserPrincipals = false;

                    // Off, and not by neglect: it walks EndpointDataSource, which in a minimal API does not
                    // show it the permissions in use, and policy names are not codes. AddAssignedRoles and
                    // AddPolicies check the declarations at registration instead.
                    options.ValidatePoliciesOnStartup = false;
                })
                .AddAssignedRoles(builder.DeclarationAssemblies)
                .AddPolicies(builder.DeclarationAssemblies, builder.ShortcutTypes);

            // "Whose data is this?" answered from the same principal as "may they?". See IUserContext.
            services.AddHttpContextAccessor();
            services.TryAddScoped<IUserContext, ClaimsUserContext>();

            return services;
        }

        /// <summary>
        /// Turns on user simulation (the <c>X-Simulate-User</c> header), on top of <c>AddKdyfAuthorization</c>: whoever holds
        /// this policy's permission may read the application AS another user — read-only, and only a user who holds
        /// nothing beyond them.
        /// </summary>
        /// <remarks>
        /// <para>
        /// A call of its own, so the feature is switched on by whoever owns it (a simulation module, or the host)
        /// rather than by whoever composes authorization. <c>UseKdyfAuthorization</c> then puts the refusal answer in the
        /// pipeline.
        /// </para>
        /// <para>
        /// The policy must demand exactly one permission: it is the one the simulation checks on the REAL caller.
        /// Declared among the policies (<c>Declarations</c>), it also appears in the policy report, so the frontend
        /// knows whether to offer the feature. It is also the door of the simulation endpoints
        /// (<c>MapKdyfAuthorizationSimulation</c>).
        /// </para>
        /// <para>
        /// Reads, all optional, from the <c>Simulation</c> part of the library's section: <c>HeaderName</c>
        /// (default <c>X-Simulate-User</c>), <c>SimulatedByClaimType</c>, <c>SimulatedByObjectIdClaimType</c>,
        /// <c>SessionIdleTimeout</c> (default 30 minutes) and <c>CandidatesMaxConcurrency</c> (default 8). Read-only and
        /// the permission are not read from configuration: relaxing either opens a hole.
        /// </para>
        /// </remarks>
        public static IServiceCollection AddKdyfAuthorizationSimulation(this IServiceCollection services, Policy policy)
        {
            var permission = KdyfAuthorizationBuilder.SinglePermission(policy, "simulation");

            if (!services.Any(d => d.ServiceType == typeof(PermissionAuthorizationOptions)))
                throw new InvalidOperationException("AddKdyfAuthorizationSimulation turns simulation on in authorization: call AddKdyfAuthorization(...) first.");
            if (services.Any(d => d.ServiceType == typeof(UserSimulationOptions)))
                throw new InvalidOperationException("User simulation is already on: AddKdyfAuthorizationSimulation may be called once.");

            var configured = services.Select(d => d.ImplementationInstance).OfType<KdyfAuthorizationSection>().LastOrDefault()
                ?.Section.GetSection("Simulation");

            services.AddUserSimulation<MembershipSimulationTargetResolver>(options =>
            {
                if (configured is not null)
                {
                    // Only these: ReadOnly and RequiredPermission are never taken from a file.
                    options.HeaderName = configured[nameof(options.HeaderName)] ?? options.HeaderName;
                    options.SimulatedByClaimType = configured[nameof(options.SimulatedByClaimType)] ?? options.SimulatedByClaimType;
                    options.SimulatedByObjectIdClaimType = configured[nameof(options.SimulatedByObjectIdClaimType)] ?? options.SimulatedByObjectIdClaimType;
                    options.SessionIdleTimeout = configured.GetValue(nameof(options.SessionIdleTimeout), options.SessionIdleTimeout);
                    options.CandidatesMaxConcurrency = configured.GetValue(nameof(options.CandidatesMaxConcurrency), options.CandidatesMaxConcurrency);
                }

                options.RequiredPermission = permission;
                options.PolicyName = policy.Name;
                // Not configurable here. Writing as somebody else would land changes in their name and
                // compare every "not on yourself" rule against the wrong person.
                options.ReadOnly = true;
            });

            return services;
        }

        /// <summary>
        /// Refuses a composition without a store or an identity provider at registration, naming the call: without
        /// them nothing could be authorized, and the first request would fail instead of the startup.
        /// </summary>
        private static void EnsureProviders(IServiceCollection services, KdyfAuthorizationProviderContext context)
        {
            bool Has<T>() => services.Any(d => d.ServiceType == typeof(T));

            if (!Has<IUserRoleSource>() || !Has<IRolePermissionSource>() || !Has<IPatStore>())
                throw new InvalidOperationException(
                    "AddKdyfAuthorization: call .UseEntityFrameworkStore((db, connectionString) => db.UseSqlServer(connectionString)) "
                    + "(kdyf.Authorization.EntityFrameworkCore), or register a store yourself: IUserRoleSource, IRolePermissionSource and IPatStore.");

            if (context.UserScheme is null || !Has<IMembershipSource>())
                throw new InvalidOperationException(
                    "AddKdyfAuthorization: call .UseEntraId() (kdyf.Authorization.EntraId) or another identity provider: "
                    + "it says how people sign in and who may use the application at all.");
        }
    }
}

namespace kdyf.Authorization.AspNetCore
{
    /// <summary>The library's section, as <c>AddKdyfAuthorization</c> was given it.</summary>
    internal sealed record KdyfAuthorizationSection(Microsoft.Extensions.Configuration.IConfigurationSection Section);
}
