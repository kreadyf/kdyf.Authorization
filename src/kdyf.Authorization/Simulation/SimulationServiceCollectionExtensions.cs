using kdyf.Authorization.Abstractions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;

namespace kdyf.Authorization.Simulation
{
    /// <summary>
    /// Registration of "simulate user".
    /// </summary>
    public static class SimulationServiceCollectionExtensions
    {
        /// <summary>
        /// Registers the middleware's dependencies, the target resolver and the claims transformation
        /// that makes the swap stick. Chain <c>UseUserSimulation()</c> in the pipeline, between
        /// <c>UseAuthentication()</c> and <c>UseAuthorization()</c>.
        /// </summary>
        /// <remarks>
        /// The transformation is registered HERE rather than left to the consumer on purpose:
        /// forgetting it produces a feature that looks wired up, logs that it is simulating, and
        /// quietly serves the administrator's own data — the failure mode is silent, so the wiring
        /// must not be optional. A consumer that already has a transformation of its own passes it to
        /// <see cref="UserSimulationBuilder.ChainAfter{TInner}"/> instead of registering it directly.
        /// </remarks>
        public static UserSimulationBuilder AddUserSimulation<TResolver>(
            this IServiceCollection services,
            Action<UserSimulationOptions> configure)
            where TResolver : class, ISimulationTargetResolver
        {
            var options = new UserSimulationOptions();
            configure(options);
            options.Validate();

            services.AddSingleton(options);
            services.AddHttpContextAccessor();
            services.AddScoped<ISimulationTargetResolver, TResolver>();

            // Which simulations are running, so each start is recorded once; and where it is recorded. The
            // default recorder only logs — the administration package replaces it with its audit log.
            services.AddMemoryCache();
            services.AddSingleton<SimulationSessions>();
            services.TryAddScoped<ISimulationRecorder, LoggingSimulationRecorder>();

            // The one place "who is this request for" is answered, for authorization and for data
            // scoping alike. TryAdd so a consumer may substitute its own.
            services.TryAddScoped<IUserContext, Authorization.ClaimsUserContext>();

            services.AddTransient<IClaimsTransformation>(sp => new SimulationClaimsTransformation(
                sp.GetRequiredService<IHttpContextAccessor>(),
                sp.GetRequiredService<UserSimulationOptions>(),
                sp.GetRequiredService<PermissionAuthorizationOptions>(),
                sp.GetRequiredService<ILogger<SimulationClaimsTransformation>>()));

            return new UserSimulationBuilder(services);
        }
    }

    /// <summary>Chains optional refinements onto <c>AddUserSimulation</c>.</summary>
    public sealed class UserSimulationBuilder
    {
        private readonly IServiceCollection _services;

        internal UserSimulationBuilder(IServiceCollection services) => _services = services;

        /// <summary>
        /// Keeps a claims transformation the consumer already has, running it AFTER the simulation
        /// swap and on the swapped principal.
        /// </summary>
        /// <remarks>
        /// ASP.NET Core resolves <see cref="IClaimsTransformation"/> as a single service, so two
        /// registrations mean the second silently wins. Without this the consumer would have to
        /// choose between its own enrichment and simulation working — and would discover which it
        /// lost only from the symptom.
        ///
        /// Running the inner one on the SWAPPED principal is the useful order: the simulated session
        /// gets the target's own directory roles rather than inheriting the administrator's.
        /// </remarks>
        public UserSimulationBuilder ChainAfter<TInner>()
            where TInner : class, IClaimsTransformation
        {
            _services.AddTransient<TInner>();

            // Replaces the plain registration made above; last one wins for a single-service resolve,
            // and leaving both would be a coin toss.
            _services.RemoveAll<IClaimsTransformation>();
            _services.AddTransient<IClaimsTransformation>(sp => new SimulationClaimsTransformation(
                sp.GetRequiredService<IHttpContextAccessor>(),
                sp.GetRequiredService<UserSimulationOptions>(),
                sp.GetRequiredService<PermissionAuthorizationOptions>(),
                sp.GetRequiredService<ILogger<SimulationClaimsTransformation>>(),
                inner: sp.GetRequiredService<TInner>()));

            return this;
        }
    }
}
