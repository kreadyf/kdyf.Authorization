using Microsoft.Extensions.DependencyInjection;
using kdyf.Authorization.Simulation;

// ASP.NET namespace on purpose: the host finds it with the usings it already has.
namespace Microsoft.AspNetCore.Builder
{
    public static class KdyfAuthorizationApplicationExtensions
    {
        /// <summary>
        /// Authentication, the answer to a refused simulation (when simulation is on), then authorization —
        /// in that order.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The host decides WHERE: static files and the SPA fallback go BEFORE this call, because the SPA
        /// has to load in order to sign in; with the fallback policy in front, even index.html would
        /// answer 401. The library cannot enforce that without also serving the SPA, which is the host's
        /// business.
        /// </para>
        /// <para>
        /// The library maps no endpoints: who the caller is, what they may do and the administration are
        /// exposed by the host itself, over the services registered by <c>AddKdyfAuthorization</c> (for instance
        /// <c>PolicyReport</c>).
        /// </para>
        /// </remarks>
        public static IApplicationBuilder UseKdyfAuthorization(this IApplicationBuilder app)
        {
            app.UseAuthentication();

            // Registered by AddKdyfAuthorization only when the builder named a simulation policy. It has to sit here:
            // the decision is taken during authentication, and a refusal must not reach an endpoint.
            if (app.ApplicationServices.GetService<UserSimulationOptions>() is not null)
                app.UseUserSimulation();

            app.UseAuthorization();
            return app;
        }
    }
}
