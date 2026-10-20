using kdyf.Authorization.Abstractions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace kdyf.Authorization.Simulation
{
    /// <summary>
    /// Answers a simulation attempt that was refused.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Deliberately small. The work — may this caller simulate, does the target exist, is the verb
    /// allowed, and the swap itself — happens in <see cref="SimulationClaimsTransformation"/>,
    /// because that is the only place where it survives (see the note there). What a transformation
    /// cannot do is write a 403, so it records the refusal and this turns it into a response.
    /// </para>
    /// <para>
    /// Without it a refused attempt would simply be served as the caller themselves. That is safe,
    /// but it is not honest: the client asked to be somebody else and would have no way to learn it
    /// did not happen — it would read its own data believing it was reading someone else's.
    /// </para>
    /// <para>
    /// Place it between <c>UseAuthentication()</c> and <c>UseAuthorization()</c>: the decision is
    /// made during authentication, and a refusal should not reach an endpoint.
    /// </para>
    /// </remarks>
    internal sealed class UserSimulationMiddleware
    {
        private readonly RequestDelegate _next;

        public UserSimulationMiddleware(RequestDelegate next) => _next = next;

        public Task InvokeAsync(HttpContext context)
        {
            if (context.Items.TryGetValue(SimulationClaimsTransformation.DecisionItemKey, out var item)
                && item is SimulationDecision { StatusCode: { } status, Error: { } error })
            {
                context.Response.StatusCode = status;
                context.Response.Headers.CacheControl = "no-store";
                return context.Response.WriteAsJsonAsync(new { error });
            }

            return _next(context);
        }
    }

    /// <summary>Adds the middleware that answers a refused simulation attempt.</summary>
    public static class UserSimulationApplicationBuilderExtensions
    {
        /// <summary>
        /// Must sit BETWEEN <c>UseAuthentication()</c> and <c>UseAuthorization()</c>.
        /// </summary>
        public static IApplicationBuilder UseUserSimulation(this IApplicationBuilder app) =>
            app.UseMiddleware<UserSimulationMiddleware>();
    }
}
