using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using kdyf.Authorization.Administration;
using kdyf.Authorization.Administration.Endpoints.Contracts;
using kdyf.Authorization.Administration.Models;
using kdyf.Authorization.AspNetCore.Endpoints;
using kdyf.Authorization.Simulation;

// ASP.NET namespace on purpose: the host finds it with the usings it already has.
namespace Microsoft.AspNetCore.Builder
{
    public static class KdyfAuthorizationSimulationEndpoints
    {
        /// <summary>
        /// User simulation under <paramref name="prefix"/>: <c>GET candidates</c> (who can be simulated), <c>POST start</c>
        /// and <c>POST end</c>.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The client flow. <c>GET candidates</c> lists who can be simulated. <c>POST start</c> (without the header) checks
        /// the person may be simulated and records the start; the client then sends the header it answers with on every
        /// request, and the server serves them as that person and refuses every write. <c>POST end</c> (without the
        /// header) records the end. A simulation nobody ends expires after its idle timeout.
        /// </para>
        /// <para>
        /// Every endpoint demands the policy simulation was switched on with (<c>AddKdyfAuthorizationSimulation</c>), and
        /// the service checks its permission again. Answers, through <see cref="IKdyfAuthorizationResultWriter"/>: 200 with
        /// the data; 204 on <c>end</c>; 422 when a rule refuses or the e-mail is malformed; 404 when nobody who may be
        /// simulated answers to the e-mail; a fixed message when the database or the directory fails.
        /// </para>
        /// </remarks>
        public static RouteGroupBuilder MapKdyfAuthorizationSimulation(this IEndpointRouteBuilder routes, string prefix = "/auth/simulation")
        {
            ArgumentNullException.ThrowIfNull(routes);

            var policy = routes.ServiceProvider.GetService<UserSimulationOptions>()?.PolicyName
                ?? throw new InvalidOperationException(
                    "MapKdyfAuthorizationSimulation exposes user simulation, which is not switched on: call AddKdyfAuthorizationSimulation(policy) first.");

            var group = routes.MapGroup(prefix)
                .RequireAuthorization(policy)
                .AddEndpointFilter<HideFailuresFilter>();

            // Checks the person may be simulated, records the start and answers how to carry on.
            group.MapPost("start", async (StartSimulationRequestDto request, HttpContext http, ClaimsPrincipal user, [FromServices] ISimulationAdminService simulation, CancellationToken ct) =>
                Answer(http, await simulation.StartAsync(user, request.Email, http.Request.Path.Value, ct), started => ResultWriter.For(http).Ok(http, SimulationMapper.ToDto(started))));

            // Records the end of the caller's simulation of that person.
            group.MapPost("end", async (EndSimulationRequestDto request, HttpContext http, ClaimsPrincipal user, [FromServices] ISimulationAdminService simulation, CancellationToken ct) =>
                Answer(http, await simulation.EndAsync(user, request.Email, ct), _ => ResultWriter.For(http).NoContent(http)));

            // Everybody with access but the caller, each with whether a start would be accepted — and why not.
            group.MapGet("candidates", async (HttpContext http, ClaimsPrincipal user, [FromServices] ISimulationAdminService simulation, CancellationToken ct) =>
                Answer(http, await simulation.ListCandidatesAsync(user, ct), candidates => ResultWriter.For(http).Ok(http, SimulationMapper.ToDto(candidates))));

            return group;
        }

        /// <summary>The answer, 404 when nobody answers to the e-mail, or 422 with the service's refusal.</summary>
        private static IResult Answer<T>(HttpContext http, SimulationResult<T> result, Func<T, IResult> ok)
        {
            var writer = ResultWriter.For(http);
            if (result.NotFound is { } missing)
                return writer.NotFound(http, missing);

            return result.Validation.IsValid
                ? ok(result.Data)
                : writer.Rejected(http, new AuthorizationRejection(
                    result.Validation.Errors.ToList(),
                    result.Validation.Fields.ToDictionary(f => f.Key, f => (IReadOnlyList<string>)f.Value.Errors.ToList())));
        }
    }
}
