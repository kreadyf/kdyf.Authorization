using System.Security.Claims;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using kdyf.Authorization.Abstractions;
using kdyf.Authorization.AspNetCore.Endpoints;
using kdyf.Authorization.Authorization;
using kdyf.Authorization.Simulation;
using Microsoft.Extensions.DependencyInjection;

namespace kdyf.Authorization.AspNetCore.Endpoints
{
    /// <summary>The body of <c>GET auth/me</c>.</summary>
    internal sealed class CurrentUserDto
    {
        /// <summary>For the name on screen.</summary>
        public string? Name { get; init; }

        /// <summary>The e-mail of the person the session is served as.</summary>
        public string? Email { get; init; }

        /// <summary>Their immutable id ('oid').</summary>
        public string? ObjectId { get; init; }

        /// <summary>True while an administrator reads the application as this person: the server refuses every write.</summary>
        public bool IsSimulating { get; init; }

        /// <summary>The administrator behind the simulation; null outside one.</summary>
        public RealUserDto? RealUser { get; init; }

        /// <summary>How this server simulates, when it does: the header to send. Null when simulation is not switched on.</summary>
        public SimulationSettingsDto? Simulation { get; init; }
    }

    /// <summary>How a client asks this server for a simulation.</summary>
    internal sealed class SimulationSettingsDto
    {
        /// <summary>The header to send, with the simulated person's e-mail, on every request while simulating.</summary>
        public required string HeaderName { get; init; }
    }

    /// <summary>Who actually signed in, during a simulation.</summary>
    internal sealed class RealUserDto
    {
        public string? Email { get; init; }

        public string? ObjectId { get; init; }
    }

    /// <summary>One door of <c>GET auth/policies</c>: its name and whether the caller opens it.</summary>
    internal sealed class PolicyAccessDto
    {
        public required string Name { get; init; }

        public bool IsAuthorized { get; init; }
    }
}

// ASP.NET namespace on purpose: the host finds it with the usings it already has.
namespace Microsoft.AspNetCore.Builder
{
    /// <summary>Maps the session endpoints a client reads: who the caller is, and which doors they open.</summary>
    public static class KdyfAuthorizationSessionEndpoints
    {
        /// <summary>
        /// The session of a client: <c>GET {prefix}/me</c> (who the caller is, and during a simulation who is really
        /// behind it) and <c>GET {prefix}/policies</c> (door by door, whether the caller opens it).
        /// </summary>
        /// <remarks>
        /// <para>
        /// Both answer for the session the server is actually serving: during a simulation that is the simulated
        /// person. Both are open to anybody with a session, including people without access: a client needs to know
        /// who they are and that they open nothing, to tell them so. What they may do is <c>/policies</c>, never the
        /// token's claims, which are as old as the token.
        /// </para>
        /// <para>The group is returned so the host can add its own conventions (tags, rate limiting, CORS).</para>
        /// </remarks>
        public static RouteGroupBuilder MapKdyfAuthorizationSession(this IEndpointRouteBuilder routes, string prefix = "/auth")
        {
            ArgumentNullException.ThrowIfNull(routes);

            // A session only, not the access gate: somebody let in by nothing still learns who they are and that they
            // may do nothing, instead of a bare 403.
            var group = routes.MapGroup(prefix)
                .RequireAuthorization(kdyf.Authorization.AspNetCore.KdyfAuthorizationPolicies.SignedIn)
                .AddEndpointFilter<HideFailuresFilter>();

            group.MapGet("me", (HttpContext http, ClaimsPrincipal user, [FromServices] IUserContext context) =>
                ResultWriter.For(http).Ok(http, new CurrentUserDto
                {
                    Name = user.FindFirstValue("name") ?? user.Identity?.Name ?? context.Email,
                    Email = context.Email,
                    ObjectId = context.SubjectId,
                    IsSimulating = context.IsSimulating,
                    RealUser = context.IsSimulating
                        ? new RealUserDto { Email = context.RealEmail, ObjectId = context.RealSubjectId }
                        : null,
                    Simulation = http.RequestServices.GetService<UserSimulationOptions>() is { } simulation
                        ? new SimulationSettingsDto { HeaderName = simulation.HeaderName }
                        : null,
                }));

            group.MapGet("policies", async (HttpContext http, ClaimsPrincipal user, [FromServices] PolicyReport report, CancellationToken ct) =>
            {
                var policies = await report.EvaluateAsync(user, ct);
                return ResultWriter.For(http).Ok(http, policies
                    .Select(p => new PolicyAccessDto { Name = p.Name, IsAuthorized = p.IsAuthorized })
                    .ToList());
            });

            return group;
        }
    }
}
