using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using kdyf.Authorization.Administration;
using kdyf.Authorization.Simulation;

namespace kdyf.Authorization.Endpoints.Test;

/// <summary>
/// The routes, verbs and doors of the library's endpoints: the contract clients are built against. A change here is
/// a breaking change.
/// </summary>
[TestClass]
public sealed class RouteContractTests
{
    private const string Admin = AccessPolicyNames.Administration;
    private const string Tokens = AccessPolicyNames.PersonalAccessTokens;
    private const string Session = "(authenticated)";

    private static readonly (string Verb, string Route, string Door)[] Expected =
    [
        ("GET", "/auth/users", Admin),
        ("GET", "/auth/users/{objectId:guid}", Admin),
        ("PUT", "/auth/users/{objectId:guid}/roles", Admin),
        ("DELETE", "/auth/users/{objectId:guid}", Admin),
        ("POST", "/auth/users/{objectId:guid}/suspension", Admin),
        ("DELETE", "/auth/users/{objectId:guid}/suspension", Admin),
        ("GET", "/auth/roles", Admin),
        ("POST", "/auth/roles", Admin),
        ("GET", "/auth/roles/orphans", Admin),
        ("DELETE", "/auth/roles/orphans", Admin),
        ("GET", "/auth/roles/{roleValue}", Admin),
        ("PUT", "/auth/roles/{roleValue}", Admin),
        ("DELETE", "/auth/roles/{roleValue}", Admin),
        ("PUT", "/auth/roles/{roleValue}/permissions", Admin),
        ("GET", "/auth/permissions", Admin),
        ("GET", "/auth/directory/users", Admin),
        ("POST", "/auth/directory/invitations", Admin),
        ("POST", "/auth/audit/{skip:int}/{take:int}", Admin),
        ("GET", "/auth/pat", Tokens),
        ("POST", "/auth/pat", Tokens),
        ("POST", "/auth/pat/{id:int}/deactivate", Tokens),
        ("POST", "/auth/pat/{id:int}/activate", Tokens),
        ("DELETE", "/auth/pat/{id:int}", Tokens),
        ("GET", "/auth/me", kdyf.Authorization.AspNetCore.KdyfAuthorizationPolicies.SignedIn),
        ("GET", "/auth/policies", kdyf.Authorization.AspNetCore.KdyfAuthorizationPolicies.SignedIn),
        ("POST", "/auth/simulation/start", TestHost.SimulationPolicy),
        ("POST", "/auth/simulation/end", TestHost.SimulationPolicy),
        ("GET", "/auth/simulation/candidates", TestHost.SimulationPolicy),
    ];

    [TestMethod]
    public async Task Every_route_has_its_verb_and_its_door()
    {
        await using var host = await TestHost.StartAsync();

        var actual = host.Endpoints
            .Select(e => (
                Verb: e.Metadata.GetMetadata<HttpMethodMetadata>()!.HttpMethods.Single(),
                Route: e.RoutePattern.RawText!,
                Door: Door(e)))
            .OrderBy(e => e.Route).ThenBy(e => e.Verb)
            .ToList();

        CollectionAssert.AreEqual(
            Expected.OrderBy(e => e.Route).ThenBy(e => e.Verb).Select(e => e.ToString()).ToList(),
            actual.Select(e => e.ToString()).ToList());
    }

    /// <summary>Every door is the library's, on the endpoint itself: a host cannot map one without it.</summary>
    [TestMethod]
    public async Task No_route_is_anonymous()
    {
        await using var host = await TestHost.StartAsync();

        foreach (var endpoint in host.Endpoints)
        {
            Assert.IsNull(endpoint.Metadata.GetMetadata<IAllowAnonymous>(), endpoint.RoutePattern.RawText);
            Assert.AreNotEqual(0, endpoint.Metadata.GetOrderedMetadata<IAuthorizeData>().Count, endpoint.RoutePattern.RawText);
        }
    }

    /// <summary>
    /// The only POST that reads is marked so: it answers during a (read-only) simulation. Any other POST marked by
    /// mistake would let a write through while somebody reads as somebody else.
    /// </summary>
    [TestMethod]
    public async Task Only_the_audit_log_is_a_POST_that_reads()
    {
        await using var host = await TestHost.StartAsync();

        var reads = host.Endpoints
            .Where(e => e.Metadata.GetMetadata<ReadOnlyOperationAttribute>() is not null)
            .Select(e => e.RoutePattern.RawText)
            .ToList();

        CollectionAssert.AreEqual(new[] { "/auth/audit/{skip:int}/{take:int}" }, reads);
    }

    /// <summary>
    /// A host that references the packages but maps nothing exposes nothing — even with controllers on, which is
    /// exactly why the endpoints are minimal APIs.
    /// </summary>
    [TestMethod]
    public async Task Nothing_is_exposed_unless_the_host_maps_it()
    {
        await using var host = await TestHost.StartAsync(
            services => services.AddControllers(),
            app => app.MapControllers());

        Assert.IsFalse(host.Endpoints.Any(e => e.RoutePattern.RawText!.StartsWith("/auth", StringComparison.Ordinal)),
            string.Join(", ", host.Endpoints.Select(e => e.RoutePattern.RawText)));
    }

    [TestMethod]
    public async Task The_host_chooses_the_prefix()
    {
        await using var host = await TestHost.StartAsync(map: app =>
        {
            app.MapKdyfAuthorizationAdministration("/api/access");
            app.MapKdyfAuthorizationSession("/api/session");
            app.MapKdyfAuthorizationSimulation("/api/simulation");
        });

        var routes = host.Endpoints.Select(e => e.RoutePattern.RawText).ToList();
        CollectionAssert.Contains(routes, "/api/access/users");
        CollectionAssert.Contains(routes, "/api/session/me");
        CollectionAssert.Contains(routes, "/api/simulation/start");
        Assert.IsFalse(routes.Any(r => r!.StartsWith("/auth", StringComparison.Ordinal)));
    }

    /// <summary>Simulation endpoints without simulation switched on would answer "not enabled" forever: refused at startup.</summary>
    [TestMethod]
    public async Task Simulation_cannot_be_mapped_without_being_switched_on()
    {
        var error = await Assert.ThrowsExceptionAsync<InvalidOperationException>(() => TestHost.StartAsync(
            services => services.RemoveAll<UserSimulationOptions>(),
            app => app.MapKdyfAuthorizationSimulation()));

        StringAssert.Contains(error.Message, "AddKdyfAuthorizationSimulation");
    }

    private static string Door(RouteEndpoint endpoint)
    {
        var policies = endpoint.Metadata.GetOrderedMetadata<IAuthorizeData>()
            .Select(a => a.Policy)
            .Where(p => p is not null)
            .Distinct()
            .ToList();
        return policies.Count == 0 ? Session : string.Join("+", policies);
    }
}
