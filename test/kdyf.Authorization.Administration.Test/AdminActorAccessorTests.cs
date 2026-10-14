using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using kdyf.Authorization.Abstractions;
using kdyf.Authorization.Simulation;

namespace kdyf.Authorization.Administration.Test;

/// <summary>
/// The actor every administration rule is decided on. The point of the accessor: a simulation is recognised by the
/// claim the HOST configured, so "no changes while simulating" cannot be bypassed by reading the wrong claim.
/// </summary>
[TestClass]
public sealed class AdminActorAccessorTests
{
    private const string Admin = "11111111-1111-1111-1111-111111111111";

    [TestMethod]
    public async Task A_simulation_is_recognised_by_the_configured_claim()
    {
        var accessor = Accessor(
            Principal(new Claim("acted_by", "admin@test")),
            new UserSimulationOptions { SimulatedByClaimType = "acted_by" });

        var actor = await accessor.GetAsync();

        Assert.IsTrue(actor.IsSimulating);
        Assert.AreEqual("admin@test", actor.SimulatedBy);
    }

    /// <summary>With a configured claim, the default one means nothing — and the configured one is what counts.</summary>
    [TestMethod]
    public async Task Only_the_configured_claim_marks_a_simulation()
    {
        var accessor = Accessor(
            Principal(new Claim("simulated_by", "someone@test")),
            new UserSimulationOptions { SimulatedByClaimType = "acted_by" });

        Assert.IsFalse((await accessor.GetAsync()).IsSimulating);
    }

    /// <summary>Simulation off: a principal still carrying the default claim was borrowed by something, and is refused changes.</summary>
    [TestMethod]
    public async Task Without_simulation_the_default_claim_still_marks_a_borrowed_principal()
    {
        var accessor = Accessor(Principal(new Claim("simulated_by", "someone@test")), simulation: null);

        Assert.IsTrue((await accessor.GetAsync()).IsSimulating);
    }

    [TestMethod]
    public async Task The_actor_is_who_the_principal_is_with_what_they_hold()
    {
        var accessor = Accessor(Principal(), simulation: null);

        var actor = await accessor.GetAsync();

        Assert.AreEqual(Admin, actor.Identity.SubjectId);
        CollectionAssert.AreEquivalent(new[] { "global.UserAdministration" }, actor.Permissions.ToArray());
        Assert.IsTrue(actor.IsPerson);
        Assert.IsFalse(actor.IsSimulating);
    }

    /// <summary>Resolved once per request: two lookups could disagree across a cache expiry.</summary>
    [TestMethod]
    public async Task The_actor_is_resolved_once_per_request()
    {
        var permissions = new CountingPermissions();
        var accessor = new HttpContextAdminActorAccessor(Http(Principal()), permissions, new OidIdentities());

        var first = await accessor.GetAsync();
        var second = await accessor.GetAsync();

        Assert.AreSame(first, second);
        Assert.AreEqual(1, permissions.Calls);
    }

    [TestMethod]
    public async Task Outside_a_request_there_is_no_actor()
    {
        var accessor = new HttpContextAdminActorAccessor(new HttpContextAccessor(), new CountingPermissions(), new OidIdentities());

        await Assert.ThrowsExceptionAsync<InvalidOperationException>(() => accessor.GetAsync());
    }

    // ── Plumbing ─────────────────────────────────────────────────────────────

    private static ClaimsPrincipal Principal(params Claim[] extra) =>
        new(new ClaimsIdentity(new[] { new Claim("oid", Admin), new Claim("email", "me@test") }.Concat(extra), "Test"));

    private static IHttpContextAccessor Http(ClaimsPrincipal user) =>
        new HttpContextAccessor { HttpContext = new DefaultHttpContext { User = user } };

    private static HttpContextAdminActorAccessor Accessor(ClaimsPrincipal user, UserSimulationOptions? simulation) =>
        new(Http(user), new CountingPermissions(), new OidIdentities(), simulation);

    private sealed class CountingPermissions : IPrincipalPermissionResolver
    {
        public int Calls { get; private set; }

        public Task<IReadOnlySet<string>> ResolveAsync(ClaimsPrincipal principal, CancellationToken cancellationToken = default)
        {
            Calls++;
            return Task.FromResult<IReadOnlySet<string>>(new HashSet<string>(StringComparer.Ordinal) { "global.UserAdministration" });
        }
    }

    private sealed class OidIdentities : IUserIdentityResolver
    {
        public UserIdentity? Resolve(ClaimsPrincipal principal) =>
            new(principal.FindFirst("oid")?.Value, principal.FindFirst("email")?.Value);
    }
}
