using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Encodings.Web;
using kdyf.Authorization.Administration.Abstractions;
using kdyf.Authorization.Administration.Persistence;
using kdyf.Authorization;
using kdyf.Authorization.Abstractions;
using kdyf.Authorization.EntityFrameworkCore;
using kdyf.Authorization.Roles;
using kdyf.Authorization.Simulation;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace kdyf.Authorization.Administration.Test;

/// <summary>
/// User simulation over HTTP, mounted the way an application mounts it: real authentication, the host's
/// policies, permissions resolved from (an in-memory) Entra group and the roles in SQLite, the simulation
/// middleware, the end endpoint and the audit log of the administration.
/// </summary>
/// <remarks>
/// The endpoints behind the doors are stand-ins — one read and one write per door — because what is asserted
/// is the wall in front of them: a simulated session cannot write, it opens only the simulated person's doors,
/// and its start and end are recorded with the real administrator. The administration's own endpoints are
/// exposed, and tested, by kdyf.Authorization.Administration.Endpoints.
/// </remarks>
[TestClass]
public sealed class SimulationPipelineTests
{
    private const string Admin = People.Admin + "|admin@test";
    private const string TokenUser = People.TokenUser + "|tokens@test";

    private const string AdministrationPath = "/test/administration";
    private const string TokensPath = "/test/tokens";
    private const string EndPath = "/test/simulation/end";
    private const string SearchPath = "/test/tokens/search";

    private sealed record EndRequest(string Email);

    private SqliteConnection _connection = null!;
    private WebApplication _app = null!;
    private HttpClient _client = null!;
    private FakeEntra _entra = null!;
    private int _writesServed;

    [TestInitialize]
    public async Task Start()
    {
        _connection = new SqliteConnection("DataSource=:memory:");
        _connection.Open();

        var assembly = typeof(SimulationPipelineTests).Assembly;
        _entra = new FakeEntra()
            .Add(People.Admin, "admin@test")
            .Add(People.Reader, "reader@test")
            .Add(People.TokenUser, "tokens@test")
            .Add(People.Newcomer, "newcomer@test", member: false);

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();

        builder.Services.AddDbContext<AdminTestContext>(o => o.UseSqlite(_connection));
        builder.Services
            .AddAuthentication(TestAuthHandler.SchemeName)
            .AddScheme<AuthenticationSchemeOptions, TestAuthHandler>(TestAuthHandler.SchemeName, _ => { });
        builder.Services.AddAuthorization();

        builder.Services
            .AddPermissionAuthorization(o =>
            {
                o.AuthenticationSchemes = new[] { TestAuthHandler.SchemeName };
                o.AdministrationPermissionCode = AccessFixture.AdministrationCode;
                o.MemberPermissionCodes = new HashSet<string>(apitest.TestRoleConfiguration.MemberGrants);
                o.ValidatePoliciesOnStartup = false;
            })
            .AddAssignedRoles(assembly)
            .AddPolicies(assembly);
        builder.Services.AddEfRoles<AdminTestContext>();

        builder.Services.AddSingleton(_entra);
        builder.Services.AddSingleton<IMembershipSource>(_entra);
        builder.Services.AddSingleton<IAccessDirectory>(_entra);
        builder.Services.AddSingleton<IDirectoryService>(_entra);

        builder.Services.AddUserSimulation<MembershipSimulationTargetResolver>(o => o.RequiredPermission = new apitest.SimulatePermission().Code);

        // The administration's audit log is what records who read the application as whom.
        builder.Services.AddAuthAdministration<AdminTestContext>();

        _app = builder.Build();
        _app.UseAuthentication();
        _app.UseUserSimulation();
        _app.UseAuthorization();

        _app.MapGet(AdministrationPath, () => Results.Ok()).RequireAuthorization(apitest.TestAdministrationPolicy.PolicyName);
        _app.MapPut(AdministrationPath, () => { _writesServed++; return Results.Ok(); })
            .RequireAuthorization(apitest.TestAdministrationPolicy.PolicyName);
        _app.MapGet(TokensPath, () => Results.Ok()).RequireAuthorization(apitest.TestTokensPolicy.PolicyName);
        // Every verb that may write, behind a door the simulated token user opens — so the only thing that can
        // refuse them is the read-only simulation. The search is a POST that only reads, and says so.
        _app.MapPost(TokensPath, () => { _writesServed++; return Results.Ok(); }).RequireAuthorization(apitest.TestTokensPolicy.PolicyName);
        _app.MapPut(TokensPath, () => { _writesServed++; return Results.Ok(); }).RequireAuthorization(apitest.TestTokensPolicy.PolicyName);
        _app.MapPatch(TokensPath, () => { _writesServed++; return Results.Ok(); }).RequireAuthorization(apitest.TestTokensPolicy.PolicyName);
        _app.MapDelete(TokensPath, () => { _writesServed++; return Results.Ok(); }).RequireAuthorization(apitest.TestTokensPolicy.PolicyName);
        _app.MapPost(SearchPath, () => Results.Ok())
            .WithMetadata(new ReadOnlyOperationAttribute())
            .RequireAuthorization(apitest.TestTokensPolicy.PolicyName);
        // A stand-in for the end of a simulation as a host exposes it (POST auth/simulation/end):
        // behind the simulation policy, it records the end and forgets the session.
        _app.MapPost(EndPath, async (EndRequest body, HttpContext http) =>
        {
            var services = http.RequestServices;
            var caller = services.GetRequiredService<IUserIdentityResolver>().Resolve(http.User)!;
            var target = (await services.GetRequiredService<ISimulationTargetResolver>().ResolveAsync(body.Email))!;
            await services.GetRequiredService<ISimulationRecorder>().EndedAsync(
                new SimulationSession(caller.SubjectId!, caller.Email!, target.SubjectId!, target.Email));
            services.GetRequiredService<SimulationSessions>().End(caller.SubjectId!, target.SubjectId!);
            return Results.NoContent();
        })
        .RequireAuthorization(apitest.TestSimulationPolicy.PolicyName);

        using (var scope = _app.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AdminTestContext>();
            db.Database.EnsureCreated();
            // The whole tree, as the startup synchronisation writes it: the root and the ancestors too.
            db.AddRange(new kdyf.Authorization.Roles.DeclaredPermissions(PermissionDefinition.DiscoverIn(assembly)).Permissions
                .Select(p => AccessFixture.CatalogRow(p.Code)));
            db.AddRange(apitest.TestRoleConfiguration.Roles());
            db.AddRange(apitest.TestRoleConfiguration.Rows());
            db.AddRange(
                AccessFixture.Holds(People.Admin, "App.Admin"),
                AccessFixture.Holds(People.Reader, "App.Reader"),
                AccessFixture.Holds(People.TokenUser, "App.TokenUser"));
            db.SaveChanges();
        }

        await _app.StartAsync();
        _client = _app.GetTestClient();
    }

    [TestCleanup]
    public async Task Stop()
    {
        _client?.Dispose();
        if (_app is not null)
            await _app.DisposeAsync();
        _connection?.Dispose();
    }

    /// <summary>The doors themselves, without simulating: the administrator opens administration, the token user does not.</summary>
    [TestMethod]
    public async Task Without_simulating_each_door_answers_its_holders()
    {
        Assert.AreEqual(HttpStatusCode.Unauthorized, (await Send(HttpMethod.Get, AdministrationPath, null)).StatusCode);
        Assert.AreEqual(HttpStatusCode.OK, (await Send(HttpMethod.Get, AdministrationPath, Admin)).StatusCode);
        Assert.AreEqual(HttpStatusCode.Forbidden, (await Send(HttpMethod.Get, AdministrationPath, TokenUser)).StatusCode);
        Assert.AreEqual(HttpStatusCode.OK, (await Send(HttpMethod.Put, AdministrationPath, Admin)).StatusCode);
    }

    /// <summary>
    /// A simulated session cannot write — not even an administrator's, not even behind a door they open.
    /// Refused before any endpoint runs: the write is never served, nothing audited.
    /// </summary>
    [TestMethod]
    public async Task No_write_goes_through_while_simulating()
    {
        var response = await Send(HttpMethod.Put, AdministrationPath, Admin, simulate: "reader@test");

        Assert.AreEqual(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.AreEqual(0, _writesServed);
        Assert.AreEqual(0, _entra.Writes.Count);
        Assert.AreEqual(0, AuditEntries().Count);
    }

    /// <summary>
    /// Every verb that may write is refused while simulating, behind a door the simulated person opens: PUT,
    /// PATCH, DELETE, and a POST nobody marked as a read. None is served.
    /// </summary>
    [TestMethod]
    [DataRow("POST")]
    [DataRow("PUT")]
    [DataRow("PATCH")]
    [DataRow("DELETE")]
    public async Task Every_verb_that_may_write_is_refused_while_simulating(string verb)
    {
        var response = await Send(new HttpMethod(verb), TokensPath, Admin, simulate: "tokens@test");

        Assert.AreEqual(HttpStatusCode.Forbidden, response.StatusCode, verb);
        StringAssert.Contains(await response.Content.ReadAsStringAsync(), "read-only");
        Assert.AreEqual(0, _writesServed, verb);
    }

    /// <summary>The same verbs, without simulating: the door is open, so only the simulation refused them above.</summary>
    [TestMethod]
    [DataRow("POST")]
    [DataRow("PUT")]
    [DataRow("PATCH")]
    [DataRow("DELETE")]
    public async Task Without_simulating_the_same_verbs_are_served(string verb)
    {
        Assert.AreEqual(HttpStatusCode.OK, (await Send(new HttpMethod(verb), TokensPath, TokenUser)).StatusCode, verb);
    }

    /// <summary>A POST that says it only reads — a search with its filter in the body — passes a read-only simulation.</summary>
    [TestMethod]
    public async Task A_POST_marked_as_a_read_goes_through_while_simulating()
    {
        var response = await Send(HttpMethod.Post, SearchPath, Admin, new { text = "x" }, simulate: "tokens@test");

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode, await response.Content.ReadAsStringAsync());
    }

    /// <summary>The mark lets a read through a read-only simulation, and nothing else: the door still decides.</summary>
    [TestMethod]
    public async Task A_POST_marked_as_a_read_still_needs_its_door()
    {
        var response = await Send(HttpMethod.Post, SearchPath, Admin, new { text = "x" }, simulate: "reader@test");

        Assert.AreEqual(HttpStatusCode.Forbidden, response.StatusCode, "a reader does not open the tokens door");
        StringAssert.DoesNotMatch(await response.Content.ReadAsStringAsync(), new System.Text.RegularExpressions.Regex("read-only"));
    }

    /// <summary>While simulating, the SIMULATED person's permissions gate the doors: a reader cannot open administration.</summary>
    [TestMethod]
    public async Task A_simulated_session_opens_only_the_simulated_persons_doors()
    {
        var response = await Send(HttpMethod.Get, AdministrationPath, Admin, simulate: "reader@test");

        Assert.AreEqual(HttpStatusCode.Forbidden, response.StatusCode);
    }

    /// <summary>
    /// Who read the application as whom, in the audit log: the first simulated request records the start —
    /// with the REAL administrator as the actor — and the following ones do not repeat it.
    /// </summary>
    [TestMethod]
    public async Task A_simulation_is_recorded_in_the_audit_log_when_it_starts()
    {
        Assert.AreEqual(HttpStatusCode.OK, (await Send(HttpMethod.Get, TokensPath, Admin, simulate: "tokens@test")).StatusCode);
        await Send(HttpMethod.Get, TokensPath, Admin, simulate: "tokens@test");

        var entry = AuditEntries().Single();
        Assert.AreEqual("simulation.started", entry.Action);
        Assert.AreEqual(People.Admin, entry.ActorObjectId, "the actor is the real administrator");
        Assert.AreEqual(People.TokenUser, entry.TargetId, "the target is the simulated person");
    }

    [TestMethod]
    public async Task Ending_a_simulation_records_the_end_and_the_next_one_starts_anew()
    {
        await Send(HttpMethod.Get, TokensPath, Admin, simulate: "tokens@test");

        var end = await Send(HttpMethod.Post, EndPath, Admin, new { email = "tokens@test" });
        Assert.AreEqual(HttpStatusCode.NoContent, end.StatusCode, await end.Content.ReadAsStringAsync());

        await Send(HttpMethod.Get, TokensPath, Admin, simulate: "tokens@test");

        CollectionAssert.AreEqual(new[] { "simulation.started", "simulation.ended", "simulation.started" },
            AuditEntries().Select(e => e.Action).ToArray());
        Assert.AreEqual(People.Admin, AuditEntries()[1].ActorObjectId);
    }

    [TestMethod]
    public async Task Only_who_may_simulate_can_end_a_simulation()
    {
        var response = await Send(HttpMethod.Post, EndPath, TokenUser, new { email = "reader@test" });

        Assert.AreEqual(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.AreEqual(0, AuditEntries().Count);
    }

    /// <summary>Ending is a write too: it cannot be sent from inside the simulation it ends.</summary>
    [TestMethod]
    public async Task A_simulation_cannot_be_ended_from_inside_it()
    {
        var response = await Send(HttpMethod.Post, EndPath, Admin, new { email = "tokens@test" }, simulate: "tokens@test");

        Assert.AreEqual(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.IsFalse(AuditEntries().Any(e => e.Action == "simulation.ended"));
    }

    // ── Plumbing ─────────────────────────────────────────────────────────────

    private List<AuditLogEntry> AuditEntries()
    {
        using var scope = _app.Services.CreateScope();
        return scope.ServiceProvider.GetRequiredService<AdminTestContext>().Set<AuditLogEntry>()
            .AsNoTracking().OrderBy(e => e.AuditLogId).ToList();
    }

    private Task<HttpResponseMessage> Send(HttpMethod method, string path, string? as_, object? body = null, string? simulate = null)
    {
        var request = new HttpRequestMessage(method, path);
        if (as_ is not null)
            request.Headers.Add(TestAuthHandler.Header, as_);
        if (simulate is not null)
            request.Headers.Add("X-Simulate-User", simulate);
        if (body is not null)
            request.Content = JsonContent.Create(body);
        return _client.SendAsync(request);
    }
}

/// <summary>
/// Authenticates from a header <c>objectId|email</c>, the way an Entra token carries them. No header,
/// no identity: the request is anonymous.
/// </summary>
internal sealed class TestAuthHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    internal const string SchemeName = "Test";
    internal const string Header = "X-Test-User";

    public TestAuthHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder)
        : base(options, logger, encoder) { }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue(Header, out var value))
            return Task.FromResult(AuthenticateResult.NoResult());

        var parts = value.ToString().Split('|');
        var identity = new ClaimsIdentity(new[]
        {
            new Claim("oid", parts[0]),
            new Claim("preferred_username", parts[1]),
        }, SchemeName);

        return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName)));
    }
}
