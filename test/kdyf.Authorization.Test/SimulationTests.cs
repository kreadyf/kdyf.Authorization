using System.Security.Claims;
using kdyf.Authorization.Abstractions;
using kdyf.Authorization.Authorization;
using kdyf.Authorization.Roles;
using kdyf.Authorization.Simulation;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;

namespace kdyf.Authorization.Test
{
    /// <summary>
    /// "See the application as another user" — and every way it could be turned into something else.
    /// </summary>
    [TestClass]
    public class SimulationTests
    {
        private const string Admin = "aaaaaaaa-0000-0000-0000-000000000001";
        private const string Support = "aaaaaaaa-0000-0000-0000-000000000002";
        private const string Reader = "aaaaaaaa-0000-0000-0000-000000000003";
        private const string Editor = "aaaaaaaa-0000-0000-0000-000000000004";

        private FakeMembershipSource _entra = null!;
        private FakeUserRoleSource _roles = null!;

        [TestInitialize]
        public void Setup()
        {
            _entra = new FakeMembershipSource()
                .Join(Admin, email: "admin@test")
                .Join(Support, email: "support@test")
                .Join(Reader, email: "reader@test", name: "Reader")
                .Join(Editor, email: "editor@test");
            _roles = new FakeUserRoleSource()
                .Give(Admin, "Portal.Admin")
                .Give(Support, "Portal.Support")
                .Give(Reader, "Portal.Reader")
                .Give(Editor, "Portal.Editor");
        }

        [TestMethod]
        public async Task An_administrator_reads_as_a_reader_with_the_readers_identity()
        {
            var (principal, status) = await Simulate(caller: Admin, callerEmail: "admin@test", target: "reader@test");

            Assert.AreEqual(StatusCodes.Status200OK, status);
            Assert.AreEqual(Reader, principal.FindFirst("oid")?.Value, "every permission check now reads the reader's");
            Assert.AreEqual("admin@test", principal.FindFirst("simulated_by")?.Value, "and who is really behind it travels along");
        }

        /// <summary>
        /// The escalation this closes: somebody allowed to simulate, borrowing an administrator, would read
        /// everything the administrator's menu opens — the audit log, the user list — read-only or not.
        /// </summary>
        [TestMethod]
        public async Task Nobody_simulates_a_user_who_holds_more_than_they_do()
        {
            var (principal, status) = await Simulate(caller: Support, callerEmail: "support@test", target: "admin@test");

            Assert.AreEqual(StatusCodes.Status403Forbidden, status);
            Assert.AreEqual(Support, principal.FindFirst("oid")?.Value, "the caller stays themselves");
        }

        [TestMethod]
        public async Task Holding_one_permission_more_is_already_too_much()
        {
            var (_, status) = await Simulate(caller: Support, callerEmail: "support@test", target: "editor@test");

            Assert.AreEqual(StatusCodes.Status403Forbidden, status, "an editor holds portal.Edit, which support does not");
        }

        [TestMethod]
        public async Task A_lesser_user_can_be_simulated_by_whoever_covers_them()
        {
            var (principal, status) = await Simulate(caller: Support, callerEmail: "support@test", target: "reader@test");

            Assert.AreEqual(StatusCodes.Status200OK, status);
            Assert.AreEqual(Reader, principal.FindFirst("oid")?.Value);
        }

        [TestMethod]
        public async Task Without_the_simulation_permission_the_attempt_is_refused()
        {
            var (_, status) = await Simulate(caller: Editor, callerEmail: "editor@test", target: "reader@test");

            Assert.AreEqual(StatusCodes.Status403Forbidden, status);
        }

        /// <summary>A write while simulating would land in the other person's name. Refused before any endpoint runs.</summary>
        [TestMethod]
        [DataRow("POST")]
        [DataRow("PUT")]
        [DataRow("PATCH")]
        [DataRow("DELETE")]
        public async Task Simulation_is_read_only(string method)
        {
            var (principal, status) = await Simulate(caller: Admin, callerEmail: "admin@test", target: "reader@test", method: method);

            Assert.AreEqual(StatusCodes.Status403Forbidden, status);
            Assert.AreEqual(Admin, principal.FindFirst("oid")?.Value);
        }

        [TestMethod]
        public async Task Somebody_without_access_cannot_be_simulated()
        {
            _entra.Leave(Reader);

            var (_, status) = await Simulate(caller: Admin, callerEmail: "admin@test", target: "reader@test");

            Assert.AreEqual(StatusCodes.Status400BadRequest, status);
        }

        // ── The trace a simulation leaves ────────────────────────────────────────

        /// <summary>The real administrator stays identifiable by the id that survives a renamed e-mail.</summary>
        [TestMethod]
        public async Task The_borrowed_identity_carries_the_real_administrators_object_id()
        {
            var (principal, _) = await Simulate(caller: Admin, callerEmail: "admin@test", target: "reader@test");

            Assert.AreEqual(Admin, principal.FindFirst("simulated_by_oid")?.Value);
        }

        /// <summary>A simulation is recorded once when it starts, not on every request it makes.</summary>
        [TestMethod]
        public async Task The_start_is_recorded_once_per_simulation()
        {
            await Simulate(caller: Admin, callerEmail: "admin@test", target: "reader@test");
            await Simulate(caller: Admin, callerEmail: "admin@test", target: "reader@test");

            var started = _recorder.Started.Single();
            Assert.AreEqual(Admin, started.RealSubjectId);
            Assert.AreEqual(Reader, started.TargetSubjectId);
            Assert.AreEqual("/api/data", started.Path);
        }

        [TestMethod]
        public async Task A_simulation_that_ended_records_a_new_start_the_next_time()
        {
            await Simulate(caller: Admin, callerEmail: "admin@test", target: "reader@test");
            _sessions.End(Admin, Reader);
            await Simulate(caller: Admin, callerEmail: "admin@test", target: "reader@test");

            Assert.AreEqual(2, _recorder.Started.Count);
        }

        /// <summary>Reading somebody else's data without a trace is what the record prevents: no record, no simulation.</summary>
        [TestMethod]
        public async Task A_simulation_whose_start_cannot_be_recorded_is_refused()
        {
            _recorder.Fail = true;

            var (principal, status) = await Simulate(caller: Admin, callerEmail: "admin@test", target: "reader@test");

            Assert.AreEqual(StatusCodes.Status503ServiceUnavailable, status);
            Assert.AreEqual(Admin, principal.FindFirst("oid")?.Value, "served as nobody but the caller");
            Assert.IsFalse(_sessions.IsActive(Admin, Reader), "and not counted as started");
        }

        [TestMethod]
        public async Task A_caller_without_an_object_id_cannot_simulate()
        {
            var (_, status) = await Simulate(caller: null, callerEmail: "admin@test", target: "reader@test");

            Assert.AreEqual(StatusCodes.Status403Forbidden, status);
            Assert.AreEqual(0, _recorder.Started.Count);
        }

        private readonly RecordingSimulationRecorder _recorder = new();
        private static readonly UserSimulationOptions Options = new() { RequiredPermission = "support.Simulate" };
        private SimulationSessions _sessions = new(new Microsoft.Extensions.Caching.Memory.MemoryCache(new Microsoft.Extensions.Caching.Memory.MemoryCacheOptions()), Options);

        /// <summary>Runs the transformation and then the middleware that answers a refusal, as the pipeline does.</summary>
        private async Task<(ClaimsPrincipal Principal, int Status)> Simulate(
            string? caller, string callerEmail, string target, string method = "GET")
        {
            var catalog = RolePermissionMapProvider.ForSource(
                new FakeRolePermissionSource(TestRoles.Grants()), TestRoles.Declared(), TimeSpan.FromMinutes(2), TestRoles.MemberGrants);
            var identityOptions = new PermissionAuthorizationOptions();

            var services = new ServiceCollection()
                .AddSingleton(identityOptions)
                .AddSingleton<IUserIdentityResolver>(new ClaimsUserIdentityResolver(identityOptions))
                .AddSingleton<IPermissionStore>(new MembershipPermissionStore(_entra, _roles, catalog, NullLogger<MembershipPermissionStore>.Instance))
                .AddSingleton<IPrincipalPermissionResolver, PrincipalPermissionResolver>()
                .AddSingleton<ISimulationTargetResolver>(new MembershipSimulationTargetResolver(_entra, _roles, catalog))
                .AddSingleton(_sessions)
                .AddSingleton<ISimulationRecorder>(_recorder)
                .BuildServiceProvider();

            var http = new DefaultHttpContext { RequestServices = services };
            http.Request.Method = method;
            http.Request.Path = "/api/data";
            http.Request.Headers["X-Simulate-User"] = target;

            var claims = new List<Claim> { new("email", callerEmail) };
            if (caller is not null)
                claims.Add(new Claim("oid", caller));
            var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, "Bearer"));

            var transformation = new SimulationClaimsTransformation(
                new HttpContextAccessor { HttpContext = http },
                Options,
                identityOptions,
                NullLogger<SimulationClaimsTransformation>.Instance);

            var result = await transformation.TransformAsync(principal);
            await new UserSimulationMiddleware(_ => Task.CompletedTask).InvokeAsync(http);

            return (result, http.Response.StatusCode);
        }
    }

    /// <summary>Keeps what was recorded; fails on cue.</summary>
    internal sealed class RecordingSimulationRecorder : ISimulationRecorder
    {
        internal List<SimulationSession> Started { get; } = new();
        internal List<SimulationSession> Ended { get; } = new();
        internal bool Fail { get; set; }

        public Task StartedAsync(SimulationSession session, CancellationToken cancellationToken = default)
        {
            if (Fail)
                throw new InvalidOperationException("audit log unreachable");
            Started.Add(session);
            return Task.CompletedTask;
        }

        public Task EndedAsync(SimulationSession session, CancellationToken cancellationToken = default)
        {
            Ended.Add(session);
            return Task.CompletedTask;
        }
    }
}
