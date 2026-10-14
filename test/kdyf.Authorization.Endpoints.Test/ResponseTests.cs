using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using kdyf.Authorization.Administration;
using kdyf.Authorization.Administration.Models;
using kdyf.Authorization.Administration.Validation;
using kdyf.Authorization.AspNetCore.Endpoints;

namespace kdyf.Authorization.Endpoints.Test;

/// <summary>
/// What the endpoints answer for what the services return: the data, a refusal, nothing found, a failure — and that
/// the actor the services receive is the accessor's.
/// </summary>
[TestClass]
public sealed class ResponseTests
{
    private const string Person = "22222222-2222-2222-2222-222222222222";

    // ── Doors ────────────────────────────────────────────────────────────────

    [TestMethod]
    public async Task Without_a_session_the_answer_is_401_and_the_service_is_not_called()
    {
        await using var host = await TestHost.StartAsync();

        var response = await host.Client.GetAsync("/auth/users");

        Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode);
        host.Access.VerifyNoOtherCalls();
    }

    [TestMethod]
    public async Task Without_the_administration_door_the_answer_is_403()
    {
        await using var host = await TestHost.StartAsync();

        var response = await host.Client.SendAsync(host.AsUser(HttpMethod.Get, "/auth/users"));

        Assert.AreEqual(HttpStatusCode.Forbidden, response.StatusCode);
        host.Access.VerifyNoOtherCalls();
    }

    // ── Answers ──────────────────────────────────────────────────────────────

    [TestMethod]
    public async Task The_data_comes_back_in_the_contract_shape_and_the_service_gets_the_accessors_actor()
    {
        await using var host = await TestHost.StartAsync();
        host.Access.Setup(a => a.ListUsersAsync(host.Actor, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Ok(new List<AccessUserResponse> { new() { ObjectId = Person, Email = "ana@test", HasAccess = true } }));

        var response = await host.Client.SendAsync(host.AsAdmin(HttpMethod.Get, "/auth/users"));

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        var user = (await response.Content.ReadFromJsonAsync<JsonElement>())[0];
        Assert.AreEqual(Person, user.GetProperty("objectId").GetString());
        Assert.AreEqual("ana@test", user.GetProperty("email").GetString());
        Assert.IsTrue(user.GetProperty("hasAccess").GetBoolean());
        Assert.AreEqual(JsonValueKind.Array, user.GetProperty("roles").ValueKind);
    }

    [TestMethod]
    public async Task A_refusal_is_422_with_the_messages_per_field()
    {
        await using var host = await TestHost.StartAsync();
        host.Access.Setup(a => a.SetRolesAsync(Person, It.Is<SetRolesRequest>(r => r.Roles.SequenceEqual(new[] { "Portal.Admin" })), host.Actor, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Refused<AccessUserResponse>("roles", "You cannot grant more than you hold."));

        var response = await host.Client.SendAsync(host.AsAdmin(HttpMethod.Put, $"/auth/users/{Person}/roles",
            JsonContent.Create(new { roles = new[] { "Portal.Admin" } })));

        Assert.AreEqual((HttpStatusCode)422, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.AreEqual("You cannot grant more than you hold.", body.GetProperty("errors").GetProperty("roles")[0].GetString());
    }

    [TestMethod]
    public async Task A_read_by_id_that_finds_nothing_is_404()
    {
        await using var host = await TestHost.StartAsync();
        host.Access.Setup(a => a.GetUserAsync(Person, host.Actor, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Refused<AccessUserResponse>("objectId", "Not visible."));

        var response = await host.Client.SendAsync(host.AsAdmin(HttpMethod.Get, $"/auth/users/{Person}"));

        Assert.AreEqual(HttpStatusCode.NotFound, response.StatusCode);
        StringAssert.Contains(await response.Content.ReadAsStringAsync(), "The user was not found.");
    }

    [TestMethod]
    public async Task A_deletion_is_204()
    {
        await using var host = await TestHost.StartAsync();
        host.Access.Setup(a => a.RevokeAsync(Person, host.Actor, It.IsAny<CancellationToken>())).ReturnsAsync(Ok(true));

        var response = await host.Client.SendAsync(host.AsAdmin(HttpMethod.Delete, $"/auth/users/{Person}"));

        Assert.AreEqual(HttpStatusCode.NoContent, response.StatusCode);
    }

    /// <summary>A database or directory failure never reaches the client with its own text.</summary>
    [TestMethod]
    public async Task A_failure_answers_a_fixed_message_without_the_exceptions_text()
    {
        await using var host = await TestHost.StartAsync();
        host.Access.Setup(a => a.ListRolesAsync(host.Actor, It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("Login failed for user 'sa' on server sql-prod-01."));

        var response = await host.Client.SendAsync(host.AsAdmin(HttpMethod.Get, "/auth/roles"));

        Assert.AreEqual(HttpStatusCode.InternalServerError, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        StringAssert.Contains(body, DefaultKdyfAuthorizationResultWriter.FailureMessage);
        Assert.IsFalse(body.Contains("sql-prod-01", StringComparison.Ordinal), body);
    }

    // ── Routing details ──────────────────────────────────────────────────────

    /// <summary>The literal segment wins: "orphans" is never read as a role called orphans.</summary>
    [TestMethod]
    public async Task Roles_orphans_is_the_report_not_a_role()
    {
        await using var host = await TestHost.StartAsync();
        host.Access.Setup(a => a.CheckRoleConsistencyAsync(host.Actor, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Ok(new RoleConsistencyResponse()));

        var response = await host.Client.SendAsync(host.AsAdmin(HttpMethod.Get, "/auth/roles/orphans"));

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        host.Access.Verify(a => a.GetRoleAsync(It.IsAny<string>(), It.IsAny<AdminActor>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    /// <summary>The filter is optional: the client may post the page request with no body.</summary>
    [TestMethod]
    public async Task The_audit_log_reads_without_a_filter()
    {
        await using var host = await TestHost.StartAsync();
        host.Audit.Setup(a => a.ListAsync(It.Is<AuditFilter>(f => f.Action == null), 0, 50, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Ok(new PagedResult<AuditEntryResponse> { Skip = 0, Take = 50 }));

        var response = await host.Client.SendAsync(host.AsAdmin(HttpMethod.Post, "/auth/audit/0/50"));

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        Assert.AreEqual(50, (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("take").GetInt32());
    }

    [TestMethod]
    public async Task A_non_numeric_token_id_matches_no_route()
    {
        await using var host = await TestHost.StartAsync();

        var response = await host.Client.SendAsync(host.AsAdmin(HttpMethod.Delete, "/auth/pat/abc"));

        Assert.AreEqual(HttpStatusCode.NotFound, response.StatusCode);
        host.Tokens.VerifyNoOtherCalls();
    }

    // ── The host's envelope ──────────────────────────────────────────────────

    /// <summary>A host keeps the envelope its clients read: every answer goes through its writer.</summary>
    [TestMethod]
    public async Task The_hosts_writer_shapes_every_answer()
    {
        await using var host = await TestHost.StartAsync(services =>
            services.AddSingleton<IKdyfAuthorizationResultWriter, EnvelopeWriter>());
        host.Access.Setup(a => a.ListPermissionsAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(Ok(new List<PermissionResponse> { new() { PermissionCode = "portal.Read" } }));
        host.Access.Setup(a => a.CreateRoleAsync(It.IsAny<CreateRoleRequest>(), host.Actor, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Refused<RoleResponse>("value", "Taken."));

        var ok = await (await host.Client.SendAsync(host.AsAdmin(HttpMethod.Get, "/auth/permissions"))).Content.ReadFromJsonAsync<JsonElement>();
        Assert.IsTrue(ok.GetProperty("isValid").GetBoolean());
        Assert.AreEqual("portal.Read", ok.GetProperty("data")[0].GetProperty("permissionCode").GetString());

        var refused = await host.Client.SendAsync(host.AsAdmin(HttpMethod.Post, "/auth/roles", JsonContent.Create(new { value = "Portal.Admin" })));
        Assert.AreEqual((HttpStatusCode)422, refused.StatusCode);
        var body = await refused.Content.ReadFromJsonAsync<JsonElement>();
        Assert.IsFalse(body.GetProperty("isValid").GetBoolean());
        Assert.AreEqual("Taken.", body.GetProperty("error").GetProperty("fields").GetProperty("value")[0].GetString());
    }

    // ── Session ──────────────────────────────────────────────────────────────

    [TestMethod]
    public async Task Me_names_the_session_and_the_real_person_behind_a_simulation()
    {
        await using var host = await TestHost.StartAsync();
        host.UserContext.SetupGet(u => u.Email).Returns("ana@test");
        host.UserContext.SetupGet(u => u.SubjectId).Returns(Person);
        host.UserContext.SetupGet(u => u.IsSimulating).Returns(true);
        host.UserContext.SetupGet(u => u.RealEmail).Returns("admin@test");
        host.UserContext.SetupGet(u => u.RealSubjectId).Returns("11111111-1111-1111-1111-111111111111");

        var me = await (await host.Client.SendAsync(host.AsUser(HttpMethod.Get, "/auth/me"))).Content.ReadFromJsonAsync<JsonElement>();

        Assert.AreEqual("user@test", me.GetProperty("name").GetString());
        Assert.AreEqual("ana@test", me.GetProperty("email").GetString());
        Assert.AreEqual(Person, me.GetProperty("objectId").GetString());
        Assert.IsTrue(me.GetProperty("isSimulating").GetBoolean());
        Assert.AreEqual("admin@test", me.GetProperty("realUser").GetProperty("email").GetString());
    }

    /// <summary>Anybody with a session, even without access: a client needs to tell them they have none.</summary>
    [TestMethod]
    public async Task Me_answers_anybody_with_a_session_and_nobody_without_one()
    {
        await using var host = await TestHost.StartAsync();

        Assert.AreEqual(HttpStatusCode.OK, (await host.Client.SendAsync(host.AsUser(HttpMethod.Get, "/auth/me"))).StatusCode);
        Assert.AreEqual(HttpStatusCode.Unauthorized, (await host.Client.GetAsync("/auth/me")).StatusCode);
    }

    [TestMethod]
    public async Task Me_tells_the_client_which_header_simulates()
    {
        await using var host = await TestHost.StartAsync();

        var me = await (await host.Client.SendAsync(host.AsUser(HttpMethod.Get, "/auth/me"))).Content.ReadFromJsonAsync<JsonElement>();

        Assert.AreEqual("X-Simulate-User", me.GetProperty("simulation").GetProperty("headerName").GetString());
    }

    // ── Simulation ───────────────────────────────────────────────────────────

    [TestMethod]
    public async Task Starting_answers_the_session_and_the_header_and_the_service_gets_the_e_mail_and_the_path()
    {
        await using var host = await TestHost.StartAsync();
        var context = new SimulationContext(true, new SimulationUser("admin-oid", "admin@test"), new SimulationUser(Person, "ana@test"), ReadOnly: true);
        host.Simulation.Setup(s => s.StartAsync(It.IsAny<System.Security.Claims.ClaimsPrincipal>(), " Ana@Test ", "/auth/simulation/start", It.IsAny<CancellationToken>()))
            .ReturnsAsync(Simulated(new SimulationStart(context, "X-Simulate-User", "ana@test", TimeSpan.FromSeconds(90), Resumed: false)));

        var response = await host.Client.SendAsync(host.AsAdmin(HttpMethod.Post, "/auth/simulation/start", JsonContent.Create(new { email = " Ana@Test " })));

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode, await response.Content.ReadAsStringAsync());
        var started = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.AreEqual("X-Simulate-User", started.GetProperty("headerName").GetString());
        Assert.AreEqual("ana@test", started.GetProperty("headerValue").GetString());
        Assert.AreEqual(2, started.GetProperty("idleTimeoutMinutes").GetInt32(), "rounded up to whole minutes");
        Assert.IsFalse(started.GetProperty("resumed").GetBoolean());
        Assert.AreEqual(Person, started.GetProperty("context").GetProperty("effectiveUser").GetProperty("objectId").GetString());
        Assert.AreEqual("admin@test", started.GetProperty("context").GetProperty("realUser").GetProperty("email").GetString());
        Assert.IsTrue(started.GetProperty("context").GetProperty("readOnly").GetBoolean());
    }

    [TestMethod]
    public async Task Nobody_to_simulate_is_404_and_a_refusal_is_422()
    {
        await using var host = await TestHost.StartAsync();
        host.Simulation.Setup(s => s.StartAsync(It.IsAny<System.Security.Claims.ClaimsPrincipal>(), "nobody@test", It.IsAny<string?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new SimulationResult<SimulationStart> { NotFound = "An active user with the e-mail nobody@test was not found." });
        var refused = new SimulationResult<SimulationStart>();
        refused.Validation.Errors.Add("You cannot simulate a user who holds permissions you do not hold.");
        host.Simulation.Setup(s => s.StartAsync(It.IsAny<System.Security.Claims.ClaimsPrincipal>(), "boss@test", It.IsAny<string?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(refused);

        var missing = await host.Client.SendAsync(host.AsAdmin(HttpMethod.Post, "/auth/simulation/start", JsonContent.Create(new { email = "nobody@test" })));
        var more = await host.Client.SendAsync(host.AsAdmin(HttpMethod.Post, "/auth/simulation/start", JsonContent.Create(new { email = "boss@test" })));

        Assert.AreEqual(HttpStatusCode.NotFound, missing.StatusCode);
        StringAssert.Contains(await missing.Content.ReadAsStringAsync(), "An active user with the e-mail nobody@test was not found.");
        Assert.AreEqual(HttpStatusCode.UnprocessableEntity, more.StatusCode);
        StringAssert.Contains(await more.Content.ReadAsStringAsync(), "You cannot simulate a user who holds permissions you do not hold.");
    }

    [TestMethod]
    public async Task Ending_is_204()
    {
        await using var host = await TestHost.StartAsync();
        host.Simulation.Setup(s => s.EndAsync(It.IsAny<System.Security.Claims.ClaimsPrincipal>(), "ana@test", It.IsAny<CancellationToken>()))
            .ReturnsAsync(Simulated(true));

        var response = await host.Client.SendAsync(host.AsAdmin(HttpMethod.Post, "/auth/simulation/end", JsonContent.Create(new { email = "ana@test" })));

        Assert.AreEqual(HttpStatusCode.NoContent, response.StatusCode);
    }

    [TestMethod]
    public async Task The_candidates_come_back_in_the_contract_shape()
    {
        await using var host = await TestHost.StartAsync();
        host.Simulation.Setup(s => s.ListCandidatesAsync(It.IsAny<System.Security.Claims.ClaimsPrincipal>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Simulated<IReadOnlyList<SimulationCandidate>>([new SimulationCandidate(Person, "ana@test", "Ana", CanSimulate: false, "Holds no access.")]));

        var candidate = (await (await host.Client.SendAsync(host.AsAdmin(HttpMethod.Get, "/auth/simulation/candidates")))
            .Content.ReadFromJsonAsync<JsonElement>())[0];

        Assert.AreEqual(Person, candidate.GetProperty("objectId").GetString());
        Assert.AreEqual("ana@test", candidate.GetProperty("email").GetString());
        Assert.AreEqual("Ana", candidate.GetProperty("name").GetString());
        Assert.IsFalse(candidate.GetProperty("canSimulate").GetBoolean());
        Assert.AreEqual("Holds no access.", candidate.GetProperty("reason").GetString());
    }

    [TestMethod]
    public async Task Without_the_simulation_door_the_answer_is_403_and_the_service_is_not_called()
    {
        await using var host = await TestHost.StartAsync();

        var response = await host.Client.SendAsync(host.AsUser(HttpMethod.Post, "/auth/simulation/start"));

        Assert.AreEqual(HttpStatusCode.Forbidden, response.StatusCode);
        host.Simulation.VerifyNoOtherCalls();
    }

    /// <summary>Without the e-mail in the body there is nothing to read: 400, before the service.</summary>
    [TestMethod]
    [DataRow("{}")]
    [DataRow("")]
    public async Task A_body_without_the_e_mail_is_400(string body)
    {
        await using var host = await TestHost.StartAsync();

        var response = await host.Client.SendAsync(host.AsAdmin(HttpMethod.Post, "/auth/simulation/start",
            new StringContent(body, System.Text.Encoding.UTF8, "application/json")));

        Assert.AreEqual(HttpStatusCode.BadRequest, response.StatusCode);
        host.Simulation.VerifyNoOtherCalls();
    }

    // ── Plumbing ─────────────────────────────────────────────────────────────

    private static SimulationResult<T> Simulated<T>(T data)
    {
        var result = new SimulationResult<T> { Data = data };
        result.Validation.IsValid = true;
        return result;
    }

    private static ValidationResult<T> Ok<T>(T data)
    {
        var result = new ValidationResult<T> { Data = data };
        result.Validation.IsValid = true;
        return result;
    }

    private static ValidationResult<T> Refused<T>(string field, string message)
    {
        var result = new ValidationResult<T>();
        result.Validation.AddFieldError(field, message);
        return result;
    }

    /// <summary>A host's own envelope: { isValid, data, error }.</summary>
    private sealed class EnvelopeWriter : IKdyfAuthorizationResultWriter
    {
        public IResult Ok(HttpContext http, object? data) => Results.Json(new { isValid = true, data, error = (object?)null });

        public IResult NoContent(HttpContext http) => Results.NoContent();

        public IResult Rejected(HttpContext http, AuthorizationRejection rejection) =>
            Results.Json(new { isValid = false, data = (object?)null, error = new { message = (string?)null, fields = rejection.Fields } }, statusCode: 422);

        public IResult NotFound(HttpContext http, string message) =>
            Results.Json(new { isValid = false, data = (object?)null, error = new { message } }, statusCode: 404);

        public IResult Failure(HttpContext http, Exception exception) =>
            Results.Json(new { isValid = false, data = (object?)null, error = new { message = "failed" } }, statusCode: 500);
    }
}
