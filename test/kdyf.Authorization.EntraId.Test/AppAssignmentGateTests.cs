using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using kdyf.Authorization.Abstractions;
using kdyf.Authorization.Administration.Abstractions;
using kdyf.Authorization.Administration.EntraId;
using kdyf.Authorization.EntraId;

namespace kdyf.Authorization.EntraId.Test;

/// <summary>
/// The gate by assignment to the Enterprise application, against Graph: who counts as assigned (only the Access role of
/// THIS application, only users), the account state, idempotent writes — and, while migrating, the group deciding with
/// every difference logged.
/// </summary>
[TestClass]
public sealed class AppAssignmentGateTests
{
    private const string Ana = "0a000000-0000-0000-0000-00000000000a";
    private const string Ben = "0b000000-0000-0000-0000-00000000000b";
    private const string Cleo = "0c000000-0000-0000-0000-00000000000c";

    // ── Who is assigned ──────────────────────────────────────────────────────

    [TestMethod]
    public async Task Only_the_access_role_of_this_application_gives_access()
    {
        var graph = new FakeGraph()
            .Person(Ana).Assign(Ana)
            .Person(Ben).Assign(Ben, role: FakeGraph.OtherRole)
            .Person(Cleo).Assign(Cleo, resource: FakeGraph.OtherApplication);
        using var services = graph.Services(AccessGate.AppAssignment);
        var gate = Source(services);

        Assert.AreEqual(new Membership(true, true), await gate.GetMembershipAsync(Ana));
        Assert.AreEqual(new Membership(true, false), await gate.GetMembershipAsync(Ben), "another role of the same application");
        Assert.AreEqual(new Membership(true, false), await gate.GetMembershipAsync(Cleo), "the same role id on another application");
    }

    /// <summary>The assignment survives a disabled account: the gate reads the account too.</summary>
    [TestMethod]
    public async Task A_disabled_account_with_an_assignment_holds_nothing()
    {
        var graph = new FakeGraph().Person(Ana, enabled: false).Assign(Ana);
        using var services = graph.Services(AccessGate.AppAssignment);

        Assert.AreEqual(new Membership(AccountEnabled: false, IsMember: true), await Source(services).GetMembershipAsync(Ana));
    }

    [TestMethod]
    public async Task Somebody_unknown_or_not_an_object_id_is_null_and_never_reaches_a_url()
    {
        var graph = new FakeGraph();
        using var services = graph.Services(AccessGate.AppAssignment);
        var gate = Source(services);

        Assert.IsNull(await gate.GetMembershipAsync(Ana));
        Assert.IsNull(await gate.GetMembershipAsync("ana@test/../../servicePrincipals"));
        Assert.IsFalse(graph.Requests.Any(r => r.Contains("ana@test")));
    }

    /// <summary>A Graph failure denies — it is never read as "not assigned" and cached as such.</summary>
    [TestMethod]
    public async Task A_graph_failure_throws()
    {
        var graph = new FakeGraph().Person(Ana).Assign(Ana);
        graph.AssignmentsDown = true;
        using var services = graph.Services(AccessGate.AppAssignment);

        await Assert.ThrowsExceptionAsync<GraphException>(() => Source(services).GetMembershipAsync(Ana));
    }

    /// <summary>The application and the role are configuration: every call names them, none takes them from outside.</summary>
    [TestMethod]
    public async Task Every_write_names_the_configured_application_and_role()
    {
        var graph = new FakeGraph().Person(Ana).Person(Ben).Assign(Ben);
        using var services = graph.Services(AccessGate.AppAssignment);
        var assignments = services.GetRequiredService<IAccessAssignments>();

        await assignments.AssignAsync(Ana, default);
        await assignments.UnassignAsync(Ben, default);

        var written = graph.Assignments.Single(a => a.Principal == Ana);
        Assert.AreEqual(FakeGraph.ServicePrincipal, written.Resource);
        Assert.AreEqual(FakeGraph.AccessRole, written.Role);
        Assert.IsTrue(graph.Requests.Where(r => !r.StartsWith("GET users/", StringComparison.Ordinal))
            .All(r => r.Contains($"servicePrincipals/{FakeGraph.ServicePrincipal}/")), string.Join("\n", graph.Requests));
    }

    // ── The administration's directory ───────────────────────────────────────

    [TestMethod]
    public async Task Granting_and_revoking_are_idempotent_and_touch_only_the_access_role()
    {
        var graph = new FakeGraph().Person(Ana).Assign(Ana, role: FakeGraph.OtherRole);
        using var services = graph.Services(AccessGate.AppAssignment, s => s.AddScoped<GraphAccessAssignmentDirectory>());
        using var scope = services.CreateScope();
        var directory = scope.ServiceProvider.GetRequiredService<GraphAccessAssignmentDirectory>();

        await directory.GrantAsync(Ana);
        await directory.GrantAsync(Ana);
        Assert.AreEqual(1, graph.Assignments.Count(a => a.Principal == Ana && a.Role == FakeGraph.AccessRole), "assigned once");
        Assert.IsTrue(await directory.HasAccessAsync(Ana));

        await directory.RevokeAsync(Ana);
        await directory.RevokeAsync(Ana);
        Assert.IsFalse(graph.IsAssigned(Ana));
        Assert.IsTrue(graph.Assignments.Any(a => a.Principal == Ana && a.Role == FakeGraph.OtherRole), "the other role stays");
    }

    [TestMethod]
    public async Task Listing_is_the_assigned_users_only()
    {
        var graph = new FakeGraph()
            .Person(Ana, enabled: false).Assign(Ana)
            .Person(Ben).Assign(Ben, role: FakeGraph.OtherRole)
            .Assign(Cleo, type: "Group");
        using var services = graph.Services(AccessGate.AppAssignment);

        var assigned = await services.GetRequiredService<IAccessAssignments>().ListAsync(default);

        CollectionAssert.AreEqual(new[] { Ana }, assigned.Select(a => a.PrincipalId).ToArray());
    }

    // ── Migrating ────────────────────────────────────────────────────────────

    [TestMethod]
    public async Task While_migrating_the_group_decides_and_every_difference_is_logged()
    {
        var graph = new FakeGraph()
            .Person(Ana, member: true)
            .Person(Ben).Assign(Ben)
            .Person(Cleo, member: true).Assign(Cleo);
        var log = new ListLogger<MigratingMembershipSource>();
        using var services = graph.Services(AccessGate.Migrating, s => s.AddSingleton<ILogger<MigratingMembershipSource>>(log));
        var gate = Source(services);

        Assert.IsTrue((await gate.GetMembershipAsync(Ana))!.IsMember, "in the group, not assigned yet: the group lets her in");
        Assert.IsFalse((await gate.GetMembershipAsync(Ben))!.IsMember, "assigned, not in the group: the group keeps him out");
        Assert.IsTrue((await gate.GetMembershipAsync(Cleo))!.IsMember);

        var differences = log.Lines.Where(l => l.Level == LogLevel.Warning).Select(l => l.Message).ToList();
        Assert.AreEqual(2, differences.Count, string.Join("\n", differences));
        Assert.IsTrue(differences.Any(d => d.Contains(Ana) && d.Contains("not assigned")));
        Assert.IsTrue(differences.Any(d => d.Contains(Ben) && d.Contains("not in")));
    }

    [TestMethod]
    public async Task While_migrating_a_failure_reading_assignments_does_not_deny()
    {
        var graph = new FakeGraph().Person(Ana, member: true);
        graph.AssignmentsDown = true;
        using var services = graph.Services(AccessGate.Migrating);

        Assert.IsTrue((await Source(services).GetMembershipAsync(Ana))!.IsMember);
    }

    private static IMembershipSource Source(ServiceProvider services) =>
        services.CreateScope().ServiceProvider.GetRequiredService<IMembershipSource>();
}

/// <summary>Looking people up by e-mail, as Graph sees the URL: every character of the address arrives.</summary>
[TestClass]
public sealed class GraphEmailLookupTests
{
    /// <summary>
    /// A guest's UPN carries '#EXT#', and plus addressing a '+': unencoded, '#' ended the query (Graph saw a broken
    /// filter) and '+' arrived as a space. Found against a real tenant by the legacy import's resolution.
    /// </summary>
    [DataTestMethod]
    [DataRow("ana+orders@test.example")]
    [DataRow("guest_outside.test#EXT#@tenant.example")]
    [DataRow("o'brien@test.example")]
    public async Task An_address_with_reserved_characters_is_found(string email)
    {
        var graph = new FakeGraph().Person("0a000000-0000-0000-0000-00000000000a");
        graph.Emails["0a000000-0000-0000-0000-00000000000a"] = email;
        using var services = graph.Services();
        using var scope = services.CreateScope();

        var found = await scope.ServiceProvider.GetRequiredService<IMembershipSource>().FindByEmailAsync(email);

        Assert.AreEqual("0a000000-0000-0000-0000-00000000000a", found?.SubjectId, string.Join("\n", graph.Requests));
    }
}
