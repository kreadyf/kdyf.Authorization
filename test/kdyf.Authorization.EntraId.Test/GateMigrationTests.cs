using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using kdyf.Authorization.Administration.Abstractions;
using kdyf.Authorization.Administration.EntraId;
using kdyf.Authorization.EntraId.Migration;

namespace kdyf.Authorization.EntraId.Test;

/// <summary>
/// The migration from the access group to the assignments, against Graph: a pass makes the assignments equal to the
/// group — adds and removals, audited as system:migration — and a second pass changes nothing; while it lasts the
/// administration writes to both.
/// </summary>
[TestClass]
public sealed class GateMigrationTests
{
    private const string Ana = "0a000000-0000-0000-0000-00000000000a";
    private const string Ben = "0b000000-0000-0000-0000-00000000000b";
    private const string Cleo = "0c000000-0000-0000-0000-00000000000c";

    // ── The sync ─────────────────────────────────────────────────────────────

    [TestMethod]
    public async Task A_pass_makes_the_assignments_equal_to_the_group_and_audits_each_change()
    {
        var graph = new FakeGraph()
            .Person(Ana, member: true)
            .Person(Ben, member: true).Assign(Ben)
            .Person(Cleo).Assign(Cleo)
            .Assign(Cleo, role: FakeGraph.OtherRole);
        var audit = new Audit();
        using var services = graph.Services(AccessGate.Migrating, s => s.AddScoped<GraphAccessGroupDirectory>());

        var result = await Migration(services, audit).RunAsync(default);

        Assert.AreEqual(new GateMigrationResult(Assigned: 1, Unassigned: 1, Failed: 0), result);
        Assert.IsTrue(graph.IsAssigned(Ana), "in the group: assigned");
        Assert.IsTrue(graph.IsAssigned(Ben), "already assigned: left alone");
        Assert.IsFalse(graph.IsAssigned(Cleo), "taken out of the group: unassigned");
        Assert.IsTrue(graph.Assignments.Any(a => a.Principal == Cleo && a.Role == FakeGraph.OtherRole), "only the access role is touched");

        CollectionAssert.AreEquivalent(
            new[] { ("access.migration.assigned", Ana), ("access.migration.unassigned", Cleo) },
            audit.Entries.Select(e => (e.Entry.Action, e.Entry.TargetId!)).ToArray());
        Assert.IsTrue(audit.Entries.All(e => e.Actor.Email == "system:migration" && e.Actor.ObjectId is null));
        Assert.AreEqual(1, audit.Saves);
    }

    [TestMethod]
    public async Task A_second_pass_changes_nothing()
    {
        var graph = new FakeGraph().Person(Ana, member: true).Person(Cleo).Assign(Cleo);
        var audit = new Audit();
        using var services = graph.Services(AccessGate.Migrating, s => s.AddScoped<GraphAccessGroupDirectory>());

        await Migration(services, audit).RunAsync(default);
        var writes = graph.Requests.Count(r => !r.StartsWith("GET", StringComparison.Ordinal));
        var second = await Migration(services, audit).RunAsync(default);

        Assert.AreEqual(new GateMigrationResult(0, 0, 0), second);
        Assert.AreEqual(writes, graph.Requests.Count(r => !r.StartsWith("GET", StringComparison.Ordinal)), "no write the second time");
        Assert.AreEqual(1, audit.Saves);
    }

    /// <summary>An empty group is far likelier the wrong group id than everybody leaving: nobody is unassigned.</summary>
    [TestMethod]
    public async Task An_empty_group_never_empties_the_assignments()
    {
        var graph = new FakeGraph().Person(Ana).Assign(Ana).Person(Ben).Assign(Ben);
        var log = new ListLogger<GateMigrationTests>();
        using var services = graph.Services(AccessGate.Migrating, s => s.AddScoped<GraphAccessGroupDirectory>());

        var result = await Migration(services, new Audit(), log).RunAsync(default);

        Assert.AreEqual(new GateMigrationResult(0, 0, 0), result);
        Assert.IsTrue(graph.IsAssigned(Ana) && graph.IsAssigned(Ben));
        Assert.IsTrue(log.Lines.Any(l => l.Level == LogLevel.Warning && l.Message.Contains("GroupId")));
    }

    [TestMethod]
    public async Task A_refused_change_is_counted_and_left_for_the_next_pass()
    {
        var graph = new FakeGraph().Person(Ana, member: true);
        using var services = graph.Services(AccessGate.Migrating, s => s.AddScoped<GraphAccessGroupDirectory>());
        var audit = new Audit();
        var migration = Migration(services, audit);

        graph.AssignmentsDown = true;
        await Assert.ThrowsExceptionAsync<GraphException>(() => migration.RunAsync(default), "the assignments cannot even be listed");

        graph.AssignmentsDown = false;
        Assert.AreEqual(new GateMigrationResult(1, 0, 0), await migration.RunAsync(default));
    }

    // ── The administration while migrating ───────────────────────────────────

    [TestMethod]
    public async Task While_migrating_a_grant_and_a_revocation_reach_the_group_and_the_assignments()
    {
        var graph = new FakeGraph().Person(Ana);
        using var services = DualWrite(graph);
        using var scope = services.CreateScope();
        var directory = scope.ServiceProvider.GetRequiredService<IAccessDirectory>();

        Assert.IsInstanceOfType<DualWriteAccessDirectory>(directory);

        await directory.GrantAsync(Ana);
        Assert.IsTrue(graph.Requests.Any(r => r.StartsWith($"POST groups/{FakeGraph.Group}/members/$ref", StringComparison.Ordinal)), "the group");
        Assert.IsTrue(graph.IsAssigned(Ana), "and the assignment");

        await directory.RevokeAsync(Ana);
        Assert.IsTrue(graph.Requests.Any(r => r.StartsWith($"DELETE groups/{FakeGraph.Group}/members/{Ana}/$ref", StringComparison.Ordinal)));
        Assert.IsFalse(graph.IsAssigned(Ana));
    }

    /// <summary>The group decides: its change stands when the assignment's fails, and the sync puts the second right.</summary>
    [TestMethod]
    public async Task While_migrating_a_failed_assignment_does_not_fail_the_grant()
    {
        var graph = new FakeGraph().Person(Ana);
        graph.AssignmentsDown = true;
        using var services = DualWrite(graph);
        using var scope = services.CreateScope();

        await scope.ServiceProvider.GetRequiredService<IAccessDirectory>().GrantAsync(Ana);

        Assert.IsTrue(graph.Requests.Any(r => r.StartsWith("POST groups/", StringComparison.Ordinal)));
        Assert.IsFalse(graph.IsAssigned(Ana));
    }

    /// <summary>What the administration reads while migrating is the group: it still decides.</summary>
    [TestMethod]
    public async Task While_migrating_the_administration_reads_the_group()
    {
        var graph = new FakeGraph().Person(Ana, member: true).Person(Ben).Assign(Ben);
        using var services = DualWrite(graph);
        using var scope = services.CreateScope();
        var directory = scope.ServiceProvider.GetRequiredService<IAccessDirectory>();

        CollectionAssert.AreEqual(new[] { Ana }, (await directory.ListWithAccessAsync()).Select(a => a.User.ObjectId).ToArray());
        Assert.IsFalse(await directory.HasAccessAsync(Ben));
    }

    // ── Plumbing ─────────────────────────────────────────────────────────────

    private static GateMigration Migration(ServiceProvider services, Audit audit, ILogger? logger = null)
    {
        var scope = services.CreateScope().ServiceProvider;
        return new GateMigration(
            scope.GetRequiredService<GraphAccessGroupDirectory>(),
            scope.GetRequiredService<IAccessAssignments>(),
            audit,
            _ => { audit.Saves++; return Task.CompletedTask; },
            logger ?? NullLogger.Instance);
    }

    /// <summary>The administration's directory as a migrating host composes it, without the database.</summary>
    private static ServiceProvider DualWrite(FakeGraph graph) =>
        graph.Services(AccessGate.Migrating, services =>
        {
            services.AddAzureAdAccessAdministration();
            services.AddScoped<IMigratingAccessDirectory>(provider => new DualWriteAccessDirectory(
                provider.GetRequiredService<GraphAccessGroupDirectory>(),
                provider.GetRequiredService<GraphAccessAssignmentDirectory>(),
                NullLogger<DualWriteAccessDirectory>.Instance));
        });

    private sealed class Audit : IAuditLog
    {
        public List<(AuditActor Actor, AuditEntry Entry)> Entries { get; } = [];

        public int Saves { get; set; }

        public void Record(AuditActor actor, AuditEntry entry) => Entries.Add((actor, entry));
    }
}
