using kdyf.Authorization.Abstractions;
using kdyf.Authorization.Migrations.Legacy;
using kdyf.Authorization.Migrations.Schema;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace kdyf.Authorization.Migrations.Test;

/// <summary>
/// Who each legacy user is in Entra, decided exactly or left for a person: never guessed. And what both gates said,
/// in the same pass.
/// </summary>
[TestClass]
public sealed class IdentityResolutionTests
{
    private const string Admin = "0f1e2d3c-0000-0000-0000-000000000001";
    private const string Reader = "0f1e2d3c-0000-0000-0000-000000000002";
    private const string Guest = "0f1e2d3c-0000-0000-0000-000000000003";
    private const string Twin1 = "0f1e2d3c-0000-0000-0000-0000000000a1";
    private const string Twin2 = "0f1e2d3c-0000-0000-0000-0000000000a2";
    private const string Service = "0f1e2d3c-0000-0000-0000-000000000005";

    private static FakeDirectory Directory() => new FakeDirectory()
        .Add(Admin, "admin@test", inLegacyGroup: true, inNewGate: true)
        .Add(Reader, "reader@test", inLegacyGroup: true, inNewGate: false)
        .Add(Guest, "guest_outside.test#EXT#@test", mail: "guest@outside.test", userType: "Guest", inLegacyGroup: true, inNewGate: true)
        .Add(Twin1, "twin1@test", mail: "twin@test")
        .Add(Twin2, "twin2@test", mail: "twin@test")
        .Add(Service, "service@test", enabled: false, inNewGate: true);

    private static LegacyImportOptions Options(LegacyGate gate = LegacyGate.Group) => new() { Gate = gate, LegacyGroupId = Guid.NewGuid().ToString() };

    private static ResolvedIdentity One(IReadOnlyList<ResolvedIdentity> identities, int id) => identities.Single(i => i.LegacyUserId == id);

    [TestMethod]
    public async Task Each_legacy_user_is_resolved_exactly_or_left_to_decide()
    {
        var directory = Directory();
        var identities = await new IdentityResolver(directory, directory, Options()).ResolveAsync(new[]
        {
            new LegacyUser(1, "Admin@Test", Admin.ToUpperInvariant(), null, true),   // object id given, in upper case
            new LegacyUser(2, "reader@test", null, null, true),                       // found by UPN
            new LegacyUser(3, "guest@outside.test", null, null, true),                // found by mail: a guest
            new LegacyUser(4, "twin@test", null, null, true),                         // two people have this mail
            new LegacyUser(5, "service@test", null, null, true),                      // a disabled account
            new LegacyUser(6, "gone@test", null, null, true),                         // nobody
            new LegacyUser(7, "moved@test", "0f1e2d3c-0000-0000-0000-0000000000ff", null, true), // its object id no longer exists
        });

        Assert.AreEqual((IdentityStatus.Ok, "existing", Admin), (One(identities, 1).Status, One(identities, 1).Method, One(identities, 1).ObjectId));
        Assert.AreEqual((IdentityStatus.Ok, "upn", Reader), (One(identities, 2).Status, One(identities, 2).Method, One(identities, 2).ObjectId));
        Assert.AreEqual((IdentityStatus.Guest, "mail"), (One(identities, 3).Status, One(identities, 3).Method));
        Assert.AreEqual((IdentityStatus.Ambiguous, 2), (One(identities, 4).Status, One(identities, 4).Matches));
        Assert.IsNull(One(identities, 4).ObjectId, "never one of the two at random");
        Assert.AreEqual(IdentityStatus.Disabled, One(identities, 5).Status);
        Assert.AreEqual(IdentityStatus.NotFound, One(identities, 6).Status);
        Assert.AreEqual(IdentityStatus.NotFound, One(identities, 7).Status, "an object id that does not exist is not replaced by a search");

        CollectionAssert.AreEqual(new[] { 1, 2 }, identities.Where(i => i.Importable).Select(i => i.LegacyUserId).ToArray());
    }

    /// <summary>The search is exact: an address among a person's other addresses names nobody.</summary>
    [TestMethod]
    public async Task Only_upn_and_mail_are_searched()
    {
        var directory = new FakeDirectory().Add(Admin, "admin@test", otherMail: "old@test");

        var identity = (await new IdentityResolver(directory, directory, Options()).ResolveAsync(new[] { new LegacyUser(1, "old@test", null, null, true) })).Single();

        Assert.AreEqual(IdentityStatus.NotFound, identity.Status);
    }

    [TestMethod]
    public async Task Both_gates_are_read_in_the_same_pass()
    {
        var directory = Directory();
        var identities = await new IdentityResolver(directory, directory, Options()).ResolveAsync(new[]
        {
            new LegacyUser(1, "admin@test", Admin, null, true),
            new LegacyUser(2, "reader@test", Reader, null, true),
            new LegacyUser(3, "nobody@test", null, null, true),
            new LegacyUser(4, "off@test", Admin, null, false),
        });

        Assert.AreEqual((true, (bool?)true), (One(identities, 1).PassedLegacyGate, One(identities, 1).PassesNewGate));
        Assert.AreEqual((true, (bool?)false), (One(identities, 2).PassedLegacyGate, One(identities, 2).PassesNewGate), "loses access with the new gate");
        Assert.IsTrue(One(identities, 3).PassedLegacyGate, "WIMBA let users without an object id through");
        Assert.IsNull(One(identities, 3).PassesNewGate, "unresolved: the new gate cannot be asked");
        Assert.IsFalse(One(identities, 4).PassedLegacyGate, "an inactive user passed nothing");
    }

    [TestMethod]
    public async Task With_active_users_as_the_gate_every_active_user_passed()
    {
        var directory = Directory();
        var identities = await new IdentityResolver(directory, directory, new LegacyImportOptions { Gate = LegacyGate.ActiveUsers })
            .ResolveAsync(new[] { new LegacyUser(1, "outsider@test", Reader, null, true), new LegacyUser(2, "x@test", null, null, false) });

        Assert.IsTrue(One(identities, 1).PassedLegacyGate);
        Assert.IsFalse(One(identities, 2).PassedLegacyGate);
    }

    /// <summary>Incremental: an unchanged row keeps its resolution and its approval; a changed one is resolved again and loses it.</summary>
    [TestMethod]
    public async Task Incremental_keeps_the_unchanged_and_resolves_the_changed()
    {
        var directory = Directory();
        var resolver = new IdentityResolver(directory, directory, Options());
        var first = await resolver.ResolveAsync(new[] { new LegacyUser(3, "guest@outside.test", null, null, true), new LegacyUser(5, "service@test", null, null, true) });
        var approved = first.Select(i => i with { ApprovedBy = "carlos", ApprovedAt = DateTime.UtcNow }).ToDictionary(i => i.LegacyUserId);
        var calls = directory.Calls;

        var second = await resolver.ResolveAsync(new[] { new LegacyUser(3, "guest@outside.test", null, null, true), new LegacyUser(5, "service@test", null, null, false) }, approved);

        Assert.IsTrue(One(second, 3).Approved);
        Assert.AreSame(approved[3], One(second, 3), "kept as it was");
        Assert.IsFalse(One(second, 5).Approved, "changed (deactivated): resolved again, the approval is gone");
        Assert.IsTrue(directory.Calls > calls);
    }

    [TestMethod]
    public void The_import_refuses_identities_that_are_stale_or_no_longer_describe_the_users()
    {
        var now = new DateTime(2026, 10, 16, 12, 0, 0, DateTimeKind.Utc);
        var users = new[] { new LegacyUser(1, "a@test", Admin, null, true), new LegacyUser(2, "b@test", null, null, true) };
        ResolvedIdentity Resolved(LegacyUser u, DateTime at) => new(u.UserId, u.Email, u.ObjectId, null, "x", 0, null, null, IdentityStatus.NotFound,
            IdentityResolver.RowVersion(u), true, null, at);

        var fresh = users.Select(u => Resolved(u, now.AddHours(-1))).ToList();
        Assert.AreEqual(0, IdentityFreshness.Problems(users, fresh, now, TimeSpan.FromHours(12)).Count);

        var old = users.Select(u => Resolved(u, now.AddHours(-13))).ToList();
        StringAssert.Contains(IdentityFreshness.Problems(users, old, now, TimeSpan.FromHours(12)).Single(), "13 h ago");

        var changed = new[] { users[0] with { IsActive = false }, users[1], new LegacyUser(3, "new@test", null, null, true) };
        var problems = IdentityFreshness.Problems(changed, fresh, now, TimeSpan.FromHours(12));
        Assert.IsTrue(problems.Any(p => p.Contains("added") && p.Contains('3')));
        Assert.IsTrue(problems.Any(p => p.Contains("changed") && p.Contains('1')));

        StringAssert.Contains(IdentityFreshness.Problems(users, Array.Empty<ResolvedIdentity>(), now, TimeSpan.FromHours(12)).Single(), "kdyf-auth resolve");
    }

    // ── The review ───────────────────────────────────────────────────────────

    [TestMethod]
    public async Task A_review_approves_a_guest_and_gives_an_ambiguous_user_an_object_id()
    {
        var directory = Directory();
        var identities = await new IdentityResolver(directory, directory, Options())
            .ResolveAsync(new[] { new LegacyUser(3, "guest@outside.test", null, null, true), new LegacyUser(4, "twin@test", null, null, true) });

        var csv = IdentityReview.ToCsv(identities)
            .Replace($"3,guest@outside.test,", "3,guest@outside.test,")
            .Split('\n').Select(line => line.StartsWith("3,") ? line.TrimEnd('\r').TrimEnd(',') + ",yes," : line.StartsWith("4,") ? $"4,,,{Twin2},,,,,,,,,yes," : line);
        var decisions = IdentityReview.ReadDecisions(string.Join("\n", csv));

        var (updated, problems) = await IdentityReview.ApplyAsync(identities, decisions, "carlos", directory, directory, DateTime.UtcNow);

        Assert.AreEqual(0, problems.Count, string.Join(" ", problems));
        Assert.IsTrue(One(updated, 3).Importable);
        Assert.AreEqual((IdentityStatus.Manual, Twin2, "carlos"), (One(updated, 4).Status, One(updated, 4).ObjectId, One(updated, 4).ApprovedBy));
    }

    [TestMethod]
    public async Task A_review_cannot_approve_what_it_does_not_name()
    {
        var directory = Directory();
        var identities = await new IdentityResolver(directory, directory, Options()).ResolveAsync(new[] { new LegacyUser(4, "twin@test", null, null, true) });

        var (_, problems) = await IdentityReview.ApplyAsync(identities, new[]
        {
            new ReviewDecision(4, null, true),                                   // ambiguous: needs an object id
            new ReviewDecision(4, "0f1e2d3c-0000-0000-0000-0000000000ee", true), // nobody has it
            new ReviewDecision(99, null, true),                                  // not a resolved user
        }, "carlos", directory, directory, DateTime.UtcNow);

        Assert.AreEqual(3, problems.Count);
    }

    [TestMethod]
    public void The_review_file_survives_commas_quotes_and_spreadsheets()
    {
        var identity = new ResolvedIdentity(1, "=cmd|' /C calc'!A0", "a,b", null, "email", 0, null, null, IdentityStatus.NotFound, "v", true, null, DateTime.UtcNow);

        var csv = IdentityReview.ToCsv(new[] { identity });

        StringAssert.Contains(csv, "'=cmd", "a formula stays text");
        StringAssert.Contains(csv, "\"a,b\"");
        Assert.AreEqual(1, IdentityReview.ReadDecisions(csv).Single().LegacyUserId);
    }

    // ── End to end, on SQL Server ────────────────────────────────────────────

    [TestMethod]
    public async Task Resolve_export_and_import_through_the_command_line()
    {
        await using var db = await TestDatabase.CreateAsync();
        await db.ExecuteAsync(LegacyFixtures.ShapeC);
        await db.ExecuteAsync(LegacyFixtures.Data);
        var directory = new FakeDirectory()
            .Add("0f1e2d3c-0000-0000-0000-000000000001", "admin@test", inLegacyGroup: true, inNewGate: true)
            .Add("0f1e2d3c-0000-0000-0000-000000000002", "reader@test", inLegacyGroup: true, inNewGate: true)
            .Add("0f1e2d3c-0000-0000-0000-000000000004", "nothing@test", inLegacyGroup: true, inNewGate: true)
            .Add(Service, "service@test", enabled: false);
        var services = new ServiceCollection()
            .AddSingleton<ILegacyDirectory>(directory)
            .AddSingleton<IMembershipSource>(directory)
            .AddKdyfAuthorizationLegacyImport(o => o.LegacyGroupId = Guid.NewGuid().ToString())
            .AddSingleton<ILegacyDirectory>(directory)
            .BuildServiceProvider();
        var file = Path.Combine(Path.GetTempPath(), $"identities-{Guid.NewGuid():N}.csv");
        try
        {
            var output = new StringWriter();
            var resolve = await SchemaCommandLine.RunAsync(new[] { "resolve" }, db.ConnectionString, "authz", output, services);
            Assert.AreEqual(SchemaCommandLine.NotDone, resolve, "user 3 is a disabled account: to decide\n" + output);
            Assert.IsFalse(output.ToString().Contains("@test"), "no e-mails on screen");
            Assert.AreEqual(4, await db.ScalarAsync<int>("SELECT COUNT(*) FROM authz.MigrationIdentity"));

            Assert.AreEqual(SchemaCommandLine.Ok, await SchemaCommandLine.RunAsync(new[] { "identities", "export", file }, db.ConnectionString, "authz", output, services));
            var reviewed = File.ReadAllLines(file).Select(line => line.StartsWith("3,") ? line[..line.LastIndexOf(',')].TrimEnd(',') + ",yes," : line);
            await File.WriteAllLinesAsync(file, reviewed);
            var import = await SchemaCommandLine.RunAsync(new[] { "identities", "import", file, "--approver", "carlos" }, db.ConnectionString, "authz", output, services);

            Assert.AreEqual(SchemaCommandLine.Ok, import, output.ToString());
            Assert.AreEqual("carlos", await db.ScalarAsync<string>("SELECT ApprovedBy FROM authz.MigrationIdentity WHERE LegacyUserId = 3"));
            Assert.AreEqual(1, await db.ScalarAsync<int>("SELECT COUNT(*) FROM authz.MigrationGateSnapshot WHERE LegacyUserId = 2 AND PassedLegacyGate = 0"), "user 2 is inactive");
        }
        finally
        {
            File.Delete(file);
        }
    }

    [TestMethod]
    public async Task Resolve_without_the_host_says_where_it_runs()
    {
        var output = new StringWriter();

        var code = await SchemaCommandLine.RunAsync(new[] { "resolve" }, "Server=unused", "authz", output);

        Assert.AreEqual(SchemaCommandLine.Usage, code);
        StringAssert.Contains(output.ToString(), "<host> kdyf-auth resolve");
    }

    /// <summary>An in-memory Entra: people, the legacy group, the new gate. Counts the calls.</summary>
    private sealed class FakeDirectory : ILegacyDirectory, IMembershipSource
    {
        private readonly List<(DirectoryPerson Person, string? OtherMail, bool LegacyGroup, bool NewGate)> _people = new();

        public int Calls { get; private set; }

        public FakeDirectory Add(string objectId, string upn, string? mail = null, string userType = "Member", bool enabled = true,
            bool inLegacyGroup = false, bool inNewGate = false, string? otherMail = null)
        {
            _people.Add((new DirectoryPerson(objectId, upn, mail ?? upn, userType, enabled), otherMail, inLegacyGroup, inNewGate));
            return this;
        }

        public Task<DirectoryPerson?> GetAsync(string objectId, CancellationToken cancellationToken = default)
        {
            Calls++;
            return Task.FromResult(_people.Select(p => p.Person).FirstOrDefault(p => string.Equals(p.ObjectId, objectId, StringComparison.OrdinalIgnoreCase)));
        }

        public Task<IReadOnlyList<DirectoryPerson>> FindExactAsync(string email, CancellationToken cancellationToken = default)
        {
            Calls++;
            IReadOnlyList<DirectoryPerson> found = _people.Select(p => p.Person)
                .Where(p => string.Equals(p.UserPrincipalName, email, StringComparison.OrdinalIgnoreCase) || string.Equals(p.Mail, email, StringComparison.OrdinalIgnoreCase))
                .ToList();
            return Task.FromResult(found);
        }

        public Task<bool> InLegacyGroupAsync(string objectId, CancellationToken cancellationToken = default) =>
            Task.FromResult(_people.Any(p => p.LegacyGroup && string.Equals(p.Person.ObjectId, objectId, StringComparison.OrdinalIgnoreCase)));

        public Task<Membership?> GetMembershipAsync(string subjectId, CancellationToken cancellationToken = default)
        {
            var person = _people.FirstOrDefault(p => string.Equals(p.Person.ObjectId, subjectId, StringComparison.OrdinalIgnoreCase));
            return Task.FromResult(person.Person is null ? null : new Membership(person.Person.AccountEnabled, person.NewGate));
        }

        public Task<DirectoryIdentity?> FindByEmailAsync(string email, CancellationToken cancellationToken = default) => Task.FromResult<DirectoryIdentity?>(null);
    }
}
