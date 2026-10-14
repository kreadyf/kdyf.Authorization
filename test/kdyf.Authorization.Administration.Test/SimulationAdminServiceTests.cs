using System.Security.Claims;
using Microsoft.Extensions.DependencyInjection;
using kdyf.Authorization.Abstractions;
using kdyf.Authorization.Administration;
using kdyf.Authorization.Administration.Abstractions;
using kdyf.Authorization.Administration.Models;
using kdyf.Authorization.Authorization;
using kdyf.Authorization.Simulation;

namespace kdyf.Authorization.Administration.Test;

/// <summary>
/// <see cref="SimulationAdminService"/> over the real simulation sessions and identity resolver, and fake permissions,
/// targets, directory and audit: a dedicated permission, read-only, real and simulated user apart, start and end recorded
/// with the real administrator, and a list of candidates that never promises what a start refuses.
/// </summary>
/// <remarks>The cases of the simulation module these operations came from, one by one.</remarks>
[TestClass]
public sealed class SimulationAdminServiceTests
{
    private const string SimulationPermission = "global.UserSimulation";

    private const string Admin = "0a000000-0000-0000-0000-000000000001";
    private const string AdminEmail = "admin@test";
    private const string Reader = "0a000000-0000-0000-0000-000000000002";
    private const string ReaderEmail = "reader@test";
    private const string Boss = "0a000000-0000-0000-0000-000000000003";
    private const string BossEmail = "boss@test";

    private readonly Permissions _permissions = new();
    private readonly Targets _targets = new();
    private readonly Directory _directory = new();
    private readonly Recorder _recorder = new();
    private readonly Group _group = new();
    private readonly UserSimulationOptions _options = new() { RequiredPermission = SimulationPermission, PolicyName = "UserSimulation" };
    private readonly PermissionAuthorizationOptions _identity = new();
    private ServiceProvider _services = null!;

    [TestInitialize]
    public void Start()
    {
        _permissions.Held[Admin] = ["Default", "portal.Read", SimulationPermission];
        _permissions.Held[Reader] = ["Default", "portal.Read"];
        _permissions.Held[Boss] = ["Default", "portal.Read", "portal.Admin"];

        _targets.People[ReaderEmail] = new SimulationTarget(ReaderEmail, Reader, "Reader");
        _targets.People[BossEmail] = new SimulationTarget(BossEmail, Boss, "Boss");

        _group.Add(Admin, AdminEmail, "Admin").Add(Reader, ReaderEmail, "Reader").Add(Boss, BossEmail, "Boss");

        var services = new ServiceCollection().AddLogging().AddMemoryCache();
        services.AddSingleton(_options);
        services.AddSingleton<IUserIdentityResolver>(new ClaimsUserIdentityResolver(_identity));
        services.AddSingleton<IPrincipalPermissionResolver>(_permissions);
        services.AddSingleton<IPermissionStore>(_permissions);
        services.AddSingleton<ISimulationTargetResolver>(_targets);
        services.AddSingleton<IMembershipSource>(_directory);
        services.AddSingleton<ISimulationRecorder>(_recorder);
        services.AddSingleton<IAccessDirectory>(_group);
        services.AddSingleton<SimulationSessions>();
        services.AddScoped<ISimulationAdminService, SimulationAdminService>();
        _services = services.BuildServiceProvider(new ServiceProviderOptions { ValidateOnBuild = true, ValidateScopes = true });
    }

    [TestCleanup]
    public void Stop() => _services.Dispose();

    // ── Start ─────────────────────────────────────────────────────────────────

    [TestMethod]
    public async Task Starting_records_the_real_administrator_and_the_simulated_user_apart()
    {
        var started = Accepted(await Service().StartAsync(Person(Admin, AdminEmail), ReaderEmail, "/auth/simulation/start", default));

        var (kind, session) = _recorder.Entries.Single();
        Assert.AreEqual("started", kind);
        Assert.AreEqual(Admin, session.RealSubjectId);
        Assert.AreEqual(AdminEmail, session.RealEmail);
        Assert.AreEqual(Reader, session.TargetSubjectId);
        Assert.AreEqual(ReaderEmail, session.TargetEmail);
        Assert.AreEqual("/auth/simulation/start", session.Path);

        Assert.IsTrue(started.Context.IsSimulating);
        Assert.IsTrue(started.Context.ReadOnly);
        Assert.AreEqual(Admin, started.Context.RealUser.ObjectId);
        Assert.AreEqual(Reader, started.Context.EffectiveUser.ObjectId);
        Assert.AreEqual("X-Simulate-User", started.HeaderName);
        Assert.AreEqual(ReaderEmail, started.HeaderValue);
        Assert.AreEqual(TimeSpan.FromMinutes(30), started.IdleTimeout);
        Assert.IsFalse(started.Resumed);
    }

    [TestMethod]
    public async Task The_e_mail_is_compared_trimmed_and_lower_case()
    {
        var started = Accepted(await Service().StartAsync(Person(Admin, AdminEmail), "  Reader@TEST ", null, default));

        Assert.AreEqual(ReaderEmail, started.HeaderValue);
    }

    [TestMethod]
    [DataRow(null, "This field is required.")]
    [DataRow("  ", "This field is required.")]
    [DataRow("reader", "This is not an e-mail address.")]
    public async Task A_malformed_e_mail_is_refused_on_its_field(string? email, string message)
    {
        var result = await Service().StartAsync(Person(Admin, AdminEmail), email, null, default);

        Assert.IsFalse(result.Validation.IsValid);
        CollectionAssert.AreEqual(new[] { message }, result.Validation.Fields["email"].Errors);
        Assert.AreEqual(0, _recorder.Entries.Count);
    }

    [TestMethod]
    public async Task Starting_again_resumes_the_simulation_without_a_second_record()
    {
        await Service().StartAsync(Person(Admin, AdminEmail), ReaderEmail, null, default);
        var again = Accepted(await Service().StartAsync(Person(Admin, AdminEmail), ReaderEmail, null, default));

        Assert.IsTrue(again.Resumed);
        Assert.AreEqual(1, _recorder.Entries.Count);
    }

    [TestMethod]
    public async Task Somebody_holding_more_than_the_caller_cannot_be_simulated()
    {
        var result = await Service().StartAsync(Person(Admin, AdminEmail), BossEmail, null, default);

        Assert.AreEqual(SimulationRules.CannotSimulateWhoHoldsMore, Refusal(result));
        Assert.AreEqual(0, _recorder.Entries.Count);
    }

    [TestMethod]
    public async Task A_wildcard_covers_what_the_simulated_user_holds()
    {
        _permissions.Held[Admin] = ["*", SimulationPermission];

        var started = Accepted(await Service().StartAsync(Person(Admin, AdminEmail), BossEmail, null, default));

        Assert.AreEqual(Boss, started.Context.EffectiveUser.ObjectId);
    }

    [TestMethod]
    public async Task A_caller_without_the_dedicated_permission_is_refused()
    {
        _targets.People[AdminEmail] = new SimulationTarget(AdminEmail, Admin, "Admin");

        var result = await Service().StartAsync(Person(Reader, ReaderEmail), AdminEmail, null, default);

        Assert.AreEqual($"Simulating another user requires {SimulationPermission}.", Refusal(result));
        Assert.AreEqual(0, _recorder.Entries.Count);
    }

    [TestMethod]
    public async Task Nobody_starts_a_simulation_from_inside_one()
    {
        var result = await Service().StartAsync(Simulated(Reader, ReaderEmail, realOid: Admin, realEmail: AdminEmail), ReaderEmail, null, default);

        Assert.AreEqual("Stop simulating first: a simulation cannot be started or ended from inside one.", Refusal(result));
        Assert.AreEqual(0, _recorder.Entries.Count);
    }

    [TestMethod]
    public async Task A_client_that_is_not_a_person_cannot_simulate()
    {
        var token = new ClaimsPrincipal(new ClaimsIdentity([new Claim("oid", Admin)], "PAT"));

        Assert.AreEqual(SimulationRules.InteractiveSignInOnly, Refusal(await Service().StartAsync(token, ReaderEmail, null, default)));
    }

    [TestMethod]
    public async Task An_unknown_person_is_not_found()
    {
        var result = await Service().StartAsync(Person(Admin, AdminEmail), "Nobody@Test", null, default);

        Assert.AreEqual("An active user with the e-mail nobody@test was not found.", result.NotFound);
    }

    [TestMethod]
    public async Task A_person_without_an_immutable_id_is_refused()
    {
        _targets.People["noid@test"] = new SimulationTarget("noid@test", SubjectId: null, "No id");

        Assert.AreEqual("The user noid@test has no immutable id to be simulated by.",
            Refusal(await Service().StartAsync(Person(Admin, AdminEmail), "noid@test", null, default)));
    }

    [TestMethod]
    public async Task A_start_that_cannot_be_recorded_does_not_begin()
    {
        _recorder.FailStart = true;
        await Assert.ThrowsExceptionAsync<InvalidOperationException>(() => Service().StartAsync(Person(Admin, AdminEmail), ReaderEmail, null, default));

        _recorder.FailStart = false;
        var started = Accepted(await Service().StartAsync(Person(Admin, AdminEmail), ReaderEmail, null, default));

        Assert.IsFalse(started.Resumed, "the failed start must not count as a running simulation");
        Assert.AreEqual(1, _recorder.Entries.Count);
    }

    // ── End ───────────────────────────────────────────────────────────────────

    [TestMethod]
    public async Task Ending_records_the_end_with_the_real_administrator_and_forgets_the_session()
    {
        await Service().StartAsync(Person(Admin, AdminEmail), ReaderEmail, null, default);

        Assert.IsTrue(Accepted(await Service().EndAsync(Person(Admin, AdminEmail), ReaderEmail, default)));

        var (kind, session) = _recorder.Entries[^1];
        Assert.AreEqual("ended", kind);
        Assert.AreEqual(Admin, session.RealSubjectId);
        Assert.AreEqual(Reader, session.TargetSubjectId);

        var again = Accepted(await Service().StartAsync(Person(Admin, AdminEmail), ReaderEmail, null, default));
        Assert.IsFalse(again.Resumed, "a simulation started after the end is a new one");
        Assert.AreEqual(3, _recorder.Entries.Count);
    }

    [TestMethod]
    public async Task The_end_is_recorded_for_somebody_who_lost_their_access_meanwhile()
    {
        _targets.People.Remove(ReaderEmail);
        _directory.People[ReaderEmail] = new DirectoryIdentity(Reader, ReaderEmail, "Reader");

        Accepted(await Service().EndAsync(Person(Admin, AdminEmail), ReaderEmail, default));

        Assert.AreEqual(Reader, _recorder.Entries.Single().Session.TargetSubjectId);
    }

    [TestMethod]
    public async Task Ending_for_nobody_known_is_not_found()
    {
        Assert.AreEqual("An active user with the e-mail nobody@test was not found.",
            (await Service().EndAsync(Person(Admin, AdminEmail), "nobody@test", default)).NotFound);
    }

    [TestMethod]
    public async Task Nobody_ends_a_simulation_from_inside_one()
    {
        var result = await Service().EndAsync(Simulated(Reader, ReaderEmail, realOid: Admin, realEmail: AdminEmail), ReaderEmail, default);

        Assert.IsFalse(result.Validation.IsValid);
        Assert.AreEqual(0, _recorder.Entries.Count);
    }

    // ── Candidates ────────────────────────────────────────────────────────────

    [TestMethod]
    public async Task The_candidates_are_everybody_with_access_but_the_caller_with_why_not()
    {
        var candidates = await CandidatesOf(Person(Admin, AdminEmail));

        CollectionAssert.AreEqual(new[] { Boss, Reader }, candidates.Select(c => c.ObjectId).ToArray(), "by name, without the caller");

        var reader = candidates.Single(c => c.ObjectId == Reader);
        Assert.IsTrue(reader.CanSimulate);
        Assert.IsNull(reader.Reason);
        Assert.AreEqual(ReaderEmail, reader.Email);
        Assert.AreEqual("Reader", reader.Name);

        var boss = candidates.Single(c => c.ObjectId == Boss);
        Assert.IsFalse(boss.CanSimulate, "holds portal.Admin, which the caller does not");
        Assert.AreEqual("Holds permissions you do not hold.", boss.Reason);
    }

    /// <summary>The list never promises what a start refuses, nor refuses what a start accepts.</summary>
    [TestMethod]
    public async Task Each_candidate_is_what_a_start_would_answer()
    {
        foreach (var candidate in await CandidatesOf(Person(Admin, AdminEmail)))
        {
            var started = await Service().StartAsync(Person(Admin, AdminEmail), candidate.Email, null, default);
            Assert.AreEqual(candidate.CanSimulate, started.Validation.IsValid, candidate.Email);
        }
    }

    [TestMethod]
    public async Task A_wildcard_makes_everybody_a_candidate()
    {
        _permissions.Held[Admin] = ["*", SimulationPermission];

        Assert.IsTrue((await CandidatesOf(Person(Admin, AdminEmail))).All(c => c.CanSimulate));
    }

    [TestMethod]
    public async Task A_disabled_account_or_one_without_an_e_mail_is_listed_but_not_a_candidate()
    {
        _group.Add("0a000000-0000-0000-0000-000000000005", "gone@test", "Gone", enabled: false);
        _group.Add("0a000000-0000-0000-0000-000000000006", email: null, "No Mail");

        var candidates = await CandidatesOf(Person(Admin, AdminEmail));

        Assert.AreEqual("The account is disabled.", candidates.Single(c => c.Name == "Gone").Reason);
        Assert.AreEqual("Has no e-mail address to be simulated by.", candidates.Single(c => c.Name == "No Mail").Reason);
    }

    [TestMethod]
    public async Task Somebody_who_holds_nothing_is_not_a_candidate()
    {
        _group.Add("0a000000-0000-0000-0000-000000000007", "empty@test", "Empty");

        var empty = (await CandidatesOf(Person(Admin, AdminEmail))).Single(c => c.Name == "Empty");

        Assert.IsFalse(empty.CanSimulate);
        Assert.AreEqual("Holds no access.", empty.Reason);
    }

    [TestMethod]
    public async Task Without_the_dedicated_permission_there_are_no_candidates()
    {
        var result = await Service().ListCandidatesAsync(Person(Reader, ReaderEmail), default);

        StringAssert.Contains(Refusal(result), SimulationPermission);
    }

    [TestMethod]
    public async Task Nobody_lists_the_candidates_from_inside_a_simulation()
    {
        var result = await Service().ListCandidatesAsync(Simulated(Reader, ReaderEmail, realOid: Admin, realEmail: AdminEmail), default);

        Assert.IsFalse(result.Validation.IsValid);
    }

    /// <summary>A host with the administration but without simulation: the service is there, and refuses.</summary>
    [TestMethod]
    public async Task Without_simulation_switched_on_every_operation_is_refused()
    {
        var services = new ServiceCollection().AddLogging();
        services.AddSingleton<IUserIdentityResolver>(new ClaimsUserIdentityResolver(_identity));
        services.AddSingleton<IPrincipalPermissionResolver>(_permissions);
        services.AddSingleton<IPermissionStore>(_permissions);
        services.AddSingleton<ISimulationRecorder>(_recorder);
        services.AddSingleton<IAccessDirectory>(_group);
        services.AddScoped<ISimulationAdminService, SimulationAdminService>();
        using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateOnBuild = true });
        using var scope = provider.CreateScope();
        var service = scope.ServiceProvider.GetRequiredService<ISimulationAdminService>();

        Assert.AreEqual("User simulation is not enabled.", Refusal(await service.StartAsync(Person(Admin, AdminEmail), ReaderEmail, null, default)));
        Assert.AreEqual("User simulation is not enabled.", Refusal(await service.EndAsync(Person(Admin, AdminEmail), ReaderEmail, default)));
        Assert.AreEqual("User simulation is not enabled.", Refusal(await service.ListCandidatesAsync(Person(Admin, AdminEmail), default)));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private ISimulationAdminService Service() =>
        _services.CreateScope().ServiceProvider.GetRequiredService<ISimulationAdminService>();

    private async Task<IReadOnlyList<SimulationCandidate>> CandidatesOf(ClaimsPrincipal principal) =>
        Accepted(await Service().ListCandidatesAsync(principal, default));

    private static T Accepted<T>(SimulationResult<T> result)
    {
        Assert.IsNull(result.NotFound, result.NotFound);
        Assert.IsTrue(result.Validation.IsValid, string.Join(" ", result.Validation.Errors));
        return result.Data;
    }

    private static string Refusal<T>(SimulationResult<T> result)
    {
        Assert.IsFalse(result.Validation.IsValid, "expected a refusal");
        Assert.IsNull(result.NotFound);
        return string.Join(" ", result.Validation.Errors);
    }

    private static ClaimsPrincipal Person(string oid, string email) =>
        new(new ClaimsIdentity([new Claim("oid", oid), new Claim("preferred_username", email)], "Bearer"));

    /// <summary>The principal as SimulationClaimsTransformation builds it: the target, plus who is behind it.</summary>
    private ClaimsPrincipal Simulated(string oid, string email, string realOid, string realEmail) =>
        new(new ClaimsIdentity(
        [
            new Claim(_identity.EmailClaimTypes[0], email),
            new Claim(_options.SimulatedByClaimType, realEmail),
            new Claim(_options.SimulatedByObjectIdClaimType, realOid),
            new Claim(_identity.SubjectClaimTypes[0], oid),
        ], "Bearer"));

    // ── Fakes ─────────────────────────────────────────────────────────────────

    /// <summary>Effective permissions by immutable id — for the caller's principal and for the target alike.</summary>
    private sealed class Permissions : IPrincipalPermissionResolver, IPermissionStore
    {
        public Dictionary<string, HashSet<string>> Held { get; } = new();

        public Task<IReadOnlySet<string>> ResolveAsync(ClaimsPrincipal principal, CancellationToken cancellationToken = default) =>
            Task.FromResult(For(principal.FindFirst("oid")?.Value));

        public Task<IReadOnlySet<string>> GetPermissionsAsync(UserIdentity user, CancellationToken cancellationToken = default) =>
            Task.FromResult(For(user.SubjectId));

        private IReadOnlySet<string> For(string? subjectId) =>
            subjectId is not null && Held.TryGetValue(subjectId, out var codes) ? codes : new HashSet<string>();
    }

    /// <summary>Who may be simulated, by e-mail.</summary>
    private sealed class Targets : ISimulationTargetResolver
    {
        public Dictionary<string, SimulationTarget> People { get; } = new();

        public Task<SimulationTarget?> ResolveAsync(string email, CancellationToken cancellationToken = default) =>
            Task.FromResult(People.GetValueOrDefault(email));
    }

    /// <summary>The directory, for somebody who lost their access and can no longer be simulated.</summary>
    private sealed class Directory : IMembershipSource
    {
        public Dictionary<string, DirectoryIdentity> People { get; } = new();

        public Task<Membership?> GetMembershipAsync(string subjectId, CancellationToken cancellationToken = default) =>
            Task.FromResult<Membership?>(null);

        public Task<DirectoryIdentity?> FindByEmailAsync(string email, CancellationToken cancellationToken = default) =>
            Task.FromResult(People.GetValueOrDefault(email));
    }

    /// <summary>Who has access, as far as listing it goes.</summary>
    private sealed class Group : IAccessDirectory
    {
        private readonly List<DirectoryAccount> _people = [];

        public Group Add(string objectId, string? email, string? name, bool enabled = true)
        {
            _people.Add(new DirectoryAccount(new DirectoryUser(objectId, name, email, email, IsGuest: false), enabled));
            return this;
        }

        public Task<IReadOnlyList<DirectoryAccount>> ListWithAccessAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<DirectoryAccount>>(_people);

        public Task<DirectoryAccount?> GetUserAsync(string objectId, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<IReadOnlyList<DirectoryAccount>> GetUsersAsync(IReadOnlyCollection<string> objectIds, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<bool> HasAccessAsync(string objectId, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task GrantAsync(string objectId, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task RevokeAsync(string objectId, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    }

    /// <summary>What was recorded, in order. <see cref="FailStart"/> makes the next start fail to be recorded.</summary>
    private sealed class Recorder : ISimulationRecorder
    {
        public List<(string Kind, SimulationSession Session)> Entries { get; } = [];

        public bool FailStart { get; set; }

        public Task StartedAsync(SimulationSession session, CancellationToken cancellationToken = default)
        {
            if (FailStart)
                throw new InvalidOperationException("The audit log is down.");

            Entries.Add(("started", session));
            return Task.CompletedTask;
        }

        public Task EndedAsync(SimulationSession session, CancellationToken cancellationToken = default)
        {
            Entries.Add(("ended", session));
            return Task.CompletedTask;
        }
    }
}
