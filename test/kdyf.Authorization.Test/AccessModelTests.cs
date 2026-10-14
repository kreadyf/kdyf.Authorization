using kdyf.Authorization.Abstractions;
using kdyf.Authorization.Caching;
using kdyf.Authorization.Roles;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;

namespace kdyf.Authorization.Test
{
    /// <summary>
    /// The group lets a person in; the roles say what they may do; code says which permissions exist. The rule
    /// that joins the three.
    /// </summary>
    [TestClass]
    public class RolePermissionMapTests
    {
        [TestMethod]
        public void Roles_grant_the_union_of_what_each_grants()
        {
            var map = TestRoles.Map();

            CollectionAssert.AreEquivalent(new[] { "portal.Read", "audit.Read" },
                map.EffectivePermissions(new[] { "Portal.Reader", "Portal.Auditor" }).ToArray());
        }

        /// <summary>A member holds the base access on top of their roles — and with no role, only that.</summary>
        [TestMethod]
        public void A_member_holds_what_every_member_holds_plus_their_roles()
        {
            var map = TestRoles.Map();

            CollectionAssert.AreEquivalent(new[] { "Default", "portal.Read" }, map.ForMember(new[] { "Portal.Reader" }).ToArray());
            CollectionAssert.AreEquivalent(new[] { "Default" }, map.ForMember(Array.Empty<string>()).ToArray());
        }

        /// <summary>A code nobody declares cannot be handed to the whole group by configuration.</summary>
        [TestMethod]
        public void Member_grants_nobody_declares_grant_nothing()
        {
            var map = new RolePermissionMap(TestRoles.Grants(), TestRoles.Declared().Codes, new[] { "Defualt" });

            Assert.AreEqual(0, map.ForMember(Array.Empty<string>()).Count);
        }

        /// <summary>The wildcard stands for every declared code, so a permission added later reaches the administrator.</summary>
        [TestMethod]
        public void The_wildcard_expands_to_every_declared_code_and_is_kept()
        {
            CollectionAssert.IsSubsetOf(
                new[] { "Default", "portal.Read", "portal.Edit", "audit.Read", "admin.Users", "support.Simulate", "*" },
                TestRoles.Map().EffectivePermissions(new[] { "Portal.Admin" }).ToArray());
        }

        /// <summary>A role that does not exist grants nothing — never a guess.</summary>
        [TestMethod]
        public void A_role_that_does_not_exist_grants_nothing()
        {
            Assert.AreEqual(0, TestRoles.Map().EffectivePermissions(new[] { "Portal.Superuser" }).Count);
            Assert.IsFalse(TestRoles.Map().Exists("Portal.Superuser"));
        }

        /// <summary>A role value is compared exactly, as it is stored: 'portal.admin' is not the admin role.</summary>
        [TestMethod]
        public void Role_values_are_case_sensitive() =>
            Assert.AreEqual(0, TestRoles.Map().EffectivePermissions(new[] { "portal.admin" }).Count);

        /// <summary>
        /// A stored code that no declaration matches (renamed or removed in code) grants nothing: no door demands
        /// it, and trusting it would let a typo in the table become a permission later.
        /// </summary>
        [TestMethod]
        public void A_configured_code_nobody_declares_grants_nothing_and_is_reported()
        {
            var map = new RolePermissionMap(
                new Dictionary<string, IReadOnlySet<string>> { ["Portal.Reader"] = Set("portal.Read", "portal.Reed") },
                TestRoles.Declared().Codes);

            CollectionAssert.AreEquivalent(new[] { "portal.Read" }, map.EffectivePermissions(new[] { "Portal.Reader" }).ToArray());
            CollectionAssert.AreEqual(new[] { "portal.Reed" }, map.Undeclared["Portal.Reader"].ToArray());
        }

        /// <summary>Nobody gives away more than they hold, and whoever holds '*' holds everything.</summary>
        [TestMethod]
        public void A_role_is_covered_only_by_somebody_holding_all_it_grants()
        {
            var map = TestRoles.Map();

            Assert.IsTrue(map.IsCoveredBy("Portal.Editor", map.ForMember(new[] { "Portal.Admin" })));
            Assert.IsFalse(map.IsCoveredBy("Portal.Editor", map.ForMember(new[] { "Portal.Reader" })));
            Assert.IsFalse(map.IsCoveredBy("Portal.Admin", map.ForMember(new[] { "Portal.Editor" })),
                "an editor cannot hand out the wildcard");
        }

        [TestMethod]
        public void With_shows_what_a_change_would_leave_without_changing_the_map()
        {
            var map = TestRoles.Map();

            var changed = map.With("Portal.Reader", Array.Empty<string>());

            Assert.IsFalse(changed.ForMember(new[] { "Portal.Reader" }).Contains("portal.Read"));
            Assert.IsTrue(changed.ForMember(new[] { "Portal.Reader" }).Contains("Default"), "the member grants stay");
            Assert.IsTrue(map.ForMember(new[] { "Portal.Reader" }).Contains("portal.Read"), "the original is untouched");
        }

        private static IReadOnlySet<string> Set(params string[] codes) => codes.ToHashSet(StringComparer.Ordinal);
    }

    [TestClass]
    public class RolePermissionMapProviderTests
    {
        /// <summary>One read serves every request; a change applies once the entry expires or is invalidated.</summary>
        [TestMethod]
        public async Task The_map_is_read_once_and_again_after_invalidation()
        {
            var source = new FakeRolePermissionSource(TestRoles.Grants());
            var provider = RolePermissionMapProvider.ForSource(source, TestRoles.Declared(), TimeSpan.FromMinutes(2));

            await provider.GetAsync();
            await provider.GetAsync();
            Assert.AreEqual(1, source.Reads);

            provider.Invalidate();
            await provider.GetAsync();
            Assert.AreEqual(2, source.Reads);
        }

        /// <summary>A database failure is not "no role grants anything" cached for minutes: it throws, and is retried.</summary>
        [TestMethod]
        public async Task A_failure_is_not_cached()
        {
            var source = new FakeRolePermissionSource(TestRoles.Grants()) { FailWith = new InvalidOperationException("database down") };
            var provider = RolePermissionMapProvider.ForSource(source, TestRoles.Declared(), TimeSpan.FromMinutes(2));

            await Assert.ThrowsExceptionAsync<InvalidOperationException>(() => provider.GetAsync());

            source.FailWith = null;
            Assert.IsTrue((await provider.GetAsync()).GrantsOf("Portal.Admin").Contains("*"));
        }
    }

    /// <summary>The deployment that removes a permission class says so in its own log.</summary>
    [TestClass]
    public class RolePermissionStartupCheckTests
    {
        [TestMethod]
        public async Task Configured_codes_nobody_declares_are_reported_at_startup()
        {
            var grants = new Dictionary<string, IReadOnlySet<string>>(TestRoles.Grants())
            {
                ["Portal.Reader"] = new HashSet<string>(StringComparer.Ordinal) { "portal.Read", "portal.Retired" }
            };
            var log = new ListLogger<RolePermissionStartupCheck>();

            await new RolePermissionStartupCheck(Provider(new FakeRolePermissionSource(grants)), log).StartAsync(default);

            var warning = log.Entries.Single(e => e.Level == Microsoft.Extensions.Logging.LogLevel.Warning);
            StringAssert.Contains(warning.Message, "Portal.Reader: portal.Retired");
        }

        [TestMethod]
        public async Task A_clean_configuration_says_nothing()
        {
            var log = new ListLogger<RolePermissionStartupCheck>();

            await new RolePermissionStartupCheck(Provider(new FakeRolePermissionSource(TestRoles.Grants())), log).StartAsync(default);

            Assert.AreEqual(0, log.Entries.Count);
        }

        /// <summary>A report must never become an outage: a database not reachable yet is logged, and startup goes on.</summary>
        [TestMethod]
        public async Task A_database_that_cannot_be_read_does_not_stop_the_host()
        {
            var source = new FakeRolePermissionSource(TestRoles.Grants()) { FailWith = new InvalidOperationException("database down") };
            var log = new ListLogger<RolePermissionStartupCheck>();

            await new RolePermissionStartupCheck(Provider(source), log).StartAsync(default);

            Assert.AreEqual(Microsoft.Extensions.Logging.LogLevel.Error, log.Entries.Single().Level);
        }

        private static RolePermissionMapProvider Provider(IRolePermissionSource source) =>
            RolePermissionMapProvider.ForSource(source, TestRoles.Declared(), TimeSpan.FromMinutes(2));
    }

    /// <summary>Keeps what was logged, to assert on it.</summary>
    internal sealed class ListLogger<T> : Microsoft.Extensions.Logging.ILogger<T>
    {
        internal List<(Microsoft.Extensions.Logging.LogLevel Level, string Message)> Entries { get; } = new();

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(Microsoft.Extensions.Logging.LogLevel logLevel) => true;

        public void Log<TState>(Microsoft.Extensions.Logging.LogLevel logLevel, Microsoft.Extensions.Logging.EventId eventId,
            TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            Entries.Add((logLevel, formatter(state, exception)));
    }

    /// <summary>
    /// The permission store of the access model: the group is the gate, the roles add to it; fail-closed, keyed
    /// by the object id, and bounded in time.
    /// </summary>
    [TestClass]
    public class MembershipPermissionStoreTests
    {
        private const string Ana = "11111111-1111-1111-1111-111111111111";

        [TestMethod]
        public async Task A_member_holds_the_base_access_plus_what_their_roles_grant()
        {
            var (entra, roles) = (new FakeMembershipSource().Join(Ana), new FakeUserRoleSource().Give(Ana, "Portal.Editor"));

            var codes = await Store(entra, roles).GetPermissionsAsync(new UserIdentity(Ana, "ana@test"));

            CollectionAssert.AreEquivalent(new[] { "Default", "portal.Read", "portal.Edit" }, codes.ToArray());
        }

        /// <summary>Being in the group is being let in: with no role, the base access and nothing else.</summary>
        [TestMethod]
        public async Task A_member_with_no_role_holds_the_base_access()
        {
            var codes = await Store(new FakeMembershipSource().Join(Ana), new FakeUserRoleSource()).GetPermissionsAsync(new UserIdentity(Ana, "ana@test"));

            CollectionAssert.AreEquivalent(new[] { "Default" }, codes.ToArray());
        }

        /// <summary>
        /// The gate this whole model rests on: out of the group, nothing — whatever roles are still in the database.
        /// It is what makes taking somebody out of the group in Entra a real revocation.
        /// </summary>
        [TestMethod]
        public async Task Somebody_outside_the_group_holds_nothing_whatever_roles_they_have()
        {
            var (entra, roles) = (new FakeMembershipSource().Join(Ana, member: false), new FakeUserRoleSource().Give(Ana, "Portal.Admin"));

            Assert.AreEqual(0, (await Store(entra, roles).GetPermissionsAsync(new UserIdentity(Ana, "ana@test"))).Count);
            Assert.AreEqual(0, roles.Calls, "the roles are not even read");
        }

        /// <summary>
        /// No 'oid', no permissions — even with an e-mail that matches somebody in the group. Resolving by e-mail is
        /// how a guest's #EXT# name, or a recycled address, lands on another person's access.
        /// </summary>
        [TestMethod]
        public async Task Without_an_object_id_nobody_is_resolved_by_email()
        {
            var entra = new FakeMembershipSource().Join(Ana, email: "ana@test");

            var codes = await Store(entra, new FakeUserRoleSource().Give(Ana, "Portal.Admin")).GetPermissionsAsync(new UserIdentity(null, "ana@test"));

            Assert.AreEqual(0, codes.Count);
            Assert.AreEqual(0, entra.Calls, "the directory is not even asked");
        }

        [TestMethod]
        public async Task Somebody_the_directory_does_not_know_holds_nothing() =>
            Assert.AreEqual(0, (await Store(new FakeMembershipSource(), new FakeUserRoleSource().Give(Ana, "Portal.Admin"))
                .GetPermissionsAsync(new UserIdentity(Ana, "ana@test"))).Count);

        /// <summary>A disabled account holds nothing, in the group or not.</summary>
        [TestMethod]
        public async Task A_disabled_account_holds_nothing()
        {
            var entra = new FakeMembershipSource().Join(Ana).Disable(Ana);

            Assert.AreEqual(0, (await Store(entra, new FakeUserRoleSource().Give(Ana, "Portal.Admin")).GetPermissionsAsync(new UserIdentity(Ana, "ana@test"))).Count);
        }

        /// <summary>Graph down is not "not a member" and not "a member as before": it throws, and the handler denies.</summary>
        [TestMethod]
        public async Task A_directory_failure_propagates_so_the_request_is_denied()
        {
            var entra = new FakeMembershipSource().Join(Ana);
            entra.FailWith = new HttpRequestException("Graph unreachable");

            await Assert.ThrowsExceptionAsync<HttpRequestException>(() =>
                Store(entra, new FakeUserRoleSource()).GetPermissionsAsync(new UserIdentity(Ana, "ana@test")));
        }

        [TestMethod]
        public async Task A_database_failure_propagates_so_the_request_is_denied()
        {
            var roles = new FakeUserRoleSource { FailWith = new InvalidOperationException("database down") };
            var configuration = new FakeRolePermissionSource(TestRoles.Grants()) { FailWith = new InvalidOperationException("database down") };

            await Assert.ThrowsExceptionAsync<InvalidOperationException>(() =>
                Store(new FakeMembershipSource().Join(Ana), roles).GetPermissionsAsync(new UserIdentity(Ana, "ana@test")));
            await Assert.ThrowsExceptionAsync<InvalidOperationException>(() =>
                Store(new FakeMembershipSource().Join(Ana), new FakeUserRoleSource(), configuration).GetPermissionsAsync(new UserIdentity(Ana, "ana@test")));
        }

        /// <summary>
        /// The documented propagation time, pinned. Somebody taken out of the group in the Entra portal keeps their
        /// access until the cached entry expires — and not a moment longer. CacheDuration IS the maximum
        /// propagation time.
        /// </summary>
        [TestMethod]
        public async Task A_removal_from_the_group_in_Entra_takes_effect_when_the_cache_expires()
        {
            var entra = new FakeMembershipSource().Join(Ana);
            var (store, _) = Cached(entra, new FakeUserRoleSource().Give(Ana, "Portal.Editor"), TimeSpan.FromMilliseconds(300));
            var ana = new UserIdentity(Ana, "ana@test");

            Assert.IsTrue((await store.GetPermissionsAsync(ana)).Contains("portal.Edit"));

            entra.Leave(Ana);

            Assert.IsTrue((await store.GetPermissionsAsync(ana)).Contains("portal.Edit"),
                "within CacheDuration the cached set still answers — that is the bounded window");

            await Task.Delay(TimeSpan.FromMilliseconds(450));

            Assert.AreEqual(0, (await store.GetPermissionsAsync(ana)).Count, "after CacheDuration, the removal holds");
        }

        /// <summary>A change made through the application invalidates the entry: effective at once on this instance.</summary>
        [TestMethod]
        public async Task An_invalidated_person_is_resolved_again_at_once()
        {
            var roles = new FakeUserRoleSource().Give(Ana, "Portal.Editor");
            var (store, cache) = Cached(new FakeMembershipSource().Join(Ana), roles, TimeSpan.FromMinutes(2));
            var ana = new UserIdentity(Ana, "ana@test");

            await store.GetPermissionsAsync(ana);
            roles.Take(Ana);

            // The PAT store and the administration service invalidate with the object id alone.
            cache.Invalidate(new UserIdentity(Ana, null));

            CollectionAssert.AreEquivalent(new[] { "Default" }, (await store.GetPermissionsAsync(ana)).ToArray());
        }

        private static MembershipPermissionStore Store(FakeMembershipSource entra, FakeUserRoleSource roles, FakeRolePermissionSource? source = null) =>
            new(entra, roles,
                RolePermissionMapProvider.ForSource(source ?? new FakeRolePermissionSource(TestRoles.Grants()), TestRoles.Declared(), TimeSpan.FromMinutes(2), TestRoles.MemberGrants),
                NullLogger<MembershipPermissionStore>.Instance);

        private static (IPermissionStore Store, MemoryPermissionCache Cache) Cached(FakeMembershipSource entra, FakeUserRoleSource roles, TimeSpan duration)
        {
            var options = new PermissionAuthorizationOptions { CacheDuration = duration, EmptyResultCacheDuration = duration };
            var cache = new MemoryPermissionCache(new MemoryCache(new MemoryCacheOptions()), options, NullLogger<MemoryPermissionCache>.Instance, TimeProvider.System);
            return (new CachingPermissionStore(Store(entra, roles), cache), cache);
        }
    }

    [TestClass]
    public class MembershipSimulationTargetResolverTests
    {
        private const string Ana = "11111111-1111-1111-1111-111111111111";

        [TestMethod]
        public async Task A_member_can_be_simulated()
        {
            var entra = new FakeMembershipSource().Join(Ana, email: "ana@test", name: "Ana");

            var target = await Resolver(entra, new FakeUserRoleSource().Give(Ana, "Portal.Reader")).ResolveAsync(" Ana@Test ");

            Assert.IsNotNull(target);
            Assert.AreEqual(Ana, target!.SubjectId);
            Assert.AreEqual("ana@test", target.Email);
        }

        [TestMethod]
        public async Task Somebody_outside_the_group_is_not_a_target()
        {
            var entra = new FakeMembershipSource().Join(Ana, member: false, email: "ana@test");

            Assert.IsNull(await Resolver(entra, new FakeUserRoleSource().Give(Ana, "Portal.Reader")).ResolveAsync("ana@test"));
        }

        [TestMethod]
        public async Task A_disabled_account_is_not_a_target()
        {
            var entra = new FakeMembershipSource().Join(Ana, email: "ana@test").Disable(Ana);

            Assert.IsNull(await Resolver(entra, new FakeUserRoleSource().Give(Ana, "Portal.Reader")).ResolveAsync("ana@test"));
        }

        /// <summary>Somebody who would hold nothing at all is refused: their session would answer no question.</summary>
        [TestMethod]
        public async Task A_member_holding_nothing_is_not_a_target()
        {
            var entra = new FakeMembershipSource().Join(Ana, email: "ana@test");
            var resolver = new MembershipSimulationTargetResolver(entra, new FakeUserRoleSource(),
                RolePermissionMapProvider.ForSource(new FakeRolePermissionSource(TestRoles.Grants()), TestRoles.Declared(), TimeSpan.FromMinutes(2)));

            Assert.IsNull(await resolver.ResolveAsync("ana@test"), "no member grants and no role: nothing to see");
        }

        /// <summary>
        /// The target is resolved on every simulated request: with a cache, the directory is asked once per
        /// CacheDuration — a refusal for the shorter EmptyResultCacheDuration — not once per request.
        /// </summary>
        [TestMethod]
        public async Task With_a_cache_the_directory_is_asked_once_per_cache_duration()
        {
            var entra = new FakeMembershipSource().Join(Ana, email: "ana@test");
            var cache = new MemoryCache(new MemoryCacheOptions());
            var options = new PermissionAuthorizationOptions();
            MembershipSimulationTargetResolver Cached() => new(entra, new FakeUserRoleSource().Give(Ana, "Portal.Reader"),
                RolePermissionMapProvider.ForSource(new FakeRolePermissionSource(TestRoles.Grants()), TestRoles.Declared(), TimeSpan.FromMinutes(2), TestRoles.MemberGrants),
                cache, options);

            var first = await Cached().ResolveAsync("ana@test");
            var callsAfterFirst = entra.Calls;
            var second = await Cached().ResolveAsync("  ANA@test ");

            Assert.AreEqual(Ana, first!.SubjectId);
            Assert.AreEqual(Ana, second!.SubjectId);
            Assert.AreEqual(callsAfterFirst, entra.Calls, "the second request, another resolver, another spelling: no directory call");

            Assert.IsNull(await Cached().ResolveAsync("nobody@test"));
            var callsAfterRefusal = entra.Calls;
            Assert.IsNull(await Cached().ResolveAsync("nobody@test"));
            Assert.AreEqual(callsAfterRefusal, entra.Calls, "a refusal is cached too, for the shorter time");
        }

        private static MembershipSimulationTargetResolver Resolver(FakeMembershipSource entra, FakeUserRoleSource roles) =>
            new(entra, roles, RolePermissionMapProvider.ForSource(new FakeRolePermissionSource(TestRoles.Grants()), TestRoles.Declared(), TimeSpan.FromMinutes(2), TestRoles.MemberGrants));
    }

    /// <summary>What Entra says about the access group, steerable from a test.</summary>
    internal sealed class FakeMembershipSource : IMembershipSource
    {
        private readonly Dictionary<string, (bool Enabled, bool Member, string? Email, string? Name)> _people =
            new(StringComparer.OrdinalIgnoreCase);

        internal int Calls { get; private set; }

        internal Exception? FailWith { get; set; }

        internal FakeMembershipSource Join(string subjectId, bool member = true, string? email = null, string? name = null)
        {
            _people[subjectId] = (true, member, email, name);
            return this;
        }

        internal FakeMembershipSource Leave(string subjectId)
        {
            _people[subjectId] = _people[subjectId] with { Member = false };
            return this;
        }

        internal FakeMembershipSource Disable(string subjectId)
        {
            _people[subjectId] = _people[subjectId] with { Enabled = false };
            return this;
        }

        public Task<Membership?> GetMembershipAsync(string subjectId, CancellationToken cancellationToken = default)
        {
            Calls++;
            if (FailWith is not null)
                throw FailWith;

            return Task.FromResult(_people.TryGetValue(subjectId, out var p) ? new Membership(p.Enabled, p.Member) : null);
        }

        public Task<DirectoryIdentity?> FindByEmailAsync(string email, CancellationToken cancellationToken = default)
        {
            Calls++;
            var match = _people.FirstOrDefault(p => string.Equals(p.Value.Email, email, StringComparison.OrdinalIgnoreCase));
            return Task.FromResult(match.Key is null ? null : new DirectoryIdentity(match.Key, email, match.Value.Name));
        }
    }

    /// <summary>Who holds which role, in memory.</summary>
    internal sealed class FakeUserRoleSource : IUserRoleSource
    {
        private readonly Dictionary<string, HashSet<string>> _held = new(StringComparer.OrdinalIgnoreCase);

        internal int Calls { get; private set; }

        internal Exception? FailWith { get; set; }

        internal FakeUserRoleSource Give(string subjectId, string role)
        {
            if (!_held.TryGetValue(subjectId, out var roles))
                _held[subjectId] = roles = new HashSet<string>(StringComparer.Ordinal);
            roles.Add(role);
            return this;
        }

        internal FakeUserRoleSource Take(string subjectId)
        {
            _held.Remove(subjectId);
            return this;
        }

        public Task<IReadOnlySet<string>> GetRolesAsync(string subjectId, CancellationToken cancellationToken = default)
        {
            Calls++;
            if (FailWith is not null)
                throw FailWith;

            return Task.FromResult<IReadOnlySet<string>>(_held.TryGetValue(subjectId, out var roles)
                ? roles.ToHashSet(StringComparer.Ordinal)
                : new HashSet<string>(StringComparer.Ordinal));
        }
    }

    /// <summary>The role configuration, in memory.</summary>
    internal sealed class FakeRolePermissionSource : IRolePermissionSource
    {
        private readonly IReadOnlyDictionary<string, IReadOnlySet<string>> _grants;

        internal FakeRolePermissionSource(IReadOnlyDictionary<string, IReadOnlySet<string>> grants) => _grants = grants;

        internal int Reads { get; private set; }

        internal Exception? FailWith { get; set; }

        public Task<IReadOnlyDictionary<string, IReadOnlySet<string>>> GetAllAsync(CancellationToken cancellationToken = default)
        {
            Reads++;
            if (FailWith is not null)
                throw FailWith;
            return Task.FromResult(_grants);
        }
    }

    /// <summary>A small, realistic role model. Every member of the group holds <c>Default</c>.</summary>
    internal static class TestRoles
    {
        internal static readonly string[] MemberGrants = ["Default"];

        internal static DeclaredPermissions Declared() => new(new PermissionDefinition[]
        {
            new global::DefaultPermission(), new Read(), new Edit(), new AuditRead(), new AdminUsers(), new Simulate(), new Everything()
        });

        internal static IReadOnlyDictionary<string, IReadOnlySet<string>> Grants() => new Dictionary<string, IReadOnlySet<string>>
        {
            ["Portal.Reader"] = Set("portal.Read"),
            ["Portal.Editor"] = Set("portal.Read", "portal.Edit"),
            ["Portal.Auditor"] = Set("audit.Read"),
            // May simulate, and reads — but does not edit and does not administer.
            ["Portal.Support"] = Set("portal.Read", "support.Simulate"),
            ["Portal.Admin"] = Set("*"),
        };

        internal static RolePermissionMap Map() => new(Grants(), Declared().Codes, MemberGrants);

        private static IReadOnlySet<string> Set(params string[] codes) => codes.ToHashSet(StringComparer.Ordinal);

        // "Default" is declared once per assembly: DefaultPermission (RoleChangePropagationTests.cs) also serves here.
        internal sealed class Read : PermissionDefinition { public Read() : base(CodeShape.Verbatim, "portal.Read", "Read") { } }
        internal sealed class Edit : PermissionDefinition { public Edit() : base(CodeShape.Verbatim, "portal.Edit", "Edit") { } }
        internal sealed class AuditRead : PermissionDefinition { public AuditRead() : base(CodeShape.Verbatim, "audit.Read", "Audit") { } }
        internal sealed class AdminUsers : PermissionDefinition { public AdminUsers() : base(CodeShape.Verbatim, "admin.Users", "Users") { } }
        internal sealed class Simulate : PermissionDefinition { public Simulate() : base(CodeShape.Verbatim, "support.Simulate", "Simulate") { } }
        internal sealed class Everything : PermissionDefinition { public Everything() : base(CodeShape.Verbatim, "*", "Everything") { } }
    }
}
