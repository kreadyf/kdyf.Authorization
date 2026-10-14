using kdyf.Authorization;
using kdyf.Authorization.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

// Block-scoped, without a namespace: the codes are declared whole, as the host's global.* codes are.
internal sealed class DefaultPermission : PermissionDefinition
{
    public DefaultPermission() : base(CodeShape.Verbatim, "Default", "Base access") { }
}

internal sealed class DataReadPermission : PermissionDefinition
{
    public DataReadPermission() : base(CodeShape.Verbatim, "global.Data.Read", "Read data") { }
}

namespace kdyf.Authorization.Test
{
    /// <summary>
    /// A role-permission change made on one instance reaches another instance — which is never told — within one
    /// <c>CacheDuration</c>, not two: the per-person cache must not outlive the role map it was resolved from.
    /// </summary>
    /// <remarks>
    /// Each instance is the real chain as the host registers it (<c>AddPermissionAuthorization().AddAssignedRoles</c>:
    /// caching over the membership store over the role map), on its own container, over one shared role table.
    /// Only the clock, the group and the tables are doubles.
    /// </remarks>
    [TestClass]
    public sealed class RoleChangePropagationTests
    {
        private static readonly TimeSpan Duration = TimeSpan.FromMinutes(2);

        private const string Reader = "00000000-0000-0000-0000-00000000000e";
        private const string Editor = "00000000-0000-0000-0000-00000000000d";

        [TestMethod]
        public async Task Another_instance_applies_a_role_change_within_one_cache_duration()
        {
            var clock = new FakeTimeProvider(new DateTimeOffset(2026, 9, 24, 8, 0, 0, TimeSpan.Zero));
            var tables = new Tables();
            using var other = Instance(tables, clock);

            // The other instance reads the role map for somebody else, an instant before the change.
            await other.PermissionsOf(Editor);
            tables.Grant("Portal.Reader", "global.Data.Read");

            // Just inside the window the map it holds is legitimately stale — and the reader is resolved from it.
            clock.Advance(Duration - TimeSpan.FromSeconds(1));
            Assert.IsFalse((await other.PermissionsOf(Reader)).Contains("global.Data.Read"),
                "within one CacheDuration a stale answer is allowed");

            // One CacheDuration after the change, the change applies.
            clock.Advance(TimeSpan.FromSeconds(1));
            Assert.IsTrue((await other.PermissionsOf(Reader)).Contains("global.Data.Read"),
                "one CacheDuration after the change the other instance must apply it, not a second window later");
        }

        [TestMethod]
        public async Task Within_the_window_a_resolved_person_is_served_from_the_cache()
        {
            var clock = new FakeTimeProvider(new DateTimeOffset(2026, 9, 24, 8, 0, 0, TimeSpan.Zero));
            var tables = new Tables();
            using var instance = Instance(tables, clock);

            await instance.PermissionsOf(Reader);
            var reads = tables.RoleReads + tables.PersonReads;

            clock.Advance(Duration - TimeSpan.FromSeconds(1));
            Assert.IsTrue((await instance.PermissionsOf(Reader)).Contains("Default"));

            Assert.AreEqual(reads, tables.RoleReads + tables.PersonReads, "a cached person costs no read");
        }

        private static Host Instance(Tables tables, TimeProvider clock)
        {
            var services = new ServiceCollection();
            services.AddLogging();
            services.AddSingleton(clock);
            services.AddSingleton<IMembershipSource>(tables);
            services.AddSingleton<IUserRoleSource>(tables);
            services.AddSingleton<IRolePermissionSource>(tables);
            services.AddPermissionAuthorization(options =>
                {
                    options.CacheDuration = Duration;
                    options.ValidatePoliciesOnStartup = false;
                    options.MemberPermissionCodes = new HashSet<string>(StringComparer.Ordinal) { "Default" };
                })
                .AddAssignedRoles(typeof(RoleChangePropagationTests).Assembly);
            return new Host(services.BuildServiceProvider());
        }

        private sealed class Host : IDisposable
        {
            private readonly ServiceProvider _services;

            internal Host(ServiceProvider services) => _services = services;

            /// <summary>One request: a scope and the store it resolves, as the authorization handler gets it.</summary>
            internal async Task<IReadOnlySet<string>> PermissionsOf(string objectId)
            {
                using var scope = _services.CreateScope();
                return await scope.ServiceProvider.GetRequiredService<IPermissionStore>()
                    .GetPermissionsAsync(new UserIdentity(objectId, null));
            }

            public void Dispose() => _services.Dispose();
        }

        /// <summary>The group and the auth tables every instance reads: both people are members, one role each.</summary>
        private sealed class Tables : IMembershipSource, IUserRoleSource, IRolePermissionSource
        {
            private readonly object _gate = new();
            private readonly Dictionary<string, HashSet<string>> _grants = new(StringComparer.Ordinal)
            {
                ["Portal.Reader"] = new(StringComparer.Ordinal),
                ["Portal.Editor"] = new(StringComparer.Ordinal) { "global.Data.Read" },
            };

            internal int RoleReads { get; private set; }
            internal int PersonReads { get; private set; }

            internal void Grant(string role, string code)
            {
                lock (_gate)
                    _grants[role].Add(code);
            }

            public Task<Membership?> GetMembershipAsync(string subjectId, CancellationToken cancellationToken = default) =>
                Task.FromResult<Membership?>(new Membership(AccountEnabled: true, IsMember: true));

            public Task<DirectoryIdentity?> FindByEmailAsync(string email, CancellationToken cancellationToken = default) =>
                Task.FromResult<DirectoryIdentity?>(null);

            public Task<IReadOnlySet<string>> GetRolesAsync(string subjectId, CancellationToken cancellationToken = default)
            {
                lock (_gate)
                {
                    PersonReads++;
                    IReadOnlySet<string> roles = new HashSet<string>(StringComparer.Ordinal)
                    {
                        subjectId == Reader ? "Portal.Reader" : "Portal.Editor",
                    };
                    return Task.FromResult(roles);
                }
            }

            public Task<IReadOnlyDictionary<string, IReadOnlySet<string>>> GetAllAsync(CancellationToken cancellationToken = default)
            {
                lock (_gate)
                {
                    RoleReads++;
                    IReadOnlyDictionary<string, IReadOnlySet<string>> copy = _grants.ToDictionary(
                        g => g.Key, g => (IReadOnlySet<string>)new HashSet<string>(g.Value, StringComparer.Ordinal), StringComparer.Ordinal);
                    return Task.FromResult(copy);
                }
            }
        }
    }
}
