using System.Reflection;
using kdyf.Authorization.Abstractions;
using kdyf.Authorization.Authorization;
using kdyf.Authorization.Caching;
using kdyf.Authorization.Roles;
using kdyf.Authorization.Startup;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

namespace kdyf.Authorization
{
    /// <summary>
    /// Registration of the permission-based authorization system.
    /// </summary>
    public static class ServiceCollectionExtensions
    {
        /// <summary>
        /// Registers the policy provider, the handler and the cache. AddStore must be chained to
        /// indicate where permissions come from: without a store, the system denies everything.
        /// </summary>
        public static PermissionAuthorizationBuilder AddPermissionAuthorization(
            this IServiceCollection services,
            Action<PermissionAuthorizationOptions>? configure = null)
        {
            var options = new PermissionAuthorizationOptions();
            configure?.Invoke(options);
            options.Validate();

            services.AddSingleton(options);
            services.AddMemoryCache();
            // The clock of every cache window. The system's, unless a host or a test registered its own first.
            services.TryAddSingleton(TimeProvider.System);

            services.AddSingleton<MemoryPermissionCache>();
            services.AddSingleton<IPermissionCache>(sp => sp.GetRequiredService<MemoryPermissionCache>());

            services.TryAddSingleton<IUserIdentityResolver, ClaimsUserIdentityResolver>();
            services.AddSingleton<IAuthorizationPolicyProvider, PermissionPolicyProvider>();
            services.AddScoped<IAuthorizationHandler, PermissionAuthorizationHandler>();
            services.AddScoped<IAuthorizationHandler, AccessGateAuthorizationHandler>();
            services.TryAddScoped<IPrincipalPermissionResolver, PrincipalPermissionResolver>();

            if (options.ValidatePoliciesOnStartup)
                services.AddSingleton<IHostedService, PolicyValidationHostedService>();

            return new PermissionAuthorizationBuilder(services, options);
        }
    }

    /// <summary>
    /// Chains the registration of the store and the catalog.
    /// </summary>
    public sealed class PermissionAuthorizationBuilder
    {
        private readonly IServiceCollection _services;
        private readonly PermissionAuthorizationOptions _options;

        /// <summary>The consumer's store, remembered so <see cref="ExpandHierarchy"/> can rebuild the
        /// chain around it.</summary>
        private Type? _storeType;

        private bool _expandHierarchy;

        private bool _policiesAdded;

        internal PermissionAuthorizationBuilder(IServiceCollection services, PermissionAuthorizationOptions options)
        {
            _services = services;
            _options = options;
        }

        /// <summary>
        /// The container being configured. For packages that add their own store or catalog to the
        /// chain (kdyf.Authorization.EntityFrameworkCore's <c>AddEfStore</c>, for one) and need
        /// to register what that store depends on.
        /// </summary>
        public IServiceCollection Services => _services;

        /// <summary>
        /// Registers the consumer's permission store, wrapped in the caching decorator.
        /// </summary>
        public PermissionAuthorizationBuilder AddStore<TStore>()
            where TStore : class, IPermissionStore
        {
            _storeType = typeof(TStore);
            _services.AddScoped<TStore>();

            RegisterStoreChain();

            return this;
        }

        /// <summary>
        /// Takes a person's permissions from the access group and the roles administrators give them. Four
        /// sources, four owners: an <see cref="IMembershipSource"/> says who may use the application at all (the
        /// directory group); an <see cref="IUserRoleSource"/> says who holds which role, and an
        /// <see cref="IRolePermissionSource"/> which roles exist and what each grants (both configured by the
        /// application's administrators, e.g. <c>auth.UserRole</c>, <c>auth.Role</c>, <c>auth.RolePermission</c>);
        /// the <see cref="PermissionDefinition"/>s declared in <paramref name="declarations"/> say which
        /// permissions exist. Register the three sources separately.
        /// </summary>
        /// <remarks>
        /// Registers the <see cref="DeclaredPermissions"/> (also as the <see cref="IPermissionCatalog"/>), the
        /// <see cref="RolePermissionMapProvider"/>, and <see cref="MembershipPermissionStore"/> as the store
        /// (cached). Nodes are expanded by the map itself, so <see cref="ExpandHierarchy"/> is not needed.
        /// </remarks>
        public PermissionAuthorizationBuilder AddAssignedRoles(Assembly declarations)
        {
            ArgumentNullException.ThrowIfNull(declarations);
            return AddAssignedRoles([declarations]);
        }

        /// <summary>
        /// <see cref="AddAssignedRoles(Assembly)"/> over the permissions declared in several assemblies — one per
        /// module that owns permissions — as ONE catalog.
        /// </summary>
        /// <remarks>
        /// A code declared in two of them stops the host at registration: which module owns a permission is not
        /// a question to leave to the order of the assemblies.
        /// </remarks>
        public PermissionAuthorizationBuilder AddAssignedRoles(IEnumerable<Assembly> declarations)
        {
            ArgumentNullException.ThrowIfNull(declarations);

            // Discovered HERE, not lazily: two classes claiming one code stop the host at registration.
            var permissions = DiscoverAcross(declarations, PermissionDefinition.DiscoverIn, p => p.Code, "permission code");

            // The tree is completed here, once: everything that reads the catalog — the role map, the administration,
            // the catalog sync, the legacy import — reads this DeclaredPermissions, so none of them can disagree about
            // which nodes exist.
            var declared = new DeclaredPermissions(permissions);

            // What every member holds must be declared leaves: a typo would silently lock everybody out, and a node
            // would hand everything below it to the whole group.
            var wrong = _options.MemberPermissionCodes
                .Where(code => !declared.IsExplicit(code)
                               || declared.Codes.Any(other => other.StartsWith(code + PermissionHierarchy.Separator, StringComparison.Ordinal)))
                .OrderBy(code => code, StringComparer.Ordinal)
                .ToList();
            if (wrong.Count > 0)
                throw new InvalidOperationException(
                    $"MemberPermissionCodes must be declared permissions with nothing below them: {string.Join(", ", wrong)}.");

            _services.AddSingleton(declared);
            _services.RemoveAll<IPermissionCatalog>();
            _services.AddSingleton<IPermissionCatalog>(declared);
            _services.AddSingleton<RolePermissionMapProvider>();

            // Reports, at startup, configured codes this version no longer declares. It only warns.
            _services.AddSingleton<IHostedService, RolePermissionStartupCheck>();

            return AddStore<MembershipPermissionStore>();
        }

        /// <summary>
        /// Registers the catalog of valid permissions, used by the startup validation and — when
        /// <see cref="ExpandHierarchy"/> is on — to expand the nodes a role grants.
        /// </summary>
        public PermissionAuthorizationBuilder AddCatalog<TCatalog>()
            where TCatalog : class, IPermissionCatalog
        {
            _services.AddScoped<IPermissionCatalog, TCatalog>();
            return this;
        }

        /// <summary>
        /// Registers every <see cref="Policy"/> declared in <paramref name="assembly"/> as a real
        /// named policy.
        /// </summary>
        /// <remarks>
        /// <para>
        /// A registered policy WINS over the code parsing — <see cref="PermissionPolicyProvider"/>
        /// asks the default provider first. So this adds a second, richer vocabulary at the door
        /// without invalidating the first: everything that names a permission code keeps working
        /// exactly as before, and the two cannot collide as long as policy names are not codes.
        /// </para>
        /// <para>
        /// The schemes come from <c>AuthenticationSchemes</c>, so a declared policy cannot forget
        /// them — the failure that would cause (a whole class of client silently anonymous, hence
        /// always 403) is too quiet to leave to each declaration.
        /// </para>
        /// </remarks>
        /// <param name="assembly">The assembly whose <c>Policy</c> subclasses are registered.</param>
        /// <param name="shortcuts">
        /// Optional: a static class holding one field per policy, for naming them in an endpoint.
        /// Every field is checked against what was actually registered.
        /// </param>
        public PermissionAuthorizationBuilder AddPolicies(Assembly assembly, Type? shortcuts = null)
        {
            ArgumentNullException.ThrowIfNull(assembly);
            return AddPolicies([assembly], shortcuts is null ? [] : [shortcuts]);
        }

        /// <summary>
        /// <see cref="AddPolicies(Assembly, Type?)"/> over the policies declared in several assemblies — one per
        /// module that owns doors — as ONE catalog, with each module's shortcut class checked.
        /// </summary>
        /// <remarks>
        /// A policy name declared in two of them stops the host at registration: two policies answering to one
        /// name would leave the door guarded by whichever registered last.
        /// </remarks>
        public PermissionAuthorizationBuilder AddPolicies(IEnumerable<Assembly> assemblies, IEnumerable<Type> shortcuts)
        {
            ArgumentNullException.ThrowIfNull(assemblies);
            ArgumentNullException.ThrowIfNull(shortcuts);

            // One catalog. A second call would silently replace the first one's: every assembly goes in one call.
            if (_policiesAdded)
                throw new InvalidOperationException("AddPolicies may be called once. Pass every assembly that declares policies to that one call.");
            _policiesAdded = true;

            var policies = DiscoverAcross(assemblies, Policy.DiscoverIn, p => p.Name, "policy name");
            var schemes = _options.AuthenticationSchemes;

            // Kept because ASP.NET Core cannot enumerate its registered policies. See PolicyCatalog.
            _services.AddSingleton(new PolicyCatalog(policies));

            // Door by door, for menus: the host exposes it where it wants (see PolicyReport).
            _services.AddScoped<PolicyReport>();

            _services.Configure<AuthorizationOptions>(authorization =>
            {
                foreach (var policy in policies)
                    authorization.AddPolicy(policy.Name, policy.Build(schemes));
            });

            foreach (var shortcut in shortcuts)
                VerifyShortcuts(shortcut, policies);

            return this;
        }

        /// <summary>
        /// What <paramref name="discover"/> finds in each assembly, as one list — refusing a key declared in more
        /// than one of them. Each assembly is still checked on its own by <paramref name="discover"/>.
        /// </summary>
        private static IReadOnlyList<T> DiscoverAcross<T>(
            IEnumerable<Assembly> assemblies, Func<Assembly, IReadOnlyList<T>> discover, Func<T, string> key, string what)
        {
            var found = assemblies
                .Distinct()
                .SelectMany(assembly => discover(assembly).Select(item => (Assembly: assembly, Item: item)))
                .ToList();

            // Case-insensitive, as auth.Permission's key and the policy provider compare them.
            var duplicated = found
                .GroupBy(f => key(f.Item), StringComparer.OrdinalIgnoreCase)
                .Where(g => g.Select(f => f.Assembly).Distinct().Count() > 1)
                .Select(g => $"{g.Key} ({string.Join(", ", g.Select(f => f.Assembly.GetName().Name).Distinct())})")
                .OrderBy(text => text, StringComparer.Ordinal)
                .ToList();

            if (duplicated.Count > 0)
                throw new InvalidOperationException(
                    $"Each {what} belongs to one module, but these are declared in more than one assembly: {string.Join("; ", duplicated)}.");

            return found.Select(f => f.Item).ToList();
        }

        /// <summary>
        /// Checks that every policy the shortcut class names was really registered.
        /// </summary>
        /// <remarks>
        /// The failure this exists for is silent. A policy class that <see cref="Policy.DiscoverIn"/>
        /// skips — abstract, or without a public parameterless constructor — still compiles as a
        /// field here, and the door named after it then falls through to reading its NAME as a
        /// permission code: a 403 for everybody, with nothing said at startup.
        /// <para>
        /// Only this direction is checked. A policy without a shortcut works perfectly well; it just
        /// has to be written with <c>new</c>.
        /// </para>
        /// </remarks>
        private static void VerifyShortcuts(Type? shortcuts, IReadOnlyList<Policy> registered)
        {
            if (shortcuts is null)
                return;

            var names = registered.Select(p => p.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);

            var missing = shortcuts
                .GetFields(BindingFlags.Public | BindingFlags.Static)
                .Where(f => typeof(Policy).IsAssignableFrom(f.FieldType))
                .Select(f => new { f.Name, Policy = f.GetValue(null) as Policy })
                .Where(f => f.Policy is null || !names.Contains(f.Policy.Name))
                .Select(f => $"{shortcuts.Name}.{f.Name}")
                .OrderBy(name => name, StringComparer.Ordinal)
                .ToList();

            if (missing.Count > 0)
                throw new InvalidOperationException(
                    $"These policies are named but not registered: {string.Join(", ", missing)}. "
                    + "A policy class must be concrete and have a public parameterless constructor "
                    + $"to be found in {shortcuts.Assembly.GetName().Name}.");
        }

        /// <summary>
        /// Lets a role grant a node of the permission tree — <c>""</c> for everything, <c>prefix</c> for an area —
        /// instead of every code one by one. The nodes are expanded against the catalog before anything sees the
        /// set, so handlers, endpoints and clients keep comparing exact codes. Stored legacy wildcards
        /// (<c>*</c>, <c>prefix.*</c>) are read as the root and <c>prefix</c>.
        /// </summary>
        /// <remarks>
        /// Chain it AFTER <see cref="AddStore{TStore}"/> and <see cref="AddCatalog{TCatalog}"/> —
        /// both are checked here rather than at the first request, because the failure this prevents
        /// is an administrator silently losing their permissions, and the administration service then
        /// refusing every change because it counts no administrators left. A startup error is a far
        /// better place to find that out.
        /// </remarks>
        public PermissionAuthorizationBuilder ExpandHierarchy()
        {
            if (_storeType is null)
                throw new InvalidOperationException(
                    "ExpandHierarchy() has to be chained after AddStore<TStore>(): there is no store to wrap.");

            if (!_services.Any(d => d.ServiceType == typeof(IPermissionCatalog)))
                throw new InvalidOperationException(
                    "ExpandHierarchy() needs a permission catalog to expand the nodes against. "
                    + "Chain AddCatalog<TCatalog>() before it.");

            _expandHierarchy = true;
            RegisterStoreChain();

            return this;
        }

        /// <summary>The name of <see cref="ExpandHierarchy"/> before 1.2.0.</summary>
        [Obsolete("Use ExpandHierarchy(): wildcards are replaced by the permission hierarchy.")]
        public PermissionAuthorizationBuilder ExpandWildcards() => ExpandHierarchy();

        /// <summary>
        /// (Re)registers <see cref="IPermissionStore"/> as the full chain. Called again by
        /// <see cref="ExpandHierarchy"/>, so the previous registration is removed first — two
        /// registrations of one service would leave which decorator wins to registration order.
        /// </summary>
        private void RegisterStoreChain()
        {
            var storeType = _storeType!;
            var expand = _expandHierarchy;

            _services.RemoveAll<IPermissionStore>();
            _services.AddScoped<IPermissionStore>(sp =>
            {
                var store = (IPermissionStore)sp.GetRequiredService(storeType);

                if (expand)
                    store = new HierarchyExpandingPermissionStore(store, sp.GetRequiredService<IPermissionCatalog>());

                // The role map, when the store resolves through one: the cache must not outlive it.
                return new CachingPermissionStore(
                    store, sp.GetRequiredService<MemoryPermissionCache>(), sp.GetService<RolePermissionMapProvider>());
            });
        }
    }
}
