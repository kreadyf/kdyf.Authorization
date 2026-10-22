using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using kdyf.Authorization;
using kdyf.Authorization.Abstractions;
using kdyf.Authorization.Authorization;
using kdyf.Authorization.EntityFrameworkCore;
using kdyf.Authorization.EntityFrameworkCore.Entities;
using kdyf.Authorization.EntraId;
using kdyf.Authorization.Roles;
using kdyf.Authorization.Simulation;

namespace kdyf.Authorization.AspNetCore.Test;

/// <summary>
/// What AddKdyfAuthorization, with the EF Core store and Entra ID plugged in, reads from its section, what it refuses,
/// and what it registers — authorization only: the administration is composed on top by
/// kdyf.Authorization.Administration.AspNetCore, and tested there.
/// </summary>
/// <remarks>
/// A host's own tests run the whole pipeline; these cover the configuration contract: every key
/// reaching its place, every validation rule naming its key. Nothing here touches a database or Entra.
/// </remarks>
[TestClass]
public sealed class AddKdyfAuthorizationTests
{
    private const string Tenant = "11111111-1111-1111-1111-111111111111";
    private const string ApiClient = "22222222-2222-2222-2222-222222222222";
    private const string Group = "55555555-5555-5555-5555-555555555555";

    /// <summary>The minimum that starts: the five required keys.</summary>
    private static readonly Dictionary<string, string?> Minimal = new()
    {
        ["ConnectionStrings:Authorization"] = "Server=unused",
        ["EntraId:TenantId"] = Tenant,
        ["EntraId:ClientId"] = ApiClient,
        ["Directory:GroupId"] = Group,
        ["Directory:ClientSecret"] = "secret-1",
    };

    // ── Binding ──────────────────────────────────────────────────────────────

    [TestMethod]
    public void Every_key_reaches_its_place()
    {
        using var provider = Build(With(
            ("Schema", "security"),
            ("EntraId:Audience", "api://custom"),
            ("Authorization:CacheDuration", "00:10:00"),
            ("Authorization:EmptyResultCacheDuration", "00:00:45")));

        var store = provider.GetRequiredService<IOptions<AuthorizationStoreOptions>>().Value;
        Assert.AreEqual("Server=unused", store.ConnectionString);
        Assert.AreEqual("security", store.Schema);

        var entra = provider.GetRequiredService<IOptions<EntraIdAuthorizationOptions>>().Value;
        Assert.AreEqual(Tenant, entra.EntraId.TenantId);
        Assert.AreEqual("api://custom", entra.EntraId.Audience);

        var permissions = provider.GetRequiredService<PermissionAuthorizationOptions>();
        Assert.AreEqual(TimeSpan.FromMinutes(10), permissions.CacheDuration);
        Assert.AreEqual(TimeSpan.FromSeconds(45), permissions.EmptyResultCacheDuration);
    }

    /// <summary>Two minutes: the documented maximum time a change made in the Entra portal takes to apply.</summary>
    [TestMethod]
    public void The_defaults_apply_when_the_keys_are_left_out()
    {
        using var provider = Build(With());

        var store = provider.GetRequiredService<IOptions<AuthorizationStoreOptions>>().Value;
        Assert.AreEqual("auth", store.Schema);
        Assert.AreEqual("Authorization", store.ConnectionStringName);
        Assert.AreEqual("https://login.microsoftonline.com/", provider.GetRequiredService<IOptions<EntraIdAuthorizationOptions>>().Value.EntraId.Instance);

        var options = provider.GetRequiredService<IOptions<KdyfAuthorizationOptions>>().Value;
        Assert.AreEqual(TimeSpan.FromMinutes(2), options.Authorization.CacheDuration);
        Assert.AreEqual(TimeSpan.FromSeconds(30), options.Authorization.EmptyResultCacheDuration);
        Assert.AreEqual(TimeSpan.FromMinutes(2), provider.GetRequiredService<PermissionAuthorizationOptions>().CacheDuration);
    }

    /// <summary>A host keeps its own keys: the section and the connection string are its choice.</summary>
    [TestMethod]
    public void The_host_names_the_section_and_the_connection_string()
    {
        var values = Minimal
            .Where(v => !v.Key.StartsWith("ConnectionStrings:", StringComparison.Ordinal))
            .Select(v => new KeyValuePair<string, string?>($"HostAuth:{v.Key}", v.Value))
            .Append(new("HostAuth:ConnectionStringName", "HostDatabase"))
            .Append(new("ConnectionStrings:HostDatabase", "Server=host"));
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(values).Build();

        var services = new ServiceCollection().AddLogging();
        services.AddKdyfAuthorization(configuration, "HostAuth", auth => Providers(auth.Declarations(typeof(AddKdyfAuthorizationTests).Assembly)));
        using var provider = services.BuildServiceProvider();

        Assert.AreEqual("Server=host", provider.GetRequiredService<IOptions<AuthorizationStoreOptions>>().Value.ConnectionString);
        Assert.AreEqual(Group, provider.GetRequiredService<IOptions<EntraGraphOptions>>().Value.GroupId);
    }

    /// <summary>A host that always named its database in code keeps doing so: no ConnectionStringName key needed.</summary>
    [TestMethod]
    public void The_host_can_name_the_connection_string_in_code_and_the_key_still_wins()
    {
        static AuthorizationStoreOptions Store(Dictionary<string, string?> values)
        {
            var services = new ServiceCollection().AddLogging();
            services.AddKdyfAuthorization(Configuration(values), auth => auth
                .Declarations(typeof(AddKdyfAuthorizationTests).Assembly)
                .UseEntityFrameworkStore("HostDatabase", Sql)
                .UseEntraId());
            using var provider = services.BuildServiceProvider();
            return provider.GetRequiredService<IOptions<AuthorizationStoreOptions>>().Value;
        }

        var inCode = Store(With(("ConnectionStrings:HostDatabase", "Server=host")));
        Assert.AreEqual("HostDatabase", inCode.ConnectionStringName);
        Assert.AreEqual("Server=host", inCode.ConnectionString);

        var byKey = Store(With(("ConnectionStringName", "Other"), ("ConnectionStrings:Other", "Server=other")));
        Assert.AreEqual("Server=other", byKey.ConnectionString);
    }

    [TestMethod]
    public void The_context_maps_the_tables_to_the_configured_schema()
    {
        using var db = new AuthorizationDbContext(
            new DbContextOptionsBuilder<AuthorizationDbContext>().UseSqlServer("Server=unused").Options,
            Options.Create(new AuthorizationStoreOptions { Schema = "security" }));

        Assert.AreEqual("security", db.Model.FindEntityType(typeof(PersonalAccessToken))!.GetSchema());
        Assert.AreEqual("security", db.Model.FindEntityType(typeof(RolePermission))!.GetSchema());
        Assert.AreEqual("security", db.Model.FindEntityType(typeof(Role))!.GetSchema());
        Assert.AreEqual("security", db.Model.FindEntityType(typeof(UserRole))!.GetSchema());
        Assert.AreEqual("security", db.Model.FindEntityType(typeof(Permission))!.GetSchema());
        Assert.AreEqual("security", db.Model.FindEntityType(typeof(UserProfile))!.GetSchema());
        Assert.AreEqual(6, db.Model.GetEntityTypes().Count(),
            "the permission catalog, roles, what each grants, who holds which, tokens and the profiles (suspension, last access): "
            + "no audit log (administration's); who people are lives in Entra");
    }

    /// <summary>The context reaches the database through the provider the host chose, with the configured connection string.</summary>
    [TestMethod]
    public void The_context_uses_the_hosts_provider_and_connection_string()
    {
        using var provider = Build(With());
        using var scope = provider.CreateScope();

        var db = scope.ServiceProvider.GetRequiredService<AuthorizationDbContext>();
        Assert.AreEqual("Microsoft.EntityFrameworkCore.SqlServer", db.Database.ProviderName);
        // The server the host configured. Compared parsed: EF Core 10 normalises the string (Server → Data Source, plus an
        // Application Name) and EF Core 8 keeps it as given.
        Assert.AreEqual("unused", new Microsoft.Data.SqlClient.SqlConnectionStringBuilder(db.Database.GetConnectionString()).DataSource);
    }

    // ── Graph ────────────────────────────────────────────────────────────────

    /// <summary>The usual case: the group and the secret; the tenant and the client come from EntraId.</summary>
    [TestMethod]
    public void Graph_inherits_the_tenant_and_the_client_from_EntraId()
    {
        using var provider = Build(With());

        var graph = provider.GetRequiredService<IOptions<EntraGraphOptions>>().Value;
        Assert.AreEqual(Tenant, graph.TenantId);
        Assert.AreEqual(ApiClient, graph.ClientId);
        Assert.AreEqual("secret-1", graph.ClientSecret);
        Assert.AreEqual(Group, graph.GroupId);
        Assert.IsTrue(graph.IsConfigured);
    }

    [TestMethod]
    public void A_separate_Graph_credential_reads_the_same_group()
    {
        using var provider = Build(With(
            ("Directory:TenantId", "33333333-3333-3333-3333-333333333333"),
            ("Directory:ClientId", "44444444-4444-4444-4444-444444444444")));

        var graph = provider.GetRequiredService<IOptions<EntraGraphOptions>>().Value;
        Assert.AreEqual("33333333-3333-3333-3333-333333333333", graph.TenantId);
        Assert.AreEqual("44444444-4444-4444-4444-444444444444", graph.ClientId);
        Assert.AreEqual(Group, graph.GroupId);
    }

    // ── Validation ───────────────────────────────────────────────────────────

    [TestMethod]
    public void A_missing_connection_string_is_named_with_where_to_set_it()
    {
        var error = ValidationError(Without("ConnectionStrings:Authorization"));

        StringAssert.Contains(error, "ConnectionStrings:Authorization is missing");
        StringAssert.Contains(error, "dotnet user-secrets set");
        StringAssert.Contains(error, "KdyfAuthorization:ConnectionStringName");
    }

    /// <summary>
    /// The database is the application's connection string, in one place: a ConnectionString key inside the section
    /// is not read — not even as a fallback.
    /// </summary>
    [TestMethod]
    public void A_connection_string_inside_the_section_is_not_read()
    {
        var values = Without("ConnectionStrings:Authorization");
        values["ConnectionString"] = "Server=old";

        StringAssert.Contains(ValidationError(values), "ConnectionStrings:Authorization is missing");
    }

    /// <summary>Handed the section by habit, every key would be looked for one level too deep: named instead.</summary>
    [TestMethod]
    public void The_whole_configuration_is_expected_not_the_section()
    {
        var error = Assert.ThrowsException<ArgumentException>(() => new ServiceCollection().AddKdyfAuthorization(
            Configuration(With()).GetSection("KdyfAuthorization"), auth => Providers(auth.Declarations(typeof(AddKdyfAuthorizationTests).Assembly))));

        StringAssert.Contains(error.Message, "builder.Configuration");
        StringAssert.Contains(error.Message, "sectionName");
    }

    [TestMethod]
    public void A_missing_tenant_is_named() =>
        StringAssert.Contains(ValidationError(Without("EntraId:TenantId")), "KdyfAuthorization:EntraId:TenantId is missing");

    [TestMethod]
    public void A_tenant_that_is_not_a_guid_is_refused() =>
        StringAssert.Contains(ValidationError(With(("EntraId:TenantId", "tenant-1"))), "KdyfAuthorization:EntraId:TenantId");

    [TestMethod]
    public void A_missing_client_is_named() =>
        StringAssert.Contains(ValidationError(Without("EntraId:ClientId")), "KdyfAuthorization:EntraId:ClientId is missing");

    /// <summary>Without Graph nobody can be authorized: the host refuses to start rather than deny everyone.</summary>
    [TestMethod]
    public void A_missing_Graph_secret_is_named()
    {
        var error = ValidationError(Without("Directory:ClientSecret"));

        StringAssert.Contains(error, "KdyfAuthorization:Directory:ClientSecret is missing");
        StringAssert.Contains(error, "dotnet user-secrets set");
    }

    /// <summary>Without the group nobody can be let in: the host refuses to start rather than deny everyone.</summary>
    [TestMethod]
    public void A_missing_access_group_is_named() =>
        StringAssert.Contains(ValidationError(Without("Directory:GroupId")), "KdyfAuthorization:Directory:GroupId is missing");

    [TestMethod]
    public void An_access_group_that_is_not_a_guid_is_refused() =>
        StringAssert.Contains(ValidationError(With(("Directory:GroupId", "App users"))), "KdyfAuthorization:Directory:GroupId");

    [TestMethod]
    public void A_Graph_tenant_that_is_not_a_guid_is_refused() =>
        StringAssert.Contains(ValidationError(With(("Directory:TenantId", "x"))), "KdyfAuthorization:Directory:TenantId is not a GUID");

    [TestMethod]
    public void A_schema_that_is_not_a_sql_identifier_is_refused() =>
        StringAssert.Contains(ValidationError(With(("Schema", "auth; DROP TABLE x"))), "KdyfAuthorization:Schema");

    [TestMethod]
    public void A_cache_duration_that_is_not_positive_is_refused() =>
        StringAssert.Contains(ValidationError(With(("Authorization:CacheDuration", "00:00:00"))), "CacheDuration must be positive");

    /// <summary>The cache duration IS the propagation time of a revocation: past a limit it stops being one.</summary>
    [TestMethod]
    public void A_cache_duration_too_long_to_call_a_revocation_one_is_refused() =>
        StringAssert.Contains(ValidationError(With(("Authorization:CacheDuration", "01:00:00"))), "CacheDuration must not exceed");

    [TestMethod]
    public void An_empty_result_cached_longer_than_a_full_one_is_refused()
    {
        var error = ValidationError(With(
            ("Authorization:CacheDuration", "00:01:00"),
            ("Authorization:EmptyResultCacheDuration", "00:05:00")));

        StringAssert.Contains(error, "EmptyResultCacheDuration must not exceed CacheDuration");
    }

    /// <summary>The messages name the section the host chose, not the default one.</summary>
    [TestMethod]
    public void The_messages_name_the_hosts_section()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(
            Without("Directory:ClientSecret").Select(v => new KeyValuePair<string, string?>(
                v.Key.StartsWith("ConnectionStrings:", StringComparison.Ordinal) ? v.Key : $"HostAuth:{v.Key}", v.Value))).Build();
        var services = new ServiceCollection().AddLogging();
        services.AddKdyfAuthorization(configuration, "HostAuth", auth => Providers(auth.Declarations(typeof(AddKdyfAuthorizationTests).Assembly)));
        using var provider = services.BuildServiceProvider();

        var error = Assert.ThrowsException<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<EntraIdAuthorizationOptions>>().Value);
        StringAssert.Contains(error.Message, "HostAuth:Directory:ClientSecret is missing");
    }

    /// <summary>The point of ValidateOnStart: a host with a broken security configuration does not start.</summary>
    [TestMethod]
    public async Task A_host_with_a_broken_configuration_does_not_start()
    {
        foreach (var key in new[] { "Directory:ClientSecret", "ConnectionStrings:Authorization" })
        {
            using var host = new HostBuilder()
                .ConfigureServices(services => Register(services, Without(key)))
                .Build();

            var error = await Assert.ThrowsExceptionAsync<OptionsValidationException>(() => host.StartAsync());
            StringAssert.Contains(error.Message, key.StartsWith("ConnectionStrings:", StringComparison.Ordinal) ? $"{key} is missing" : $"KdyfAuthorization:{key} is missing");
        }
    }

    // ── Providers ────────────────────────────────────────────────────────────

    /// <summary>Without a store nothing says what roles grant: refused at registration, naming the call.</summary>
    [TestMethod]
    public void Without_a_store_the_host_does_not_register()
    {
        var error = Assert.ThrowsException<InvalidOperationException>(() => new ServiceCollection().AddLogging().AddKdyfAuthorization(
            Configuration(With()), auth => auth.Declarations(typeof(AddKdyfAuthorizationTests).Assembly).UseEntraId()));

        StringAssert.Contains(error.Message, ".UseEntityFrameworkStore(");
    }

    /// <summary>Without an identity provider nobody can sign in nor be let in: refused at registration, naming the call.</summary>
    [TestMethod]
    public void Without_an_identity_provider_the_host_does_not_register()
    {
        var error = Assert.ThrowsException<InvalidOperationException>(() => new ServiceCollection().AddLogging().AddKdyfAuthorization(
            Configuration(With()), auth => auth.Declarations(typeof(AddKdyfAuthorizationTests).Assembly).UseEntityFrameworkStore(Sql)));

        StringAssert.Contains(error.Message, ".UseEntraId()");
    }

    [TestMethod]
    public void A_provider_is_plugged_in_once()
    {
        var error = Assert.ThrowsException<InvalidOperationException>(() => new ServiceCollection().AddLogging().AddKdyfAuthorization(
            Configuration(With()), auth => Providers(auth.Declarations(typeof(AddKdyfAuthorizationTests).Assembly)).UseEntraId()));

        StringAssert.Contains(error.Message, ".UseEntraId(...) is called twice");
    }

    /// <summary>
    /// The composition knows no database and no identity provider: those are the packages the host references.
    /// </summary>
    [TestMethod]
    public void The_composition_references_no_provider()
    {
        var references = typeof(KdyfAuthorizationBuilder).Assembly.GetReferencedAssemblies().Select(a => a.Name!).ToList();

        foreach (var forbidden in new[]
        {
            "kdyf.Authorization.EntityFrameworkCore", "kdyf.Authorization.EntraId", "Microsoft.EntityFrameworkCore",
            "Microsoft.EntityFrameworkCore.SqlServer", "Microsoft.Identity.Web",
        })
            CollectionAssert.DoesNotContain(references, forbidden);
    }

    // ── Composition ──────────────────────────────────────────────────────────

    [TestMethod]
    public void The_whole_chain_is_registered()
    {
        var services = new ServiceCollection();
        Register(services, With());

        foreach (var type in new[]
        {
            typeof(IPermissionStore), typeof(IPermissionCatalog), typeof(IPatStore),
            typeof(RolePermissionMapProvider), typeof(IRolePermissionSource), typeof(IUserRoleSource), typeof(DeclaredPermissions),
            typeof(IMembershipSource), typeof(IUserContext), typeof(AuthorizationDbContext), typeof(PolicyReport),
        })
            Assert.IsTrue(services.Any(d => d.ServiceType == type), $"{type.Name} is not registered.");

        // The profiles (suspension, last access) are optional: the six tables are the whole schema until UserProfiles is on.
        foreach (var type in new[] { typeof(IUserSuspensionSource), typeof(IUserActivityRecorder) })
            Assert.IsFalse(services.Any(d => d.ServiceType == type), $"{type.Name} is registered without UserProfiles.");

        // First among the hosted services: the check of the schema's version, then the catalog sync, so nothing reads
        // auth.Permission before it is written, and nothing writes to a schema of another version.
        var hosted = services.Where(d => d.ServiceType == typeof(IHostedService)).Select(d => d.ImplementationType).Take(2).ToArray();
        Assert.AreEqual("SchemaVersionCheck`1", hosted[0]!.Name);
        Assert.AreEqual(typeof(PermissionCatalogSynchronizer<AuthorizationDbContext>), hosted[1]);
    }

    [TestMethod]
    public void The_profiles_are_registered_when_they_are_turned_on()
    {
        var services = new ServiceCollection();
        Register(services, With(("UserProfiles", "true")));

        foreach (var type in new[] { typeof(IUserSuspensionSource), typeof(IUserActivityRecorder) })
            Assert.IsTrue(services.Any(d => d.ServiceType == type), $"{type.Name} is not registered with UserProfiles.");
    }

    /// <summary>
    /// A host that only authorizes gets no administration: no service that changes access, no Graph with write
    /// permissions, no audit log, no administration doors. That is AddKdyfAuthorizationAdministration's.
    /// </summary>
    [TestMethod]
    public void Authorization_alone_registers_nothing_of_the_administration()
    {
        var services = new ServiceCollection();
        Register(services, With());

        var administration = services
            .Select(d => d.ServiceType.Assembly.GetName().Name ?? "")
            .Concat(services.Select(d => d.ImplementationType?.Assembly.GetName().Name ?? ""))
            .Where(name => name.StartsWith("kdyf.Authorization.Administration", StringComparison.Ordinal))
            .Distinct()
            .ToList();
        CollectionAssert.AreEqual(Array.Empty<string>(), administration);

        Assert.IsFalse(typeof(KdyfAuthorizationBuilder).Assembly.GetReferencedAssemblies()
            .Any(a => a.Name!.StartsWith("kdyf.Authorization.Administration", StringComparison.Ordinal)),
            "kdyf.Authorization.AspNetCore must not reference the administration: it composes authorization only");
    }

    /// <summary>
    /// The token's own 'roles' claim never authorizes a person: it is as old as the token, and a role
    /// revoked in Entra would keep working until it expires.
    /// </summary>
    [TestMethod]
    public void The_tokens_role_claims_do_not_authorize_people()
    {
        using var provider = Build(With());

        Assert.IsFalse(provider.GetRequiredService<PermissionAuthorizationOptions>().AcceptRoleClaimsForUserPrincipals);
    }

    [TestMethod]
    public void The_permission_store_reads_the_Entra_group_and_the_roles_in_the_database()
    {
        var services = new ServiceCollection();
        Register(services, With());

        Assert.IsTrue(services.Any(d => d.ServiceType == typeof(MembershipPermissionStore)));
        using var provider = Build(With());
        using var scope = provider.CreateScope();
        Assert.IsInstanceOfType<GraphMembershipSource>(scope.ServiceProvider.GetRequiredService<IMembershipSource>(), "the group, by default");
    }

    /// <summary>Directory:Gate picks who may use the application; the access group unless it says otherwise.</summary>
    [TestMethod]
    [DataRow("Group", typeof(GraphMembershipSource))]
    [DataRow("Migrating", typeof(MigratingMembershipSource))]
    [DataRow("AppAssignment", typeof(GraphAppAssignmentMembershipSource))]
    public void The_gate_picks_the_membership_source(string gate, Type expected)
    {
        using var provider = Build(With(
            ("Directory:Gate", gate),
            ("Directory:ServicePrincipalId", "66666666-6666-6666-6666-666666666666"),
            ("Directory:AccessAppRoleId", "77777777-7777-7777-7777-777777777777")));
        using var scope = provider.CreateScope();

        Assert.IsInstanceOfType(scope.ServiceProvider.GetRequiredService<IMembershipSource>(), expected);
        var graph = provider.GetRequiredService<IOptions<EntraGraphOptions>>().Value;
        Assert.AreEqual(Enum.Parse<AccessGate>(gate), graph.Gate);
        Assert.AreEqual("66666666-6666-6666-6666-666666666666", graph.ServicePrincipalId);
        Assert.AreEqual("77777777-7777-7777-7777-777777777777", graph.AccessAppRoleId);
    }

    /// <summary>What each gate needs (design, 7.5): without it the host does not start, and the message names the key.</summary>
    [TestMethod]
    [DataRow("Migrating", "Directory:ServicePrincipalId", null)]
    [DataRow("Migrating", "Directory:AccessAppRoleId", null)]
    [DataRow("Migrating", "Directory:GroupId", null)]
    [DataRow("AppAssignment", "Directory:ServicePrincipalId", "not-a-guid")]
    [DataRow("AppAssignment", "Directory:AccessAppRoleId", null)]
    [DataRow("Group", "Directory:GroupId", null)]
    public void Each_gate_needs_its_keys(string gate, string key, string? value)
    {
        var values = With(
            ("Directory:Gate", gate),
            ("Directory:ServicePrincipalId", "66666666-6666-6666-6666-666666666666"),
            ("Directory:AccessAppRoleId", "77777777-7777-7777-7777-777777777777"),
            (key, value));

        StringAssert.Contains(ValidationError(values), $"KdyfAuthorization:{key}");
    }

    /// <summary>With assignments only, the group is not needed.</summary>
    [TestMethod]
    public void The_assignment_gate_starts_without_a_group()
    {
        var values = With(
            ("Directory:Gate", "AppAssignment"),
            ("Directory:ServicePrincipalId", "66666666-6666-6666-6666-666666666666"),
            ("Directory:AccessAppRoleId", "77777777-7777-7777-7777-777777777777"));
        values.Remove("Directory:GroupId");

        using var provider = Build(values);
        Assert.AreEqual(AccessGate.AppAssignment, provider.GetRequiredService<IOptions<EntraIdAuthorizationOptions>>().Value.Directory.Gate);
    }

    /// <summary>A scheme missing from the fallback makes its tokens arrive anonymous: a permanent 401.</summary>
    [TestMethod]
    public void The_fallback_and_default_policies_demand_a_session_from_both_schemes()
    {
        using var provider = Build(With());
        var authorization = provider.GetRequiredService<IOptions<AuthorizationOptions>>().Value;

        foreach (var policy in new[] { authorization.FallbackPolicy!, authorization.DefaultPolicy })
        {
            CollectionAssert.AreEquivalent(new[] { "Bearer", "PAT" }, policy.AuthenticationSchemes.ToArray());
            Assert.IsTrue(policy.Requirements.OfType<Microsoft.AspNetCore.Authorization.Infrastructure.DenyAnonymousAuthorizationRequirement>().Any());
        }

        CollectionAssert.AreEquivalent(new[] { "Bearer", "PAT" }, provider.GetRequiredService<PermissionAuthorizationOptions>().AuthenticationSchemes);
    }

    /// <summary>
    /// A token proves an account of the tenant, not that the application lets it in: the fallback and the default
    /// policies demand the access gate too. The session policy does not, so who-am-I can tell somebody they have no access.
    /// </summary>
    [TestMethod]
    public void The_fallback_and_default_policies_demand_the_access_gate()
    {
        using var provider = Build(With());
        var authorization = provider.GetRequiredService<IOptions<AuthorizationOptions>>().Value;

        foreach (var policy in new[] { authorization.FallbackPolicy!, authorization.DefaultPolicy })
            CollectionAssert.Contains(policy.Requirements.ToArray(), AccessGateRequirement.Instance);

        var signedIn = authorization.GetPolicy(kdyf.Authorization.AspNetCore.KdyfAuthorizationPolicies.SignedIn)!;
        CollectionAssert.AreEquivalent(new[] { "Bearer", "PAT" }, signedIn.AuthenticationSchemes.ToArray());
        CollectionAssert.DoesNotContain(signedIn.Requirements.ToArray(), AccessGateRequirement.Instance);
        Assert.IsTrue(signedIn.Requirements.OfType<Microsoft.AspNetCore.Authorization.Infrastructure.DenyAnonymousAuthorizationRequirement>().Any());

        var services = new ServiceCollection();
        Register(services, With());
        Assert.IsTrue(services.Any(d => d.ServiceType == typeof(IAuthorizationHandler) && d.ImplementationType == typeof(AccessGateAuthorizationHandler)));
    }

    [TestMethod]
    public void SignedInIsEnough_leaves_the_gate_to_the_endpoints()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddKdyfAuthorization(Configuration(With()), auth => Providers(auth
            .Declarations(typeof(AddKdyfAuthorizationTests).Assembly)
            .SignedInIsEnough()));
        using var provider = services.BuildServiceProvider();
        var authorization = provider.GetRequiredService<IOptions<AuthorizationOptions>>().Value;

        foreach (var policy in new[] { authorization.FallbackPolicy!, authorization.DefaultPolicy })
        {
            CollectionAssert.DoesNotContain(policy.Requirements.ToArray(), AccessGateRequirement.Instance);
            Assert.IsTrue(policy.Requirements.OfType<Microsoft.AspNetCore.Authorization.Infrastructure.DenyAnonymousAuthorizationRequirement>().Any());
        }
    }

    /// <summary>
    /// The default scheme forwards by the Authorization header — "PAT …" to the PAT scheme, anything else to the
    /// identity provider's JWT — so the authentication middleware authenticates both kinds of caller.
    /// </summary>
    [TestMethod]
    public async Task The_default_scheme_picks_PAT_or_JWT_by_the_header()
    {
        using var provider = Build(With());
        var schemes = provider.GetRequiredService<Microsoft.AspNetCore.Authentication.IAuthenticationSchemeProvider>();
        var options = provider.GetRequiredService<IOptionsMonitor<Microsoft.AspNetCore.Authentication.PolicySchemeOptions>>()
            .Get(KdyfAuthorizationServiceCollectionExtensions.DefaultScheme);

        Assert.AreEqual(KdyfAuthorizationServiceCollectionExtensions.DefaultScheme, (await schemes.GetDefaultAuthenticateSchemeAsync())!.Name);

        string Pick(string? header)
        {
            var http = new Microsoft.AspNetCore.Http.DefaultHttpContext();
            if (header is not null)
                http.Request.Headers.Authorization = header;
            return options.ForwardDefaultSelector!(http)!;
        }

        Assert.AreEqual("PAT", Pick("PAT abc"));
        Assert.AreEqual("PAT", Pick("pat abc"));
        Assert.AreEqual("Bearer", Pick("Bearer eyJ..."));
        Assert.AreEqual("Bearer", Pick(null), "no header: the JWT scheme answers the challenge with 401");
    }

    [TestMethod]
    public void The_host_policies_are_registered()
    {
        using var provider = Build(With());
        var authorization = provider.GetRequiredService<IOptions<AuthorizationOptions>>().Value;

        Assert.IsNotNull(authorization.GetPolicy("TestAdministration"));
        Assert.IsNotNull(authorization.GetPolicy("TestTokens"));
    }

    // ── The builder ──────────────────────────────────────────────────────────

    [TestMethod]
    public void A_simulation_policy_that_demands_either_of_two_permissions_is_refused()
    {
        var error = Assert.ThrowsException<ArgumentException>(() => new ServiceCollection().AddKdyfAuthorizationSimulation(new authtest.EitherPolicy()));

        StringAssert.Contains(error.Message, "exactly one permission");
        StringAssert.Contains(error.Message, "authtest.Admin, authtest.Other");
    }

    /// <summary>What every member holds reaches the store's options.</summary>
    [TestMethod]
    public void What_every_member_holds_is_passed_on()
    {
        var services = new ServiceCollection().AddLogging();
        services.AddKdyfAuthorization(Configuration(With()), auth => Providers(auth
            .Declarations(typeof(AddKdyfAuthorizationTests).Assembly)
            .EveryMemberHolds(new authtest.BaseAccess())));
        using var provider = services.BuildServiceProvider();

        CollectionAssert.AreEqual(new[] { "Default" }, provider.GetRequiredService<PermissionAuthorizationOptions>().MemberPermissionCodes.ToArray());
    }

    /// <summary>Everybody in the group would hold everything the wildcard covers.</summary>
    [TestMethod]
    public void A_wildcard_is_never_what_every_member_holds() =>
        Assert.ThrowsException<ArgumentException>(() => new KdyfAuthorizationBuilder().EveryMemberHolds(new authtest.Everything()));

    /// <summary>A permission from another assembly is not declared here: every member would hold a code no door knows.</summary>
    [TestMethod]
    public void What_every_member_holds_must_be_declared()
    {
        var error = Assert.ThrowsException<InvalidOperationException>(() => new ServiceCollection().AddLogging().AddKdyfAuthorization(Configuration(With()), auth => Providers(auth
            .Declarations(typeof(AddKdyfAuthorizationTests).Assembly)
            .EveryMemberHolds(new kdyf.Authorization.AspNetCore.Test.Foreign.ElsewherePermission()))));

        StringAssert.Contains(error.Message, "MemberPermissionCodes");
    }

    [TestMethod]
    public void Without_a_simulation_policy_there_is_no_simulation()
    {
        using var provider = Build(With());

        Assert.IsNull(provider.GetService<UserSimulationOptions>());
    }

    /// <summary>Read-only is not a setting: writing as somebody else lands changes in their name.</summary>
    [TestMethod]
    public void Simulation_is_read_only_and_checks_the_policys_permission_on_the_real_caller()
    {
        var services = new ServiceCollection().AddLogging();
        services.AddKdyfAuthorization(Configuration(With()), auth => Providers(auth.Declarations(typeof(AddKdyfAuthorizationTests).Assembly)));
        services.AddKdyfAuthorizationSimulation(new authtest.SimulationPolicy());
        using var provider = services.BuildServiceProvider();

        var simulation = provider.GetRequiredService<UserSimulationOptions>();
        Assert.AreEqual("authtest.Simulate", simulation.RequiredPermission);
        Assert.IsTrue(simulation.ReadOnly);
        Assert.AreEqual("TestSimulation", simulation.PolicyName, "the door of the simulation endpoints");
    }

    /// <summary>
    /// A host's own claims transformation (a legacy host's directory roles) is kept, and runs on the principal the simulation
    /// produced: registered beside it, one of the two would silently win.
    /// </summary>
    [TestMethod]
    public async Task A_hosts_claims_transformation_runs_after_the_simulation()
    {
        var services = new ServiceCollection().AddLogging().AddHttpContextAccessor();
        services.AddKdyfAuthorization(Configuration(With()), auth => Providers(auth.Declarations(typeof(AddKdyfAuthorizationTests).Assembly)));
        services.AddKdyfAuthorizationSimulation<MarkingTransformation>(new authtest.SimulationPolicy());
        using var provider = services.BuildServiceProvider();
        provider.GetRequiredService<Microsoft.AspNetCore.Http.IHttpContextAccessor>().HttpContext = new Microsoft.AspNetCore.Http.DefaultHttpContext();

        var transformation = provider.GetRequiredService<Microsoft.AspNetCore.Authentication.IClaimsTransformation>();
        var principal = await transformation.TransformAsync(new System.Security.Claims.ClaimsPrincipal(new System.Security.Claims.ClaimsIdentity(
            new[] { new System.Security.Claims.Claim("oid", "0a000000-0000-0000-0000-00000000000a") }, "test")));

        Assert.AreEqual("SimulationClaimsTransformation", transformation.GetType().Name);
        Assert.IsTrue(principal.HasClaim("marked", "yes"), "the host's transformation ran");
        Assert.IsNotNull(provider.GetService<UserSimulationOptions>());
    }

    private sealed class MarkingTransformation : Microsoft.AspNetCore.Authentication.IClaimsTransformation
    {
        public Task<System.Security.Claims.ClaimsPrincipal> TransformAsync(System.Security.Claims.ClaimsPrincipal principal)
        {
            ((System.Security.Claims.ClaimsIdentity)principal.Identity!).AddClaim(new System.Security.Claims.Claim("marked", "yes"));
            return Task.FromResult(principal);
        }
    }

    /// <summary>Without a Simulation part the defaults apply: the header and the timeout clients already use.</summary>
    [TestMethod]
    public void Simulation_defaults_apply_when_the_section_says_nothing()
    {
        var simulation = SimulationOptions(With());

        Assert.AreEqual("X-Simulate-User", simulation.HeaderName);
        Assert.AreEqual("simulated_by", simulation.SimulatedByClaimType);
        Assert.AreEqual("simulated_by_oid", simulation.SimulatedByObjectIdClaimType);
        Assert.AreEqual(TimeSpan.FromMinutes(30), simulation.SessionIdleTimeout);
        Assert.AreEqual(8, simulation.CandidatesMaxConcurrency);
    }

    [TestMethod]
    public void Every_simulation_key_reaches_its_place_but_read_only_and_the_permission_never_do()
    {
        var simulation = SimulationOptions(With(
            ("Simulation:HeaderName", "X-Act-As"),
            ("Simulation:SimulatedByClaimType", "acting_by"),
            ("Simulation:SimulatedByObjectIdClaimType", "acting_by_oid"),
            ("Simulation:SessionIdleTimeout", "00:10:00"),
            ("Simulation:CandidatesMaxConcurrency", "4"),
            ("Simulation:ReadOnly", "false"),
            ("Simulation:RequiredPermission", "Default")));

        Assert.AreEqual("X-Act-As", simulation.HeaderName);
        Assert.AreEqual("acting_by", simulation.SimulatedByClaimType);
        Assert.AreEqual("acting_by_oid", simulation.SimulatedByObjectIdClaimType);
        Assert.AreEqual(TimeSpan.FromMinutes(10), simulation.SessionIdleTimeout);
        Assert.AreEqual(4, simulation.CandidatesMaxConcurrency);
        Assert.IsTrue(simulation.ReadOnly, "never from a file");
        Assert.AreEqual("authtest.Simulate", simulation.RequiredPermission, "never from a file");
    }

    /// <summary>Values that would open a hole, or make no sense, stop the registration with the key named.</summary>
    [TestMethod]
    [DataRow("Simulation:HeaderName", "Authorization", "HeaderName")]
    [DataRow("Simulation:HeaderName", "X-Forwarded-User", "HeaderName")]
    [DataRow("Simulation:HeaderName", "X Simulate", "HeaderName")]
    [DataRow("Simulation:SimulatedByClaimType", "oid", "SimulatedByClaimType")]
    [DataRow("Simulation:SimulatedByObjectIdClaimType", "simulated_by", "different")]
    [DataRow("Simulation:SessionIdleTimeout", "00:00:10", "SessionIdleTimeout")]
    [DataRow("Simulation:SessionIdleTimeout", "09:00:00", "SessionIdleTimeout")]
    [DataRow("Simulation:CandidatesMaxConcurrency", "0", "CandidatesMaxConcurrency")]
    [DataRow("Simulation:CandidatesMaxConcurrency", "33", "CandidatesMaxConcurrency")]
    public void A_simulation_value_that_opens_a_hole_is_refused(string key, string value, string named)
    {
        var error = Assert.ThrowsException<InvalidOperationException>(() => SimulationOptions(With((key, value))));

        StringAssert.Contains(error.Message, named);
    }

    private static UserSimulationOptions SimulationOptions(Dictionary<string, string?> values)
    {
        var services = new ServiceCollection().AddLogging();
        services.AddKdyfAuthorization(Configuration(values), auth => Providers(auth.Declarations(typeof(AddKdyfAuthorizationTests).Assembly)));
        services.AddKdyfAuthorizationSimulation(new authtest.SimulationPolicy());
        using var provider = services.BuildServiceProvider();
        return provider.GetRequiredService<UserSimulationOptions>();
    }

    [TestMethod]
    public void Each_missing_decision_is_named_at_registration()
    {
        var section = Configuration(With());

        var noDeclarations = Assert.ThrowsException<InvalidOperationException>(() => new ServiceCollection().AddKdyfAuthorization(section, _ => { }));
        StringAssert.Contains(noDeclarations.Message, ".Declarations(");
    }

    /// <summary>Simulation is switched on on top of authorization, once — by whoever owns the feature.</summary>
    [TestMethod]
    public void Simulation_needs_AddKdyfAuthorization_first_and_is_switched_on_once()
    {
        var alone = Assert.ThrowsException<InvalidOperationException>(() =>
            new ServiceCollection().AddKdyfAuthorizationSimulation(new authtest.SimulationPolicy()));
        StringAssert.Contains(alone.Message, "AddKdyfAuthorization(");

        var services = new ServiceCollection().AddLogging();
        services.AddKdyfAuthorization(Configuration(With()), auth => Providers(auth.Declarations(typeof(AddKdyfAuthorizationTests).Assembly)));
        services.AddKdyfAuthorizationSimulation(new authtest.SimulationPolicy());

        var twice = Assert.ThrowsException<InvalidOperationException>(() => services.AddKdyfAuthorizationSimulation(new authtest.SimulationPolicy()));
        StringAssert.Contains(twice.Message, "once");
    }

    /// <summary>Several assemblies declaring permissions and policies make ONE catalog.</summary>
    [TestMethod]
    public void Declarations_from_several_assemblies_make_one_catalog()
    {
        var services = new ServiceCollection().AddLogging();
        services.AddKdyfAuthorization(Configuration(With()), auth => Providers(auth
            .Declarations(typeof(AddKdyfAuthorizationTests).Assembly)
            .Declarations(typeof(kdyf.Authorization.Abstractions.PermissionDefinition).Assembly)));
        using var provider = services.BuildServiceProvider();

        CollectionAssert.Contains(provider.GetRequiredService<kdyf.Authorization.Roles.DeclaredPermissions>().Codes.ToArray(), "authtest.Admin");
    }

    // ── The permission tree ──────────────────────────────────────────────────

    /// <summary>The catalog every reader shares: the area's node and the root exist without a class.</summary>
    [TestMethod]
    public void The_catalog_holds_every_node_of_the_tree()
    {
        using var provider = Build(With());

        var declared = provider.GetRequiredService<kdyf.Authorization.Roles.DeclaredPermissions>();
        Assert.IsInstanceOfType(declared.Find("authtest"), typeof(PermissionNode));
        Assert.IsInstanceOfType(declared.Find(PermissionHierarchy.Root), typeof(PermissionNode));
        Assert.AreSame(declared, provider.GetRequiredService<IPermissionCatalog>(), "the catalog the role map expands against");
    }

    /// <summary>A wildcard class left over from 1.1.0 is not part of the catalog: the node stands for its area.</summary>
    [TestMethod]
    public void A_wildcard_class_is_left_out_of_the_catalog()
    {
        using var provider = Build(With());

        var declared = provider.GetRequiredService<kdyf.Authorization.Roles.DeclaredPermissions>();
        Assert.IsNull(declared.Find("*"));
        CollectionAssert.Contains(declared.IgnoredWildcards.ToArray(), "*");
    }

#pragma warning disable CS0618 // AreaWildcards() is obsolete: what is tested is that it changes nothing.
    /// <summary>A host that still calls AreaWildcards compiles and gets the same catalog: the call has no effect.</summary>
    [TestMethod]
    public void AreaWildcards_changes_nothing()
    {
        using var with = BuildWith(auth => auth.AreaWildcards(except: "Whatever"));
        using var without = Build(With());

        CollectionAssert.AreEqual(
            without.GetRequiredService<kdyf.Authorization.Roles.DeclaredPermissions>().Codes.Order().ToArray(),
            with.GetRequiredService<kdyf.Authorization.Roles.DeclaredPermissions>().Codes.Order().ToArray());
        Assert.IsNull(with.GetRequiredService<kdyf.Authorization.Roles.DeclaredPermissions>().Find("authtest.*"));
    }
#pragma warning restore CS0618

    /// <summary>The rows are written from the catalog authorization reads, so the implicit nodes get their rows too.</summary>
    [TestMethod]
    public void The_catalog_sync_writes_from_the_declared_permissions()
    {
        using var provider = Build(With());

        Assert.IsTrue(provider.GetRequiredService<PermissionCatalogSyncOptions>().FromDeclaredPermissions);
    }

    private static ServiceProvider BuildWith(Func<KdyfAuthorizationBuilder, KdyfAuthorizationBuilder> decide)
    {
        var services = new ServiceCollection().AddLogging();
        services.AddKdyfAuthorization(Configuration(With()), auth => Providers(decide(auth
            .Declarations(typeof(AddKdyfAuthorizationTests).Assembly))));
        return services.BuildServiceProvider();
    }

    // ── Plumbing ─────────────────────────────────────────────────────────────

    /// <summary>The provider the tests plug in: SQL Server, never connected to.</summary>
    private static void Sql(DbContextOptionsBuilder db, string connectionString) => db.UseSqlServer(connectionString);

    /// <summary>The providers a host plugs in: the EF Core store and Entra ID.</summary>
    private static KdyfAuthorizationBuilder Providers(KdyfAuthorizationBuilder auth) =>
        auth.UseEntityFrameworkStore(Sql).UseEntraId();

    private static Dictionary<string, string?> With(params (string Key, string? Value)[] extra)
    {
        var values = new Dictionary<string, string?>(Minimal);
        foreach (var (key, value) in extra)
            values[key] = value;
        return values;
    }

    private static Dictionary<string, string?> Without(string key)
    {
        var values = new Dictionary<string, string?>(Minimal);
        values.Remove(key);
        return values;
    }

    /// <summary>The host's configuration: the keys above are relative to KdyfAuthorization, the connection strings its own.</summary>
    private static IConfiguration Configuration(Dictionary<string, string?> values) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(values.Select(v => new KeyValuePair<string, string?>(
                v.Key.StartsWith("ConnectionStrings:", StringComparison.Ordinal) ? v.Key : $"KdyfAuthorization:{v.Key}", v.Value)))
            .Build();

    private static void Register(IServiceCollection services, Dictionary<string, string?> values)
    {
        services.AddLogging();
        services.AddKdyfAuthorization(Configuration(values), auth => Providers(auth
            .Declarations(typeof(AddKdyfAuthorizationTests).Assembly)));
    }

    private static ServiceProvider Build(Dictionary<string, string?> values)
    {
        var services = new ServiceCollection();
        Register(services, values);
        return services.BuildServiceProvider();
    }

    /// <summary>The validation messages for these values, from every part of the section: reading the options runs the validators.</summary>
    private static string ValidationError(Dictionary<string, string?> values)
    {
        using var provider = Build(values);
        var messages = new List<string>();

        void Read<T>() where T : class
        {
            try
            {
                _ = provider.GetRequiredService<IOptions<T>>().Value;
            }
            catch (OptionsValidationException error)
            {
                messages.Add(error.Message);
            }
        }

        Read<KdyfAuthorizationOptions>();
        Read<AuthorizationStoreOptions>();
        Read<EntraIdAuthorizationOptions>();

        Assert.AreNotEqual(0, messages.Count, "the configuration was expected to be refused");
        return string.Join(Environment.NewLine, messages);
    }
}
