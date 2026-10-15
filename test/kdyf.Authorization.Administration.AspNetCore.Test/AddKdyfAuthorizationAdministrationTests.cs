using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using kdyf.Authorization.Administration;
using kdyf.Authorization.Administration.Abstractions;
using kdyf.Authorization.Administration.AspNetCore;
using kdyf.Authorization.Administration.EntraId;
using kdyf.Authorization.Administration.Persistence;
using kdyf.Authorization.AspNetCore;
using kdyf.Authorization;
using kdyf.Authorization.Abstractions;
using kdyf.Authorization.EntityFrameworkCore;
using kdyf.Authorization.EntityFrameworkCore.Entities;
using kdyf.Authorization.EntraId;

namespace kdyf.Authorization.Administration.AspNetCore.Test;

/// <summary>
/// What AddKdyfAuthorizationAdministration adds on top of AddKdyfAuthorization: the administration services, their context with the
/// audit log, the doors under AccessPolicyNames and the code the lockout guard counts. Nothing here touches a
/// database or Entra.
/// </summary>
[TestClass]
public sealed class AddKdyfAuthorizationAdministrationTests
{
    private static readonly Dictionary<string, string?> Minimal = new()
    {
        ["ConnectionStrings:Authorization"] = "Server=unused",
        ["EntraId:TenantId"] = "11111111-1111-1111-1111-111111111111",
        ["EntraId:ClientId"] = "22222222-2222-2222-2222-222222222222",
        ["Directory:GroupId"] = "55555555-5555-5555-5555-555555555555",
        ["Directory:ClientSecret"] = "secret-1",
    };

    [TestMethod]
    public void The_administration_is_registered_on_top_of_authorization()
    {
        var services = Register();

        foreach (var type in new[]
        {
            typeof(IAccessDirectory), typeof(IDirectoryService),
            typeof(IAccessAdminService), typeof(IPatAdminService), typeof(IDirectoryAdminService), typeof(IAuditAdminService),
            typeof(IAuditLog), typeof(IAccessChangeNotifier), typeof(AdministrationDbContext), typeof(IAdminActorAccessor),
            typeof(AuthorizationDbContext), typeof(IPermissionStore),
        })
            Assert.IsTrue(services.Any(d => d.ServiceType == type), $"{type.Name} is not registered.");

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();
        Assert.IsInstanceOfType<GraphAccessGroupDirectory>(scope.ServiceProvider.GetRequiredService<IAccessDirectory>(), "the group, by default");
    }

    /// <summary>Directory:Gate picks what the administration writes: the group, or the assignments.</summary>
    [TestMethod]
    public void With_the_assignment_gate_access_is_given_by_assigning_the_application()
    {
        using var provider = Register(
                ("Directory:Gate", "AppAssignment"),
                ("Directory:ServicePrincipalId", "66666666-6666-6666-6666-666666666666"),
                ("Directory:AccessAppRoleId", "77777777-7777-7777-7777-777777777777"))
            .BuildServiceProvider();
        using var scope = provider.CreateScope();

        Assert.IsInstanceOfType<GraphAccessAssignmentDirectory>(scope.ServiceProvider.GetRequiredService<IAccessDirectory>());
    }

    /// <summary>With the migration package, a migrating host starts and the administration writes to both.</summary>
    [TestMethod]
    public void Migrating_with_the_migration_package_writes_to_the_group_and_the_assignments()
    {
        var services = Register(
            ("Directory:Gate", "Migrating"),
            ("Directory:ServicePrincipalId", "66666666-6666-6666-6666-666666666666"),
            ("Directory:AccessAppRoleId", "77777777-7777-7777-7777-777777777777"));
        services.AddKdyfAuthorizationGateMigration();
        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();

        Assert.AreEqual(kdyf.Authorization.EntraId.AccessGate.Migrating,
            provider.GetRequiredService<IOptions<kdyf.Authorization.EntraId.EntraIdAuthorizationOptions>>().Value.Directory.Gate);
        Assert.IsInstanceOfType<kdyf.Authorization.EntraId.Migration.DualWriteAccessDirectory>(scope.ServiceProvider.GetRequiredService<IAccessDirectory>());
        Assert.IsTrue(services.Any(d => d.ImplementationType?.Name == "GateMigrationService"), "the sync runs in this host");
    }

    [TestMethod]
    public void The_migration_needs_the_administration_first()
    {
        var error = Assert.ThrowsException<InvalidOperationException>(() => new ServiceCollection().AddKdyfAuthorizationGateMigration());

        StringAssert.Contains(error.Message, "AddKdyfAuthorizationAdministration");
    }

    /// <summary>Migrating without the migration package would change the group and leave the assignments behind.</summary>
    [TestMethod]
    public void Migrating_without_the_migration_package_does_not_start()
    {
        using var provider = Register(
                ("Directory:Gate", "Migrating"),
                ("Directory:ServicePrincipalId", "66666666-6666-6666-6666-666666666666"),
                ("Directory:AccessAppRoleId", "77777777-7777-7777-7777-777777777777"))
            .BuildServiceProvider();

        var error = Assert.ThrowsException<OptionsValidationException>(() =>
            provider.GetRequiredService<IOptions<kdyf.Authorization.EntraId.EntraIdAuthorizationOptions>>().Value);
        StringAssert.Contains(error.Message, "kdyf.Authorization.Migrations");
    }

    /// <summary>One value for two jobs: the door of the administration and the code the lockout guard counts.</summary>
    [TestMethod]
    public void The_administration_policy_names_the_code_the_lockout_guard_counts()
    {
        using var provider = Register().BuildServiceProvider();

        Assert.AreEqual("admintest.Admin", provider.GetRequiredService<PermissionAuthorizationOptions>().AdministrationPermissionCode);
    }

    /// <summary>The fixed names the administration's controllers name, with the host's requirements and both schemes.</summary>
    [TestMethod]
    public void The_doors_are_registered_under_their_fixed_names()
    {
        using var provider = Register().BuildServiceProvider();
        var authorization = provider.GetRequiredService<IOptions<AuthorizationOptions>>().Value;

        foreach (var name in new[] { AccessPolicyNames.Administration, AccessPolicyNames.PersonalAccessTokens })
        {
            var policy = authorization.GetPolicy(name);
            Assert.IsNotNull(policy, name);
            CollectionAssert.AreEquivalent(new[] { "Bearer", "PAT" }, policy.AuthenticationSchemes.ToArray(), name);
        }
    }

    [TestMethod]
    public void The_invitation_settings_reach_the_directory()
    {
        using var provider = Register(("Directory:InviteRedirectUrl", "https://app.test/"), ("Directory:SendInvitationMessage", "false"))
            .BuildServiceProvider();

        var directory = provider.GetRequiredService<IOptions<GraphDirectoryOptions>>().Value;
        Assert.AreEqual("https://app.test/", directory.InviteRedirectUrl);
        Assert.IsFalse(directory.SendInvitationMessage);
    }

    /// <summary>A change and its audit entry in one transaction: both models on the administration's context.</summary>
    [TestMethod]
    public void The_administration_context_maps_the_authorization_tables_and_the_audit_log()
    {
        using var db = new AdministrationDbContext(
            new DbContextOptionsBuilder<AdministrationDbContext>().UseSqlServer("Server=unused").Options,
            Options.Create(new AuthorizationStoreOptions { Schema = "security" }));

        foreach (var entity in new[] { typeof(AuditLogEntry), typeof(PersonalAccessToken), typeof(Role), typeof(RolePermission), typeof(UserRole), typeof(Permission) })
            Assert.AreEqual("security", db.Model.FindEntityType(entity)!.GetSchema(), entity.Name);
        Assert.AreEqual(6, db.Model.GetEntityTypes().Count());
    }

    /// <summary>With administration, a simulation is recorded in the audit log — whatever order the two calls came in.</summary>
    [TestMethod]
    public void Simulations_are_recorded_in_the_audit_log()
    {
        var services = Register(simulation: true);

        Assert.AreEqual(typeof(AuditSimulationRecorder<AdministrationDbContext>),
            services.Single(d => d.ServiceType == typeof(ISimulationRecorder)).ImplementationType);
    }

    [TestMethod]
    public void A_policy_that_demands_either_of_two_permissions_cannot_administer()
    {
        var error = Assert.ThrowsException<ArgumentException>(() => new KdyfAuthorizationAdministrationBuilder().AdministeredBy(new admintest.EitherPolicy()));

        StringAssert.Contains(error.Message, "exactly one permission");
        StringAssert.Contains(error.Message, "admintest.Admin, admintest.Other");
    }

    [TestMethod]
    public void A_policy_that_demands_nothing_cannot_administer() =>
        Assert.ThrowsException<ArgumentException>(() => new KdyfAuthorizationAdministrationBuilder().AdministeredBy(new admintest.SessionOnlyPolicy()));

    [TestMethod]
    public void Each_missing_decision_is_named_at_registration()
    {
        var noAdministration = Assert.ThrowsException<InvalidOperationException>(() =>
            Authorization().AddKdyfAuthorizationAdministration(admin => admin.TokensManagedBy(new admintest.TokensPolicy())));
        StringAssert.Contains(noAdministration.Message, ".AdministeredBy(");

        var noTokens = Assert.ThrowsException<InvalidOperationException>(() =>
            Authorization().AddKdyfAuthorizationAdministration(admin => admin.AdministeredBy(new admintest.AdminPolicy())));
        StringAssert.Contains(noTokens.Message, ".TokensManagedBy(");
    }

    /// <summary>Administration without authorization would administer roles nobody reads: refused at registration.</summary>
    [TestMethod]
    public void Administration_needs_AddKdyfAuthorization_first()
    {
        var error = Assert.ThrowsException<InvalidOperationException>(() => new ServiceCollection().AddKdyfAuthorizationAdministration(admin => admin
            .AdministeredBy(new admintest.AdminPolicy()).TokensManagedBy(new admintest.TokensPolicy())));

        StringAssert.Contains(error.Message, "AddKdyfAuthorization(");
    }

    // ── Plumbing ─────────────────────────────────────────────────────────────

    private static IServiceCollection Authorization(bool simulation = false, params (string Key, string? Value)[] extra)
    {
        var values = new Dictionary<string, string?>(Minimal);
        foreach (var (key, value) in extra)
            values[key] = value;

        // The KdyfAuthorization keys below are relative to their section; the connection strings are the host's own.
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(values.Select(v => new KeyValuePair<string, string?>(
                v.Key.StartsWith("ConnectionStrings:", StringComparison.Ordinal) ? v.Key : $"KdyfAuthorization:{v.Key}", v.Value)))
            .Build();

        var services = new ServiceCollection().AddLogging();
        services.AddKdyfAuthorization(configuration, auth => auth
            .Declarations(typeof(AddKdyfAuthorizationAdministrationTests).Assembly)
            .UseEntityFrameworkStore((db, connectionString) => db.UseSqlServer(connectionString))
            .UseEntraId());
        if (simulation)
            services.AddKdyfAuthorizationSimulation(new admintest.SimulationPolicy());
        return services;
    }

    private static IServiceCollection Register(params (string Key, string? Value)[] extra) => Register(false, extra);

    private static IServiceCollection Register(bool simulation, params (string Key, string? Value)[] extra) =>
        Authorization(simulation, extra).AddKdyfAuthorizationAdministration(admin => admin
            .AdministeredBy(new admintest.AdminPolicy())
            .TokensManagedBy(new admintest.TokensPolicy()));
}
