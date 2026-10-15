using System.Reflection;
using kdyf.Authorization.Administration.Persistence;
using kdyf.Authorization;
using kdyf.Authorization.EntityFrameworkCore;
using kdyf.Authorization.EntraId;

namespace kdyf.Authorization.Administration.Test;

/// <summary>
/// The split the whole kdyf.Authorization.* layout exists for: authorization knows nothing of administration,
/// and administration depends on authorization — never the other way round.
/// </summary>
/// <remarks>
/// Here because this project references both families, so it can load every assembly involved. A
/// compiler already refuses a project cycle; what it does not refuse is a NEW reference from an
/// authorization project to an administration one, which would make every app that only authorizes
/// drag the administration surface along.
/// </remarks>
[TestClass]
public sealed class DependencyDirectionTests
{
    private const string AdministrationPrefix = "kdyf.Authorization.Administration";

    [TestMethod]
    public void Authorization_does_not_reference_administration() =>
        AssertNoAdministrationReference(typeof(PermissionAuthorizationOptions).Assembly);

    [TestMethod]
    public void Authorization_persistence_does_not_reference_administration() =>
        AssertNoAdministrationReference(typeof(ModelBuilderExtensions).Assembly);

    /// <summary>Reading the access group is authorization; changing it is administration.</summary>
    [TestMethod]
    public void Authorization_over_Entra_does_not_reference_administration() =>
        AssertNoAdministrationReference(typeof(GraphMembershipSource).Assembly);

    /// <summary>The host composition and the session endpoints stay usable by a host that only authorizes.</summary>
    [TestMethod]
    public void Authorization_for_a_host_does_not_reference_administration() =>
        AssertNoAdministrationReference(typeof(kdyf.Authorization.AspNetCore.KdyfAuthorizationBuilder).Assembly);

    [TestMethod]
    public void Administration_references_authorization()
    {
        var references = typeof(AdministrationModelBuilderExtensions).Assembly.GetReferencedAssemblies()
            .Select(a => a.Name)
            .ToArray();

        CollectionAssert.Contains(references, typeof(PermissionAuthorizationOptions).Assembly.GetName().Name);
    }

    /// <summary>Asserted by name so that moving one into an authorization assembly fails here, with the reason.</summary>
    [TestMethod]
    public void The_administration_contracts_live_in_administration()
    {
        var authorizationTypes = typeof(PermissionAuthorizationOptions).Assembly.GetTypes()
            .Concat(typeof(ModelBuilderExtensions).Assembly.GetTypes())
            .Concat(typeof(GraphMembershipSource).Assembly.GetTypes())
            .Select(t => t.Name)
            .ToHashSet();

        foreach (var name in new[] { "IAuditLog", "IDirectoryService", "IInvitationNotifier", "IAccessDirectory", "IAccessChangeNotifier", "AuditLogEntry", "EfAuditLog`1" })
            Assert.IsFalse(authorizationTypes.Contains(name), $"{name} is administration and must not live in an authorization assembly.");
    }

    private static void AssertNoAdministrationReference(Assembly assembly)
    {
        var offending = assembly.GetReferencedAssemblies()
            .Where(a => a.Name?.StartsWith(AdministrationPrefix, StringComparison.Ordinal) == true)
            .Select(a => a.Name)
            .ToArray();

        Assert.AreEqual(0, offending.Length,
            $"{assembly.GetName().Name} references {string.Join(", ", offending)}. Authorization must not depend on administration.");
    }
}
