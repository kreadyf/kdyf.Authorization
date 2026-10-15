using kdyf.Authorization.Abstractions;
using kdyf.Authorization.EntraId;
using kdyf.Authorization.Migrations.Legacy;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace kdyf.Authorization.Migrations.Test;

/// <summary>
/// The legacy directory against a REAL Microsoft Graph: a test tenant named by environment variables, never by the
/// repository. Without them the tests are inconclusive.
/// </summary>
/// <remarks>
/// <c>KDYF_AUTHZ_TEST_GRAPH_TENANT</c>, <c>_CLIENT</c>, <c>_SECRET</c> and <c>_GROUP</c> (a group with at least one member).
/// The registration needs User.Read.All and GroupMember.Read.All.
/// </remarks>
[TestClass]
public sealed class GraphLegacyDirectoryTests
{
    private static ServiceProvider Services()
    {
        string Variable(string name) => Environment.GetEnvironmentVariable($"KDYF_AUTHZ_TEST_GRAPH_{name}") is { Length: > 0 } value
            ? value
            : throw new AssertInconclusiveException($"KDYF_AUTHZ_TEST_GRAPH_{name} is not set: no test tenant.");

        var (tenant, client, secret, group) = (Variable("TENANT"), Variable("CLIENT"), Variable("SECRET"), Variable("GROUP"));
        var services = new ServiceCollection().AddLogging();
        services.AddEntraGroupMembership();
        services.Configure<EntraGraphOptions>(o =>
        {
            o.TenantId = tenant;
            o.ClientId = client;
            o.ClientSecret = secret;
            o.GroupId = group;
            o.Gate = AccessGate.Group;
        });
        services.AddKdyfAuthorizationLegacyImport(o => o.LegacyGroupId = group);
        return services.BuildServiceProvider();
    }

    /// <summary>A real member of the group, read from Graph: the tests know nobody in advance.</summary>
    private static async Task<(string Id, string Upn)> AMemberAsync(ServiceProvider services)
    {
        var graph = services.GetRequiredService<GraphClient>();
        var group = services.GetRequiredService<IOptions<EntraGraphOptions>>().Value.GroupId;
        var members = await graph.GetAllAsync<Member>($"groups/{group}/members/microsoft.graph.user?$select=id,userPrincipalName", "listing the test group", default);
        var member = members.FirstOrDefault(m => m.Id is not null && m.UserPrincipalName is not null)
                     ?? throw new AssertInconclusiveException("The test group has no user member.");
        return (member.Id!, member.UserPrincipalName!);
    }

    [TestMethod]
    public async Task A_person_is_found_by_object_id_and_by_their_exact_upn_and_nobody_else_is()
    {
        await using var services = Services();
        var directory = services.GetRequiredService<ILegacyDirectory>();
        var (id, upn) = await AMemberAsync(services);

        var byId = await directory.GetAsync(id);
        var byUpn = await directory.FindExactAsync(upn.ToUpperInvariant());
        var nobody = await directory.FindExactAsync($"nobody-{Guid.NewGuid():N}@example.invalid");
        var missing = await directory.GetAsync(Guid.NewGuid().ToString());

        Assert.AreEqual(upn, byId!.UserPrincipalName);
        Assert.AreEqual(id, byUpn.Single().ObjectId);
        Assert.AreEqual(0, nobody.Count);
        Assert.IsNull(missing);
        Assert.IsTrue(await directory.InLegacyGroupAsync(id));
        Assert.IsFalse(await directory.InLegacyGroupAsync(Guid.NewGuid().ToString()));
    }

    [TestMethod]
    public async Task A_legacy_user_without_object_id_is_resolved_by_upn_with_both_gates()
    {
        await using var services = Services();
        var (id, upn) = await AMemberAsync(services);
        using var scope = services.CreateScope();
        var resolver = new IdentityResolver(
            scope.ServiceProvider.GetRequiredService<ILegacyDirectory>(),
            scope.ServiceProvider.GetRequiredService<IMembershipSource>(),
            services.GetRequiredService<IOptions<LegacyImportOptions>>().Value);

        var identity = (await resolver.ResolveAsync(new[] { new LegacyUser(1, upn, null, null, true), new LegacyUser(2, upn, id.ToUpperInvariant(), null, true) })).ToList();

        Assert.AreEqual((id, "upn"), (identity[0].ObjectId, identity[0].Method));
        Assert.AreEqual((id, "existing"), (identity[1].ObjectId, identity[1].Method));
        Assert.IsTrue(identity[1].PassedLegacyGate, "a member of the legacy group");
        Assert.AreEqual(identity[1].AccountEnabled, identity[1].PassesNewGate, "same group as the new gate: passes when enabled");
    }

    private sealed class Member
    {
        public string? Id { get; set; }
        public string? UserPrincipalName { get; set; }
    }
}
