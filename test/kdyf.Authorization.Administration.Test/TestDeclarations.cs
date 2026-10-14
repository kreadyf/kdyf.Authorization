using kdyf.Authorization.Abstractions;
using kdyf.Authorization.Authorization;
using kdyf.Authorization.EntityFrameworkCore.Entities;

// The declarations of a small application, discovered from this assembly exactly as a host's are.
// A block-scoped namespace: the permission's namespace is its area (apitest.Admin, apitest.Read...).
namespace apitest
{
    internal sealed class BaseAccess : PermissionDefinition
    {
        public BaseAccess() : base(CodeShape.Verbatim, "Default", "Base access") { }
    }

    internal sealed class Everything : PermissionDefinition
    {
        public Everything() : base(CodeShape.Verbatim, "*", "Everything") { }
    }

    /// <summary><c>apitest.Admin</c>: administer access. The lockout guard counts it.</summary>
    internal sealed class AdminPermission : PermissionDefinition
    {
        public AdminPermission() : base("Admin", "Administration", "Decide who has access") { }
    }

    /// <summary><c>apitest.Tokens</c>.</summary>
    internal sealed class TokensPermission : PermissionDefinition
    {
        public TokensPermission() : base("Tokens", "Own tokens", "Manage one's own access tokens") { }
    }

    internal sealed class ReadPermission : PermissionDefinition
    {
        public ReadPermission() : base("Read", "Read", "Read the data") { }
    }

    internal sealed class EditPermission : PermissionDefinition
    {
        public EditPermission() : base("Edit", "Edit", "Change the data") { }
    }

    internal sealed class SimulatePermission : PermissionDefinition
    {
        public SimulatePermission() : base("Simulate", "Simulate", "Read as another user") { }
    }

    /// <summary>
    /// The roles and the initial configuration of what each grants — what auth-schema.sql seeds for a real
    /// host. Every member of the access group holds <c>Default</c> without any role.
    /// </summary>
    internal static class TestRoleConfiguration
    {
        internal static readonly string[] RoleValues = ["App.Admin", "App.Editor", "App.Reader", "App.TokenUser", "App.UserManager"];

        internal static readonly string[] MemberGrants = ["Default"];

        internal static Role[] Roles() =>
            RoleValues.Select(value => new Role { RoleValue = value, Name = value.Replace("App.", ""), CreatedAt = DateTime.UtcNow }).ToArray();

        internal static RolePermission[] Rows() =>
        [
            new() { RoleValue = "App.Reader", PermissionCode = "apitest.Read" },
            new() { RoleValue = "App.Editor", PermissionCode = "apitest.Read" },
            new() { RoleValue = "App.Editor", PermissionCode = "apitest.Edit" },
            new() { RoleValue = "App.TokenUser", PermissionCode = "apitest.Tokens" },
            // A LESSER administrator: decides who has access, but holds neither Edit nor Tokens — so may hand
            // out Reader, never Editor or Admin.
            new() { RoleValue = "App.UserManager", PermissionCode = "apitest.Read" },
            new() { RoleValue = "App.UserManager", PermissionCode = "apitest.Admin" },
            new() { RoleValue = "App.Admin", PermissionCode = "*" },
        ];
    }

    // ── Policies: the doors the test hosts guard ──

    internal sealed class TestAdministrationPolicy : Policy
    {
        internal const string PolicyName = "TestAdministration";

        public TestAdministrationPolicy() : base(PolicyName) => RequireAny(new AdminPermission());
    }

    internal sealed class TestSimulationPolicy : Policy
    {
        internal const string PolicyName = "TestSimulation";

        public TestSimulationPolicy() : base(PolicyName) => RequireAny(new SimulatePermission());
    }

    internal sealed class TestTokensPolicy : Policy
    {
        internal const string PolicyName = "TestTokens";

        public TestTokensPolicy() : base(PolicyName) => RequireAny(new TokensPermission());
    }
}
