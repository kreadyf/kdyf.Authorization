using kdyf.Authorization.Abstractions;
using kdyf.Authorization.Authorization;

// The namespace is the permission's area: these classes declare authtest.Admin, authtest.Tokens,
// authtest.Simulate and authtest.Other. Shaped like a host's Permissions/ and Policies/.
namespace authtest
{
    internal sealed class AdminPermission : PermissionDefinition
    {
        public AdminPermission() : base("Admin", "Administration", "Decide who has access") { }
    }

    internal sealed class TokensPermission : PermissionDefinition
    {
        public TokensPermission() : base("Tokens", "Own tokens", "Manage one's own access tokens") { }
    }

    internal sealed class SimulatePermission : PermissionDefinition
    {
        public SimulatePermission() : base("Simulate", "Simulate", "Read as another user") { }
    }

    internal sealed class OtherPermission : PermissionDefinition
    {
        public OtherPermission() : base("Other", "Other", "Anything else") { }
    }

    /// <summary>The base access, held by every member of the access group.</summary>
    internal sealed class BaseAccess : PermissionDefinition
    {
        public BaseAccess() : base(CodeShape.Verbatim, "Default", "Base access") { }
    }

    internal sealed class Everything : PermissionDefinition
    {
        public Everything() : base(CodeShape.Verbatim, "*", "Everything") { }
    }

    /// <summary>A good administration policy: exactly one permission.</summary>
    internal sealed class AdminPolicy : Policy
    {
        public AdminPolicy() : base("TestAdministration") => RequireAny(new AdminPermission());
    }

    internal sealed class TokensPolicy : Policy
    {
        public TokensPolicy() : base("TestTokens") => RequireAny(new TokensPermission());
    }

    internal sealed class SimulationPolicy : Policy
    {
        public SimulationPolicy() : base("TestSimulation") => RequireAny(new SimulatePermission());
    }

    /// <summary>Unfit to administer: the lockout guard cannot count holders of "either of two".</summary>
    internal sealed class EitherPolicy : Policy
    {
        public EitherPolicy() : base("TestEither") => RequireAny(new AdminPermission(), new OtherPermission());
    }

    /// <summary>Unfit to administer: it demands nothing, so there is no code to count.</summary>
    internal sealed class SessionOnlyPolicy : Policy
    {
        public SessionOnlyPolicy() : base("TestSessionOnly") { }
    }
}

namespace kdyf.Authorization.AspNetCore.Test.Foreign
{
    /// <summary>
    /// Stands for a permission some other assembly declares: without a parameterless constructor, discovery in
    /// this one never finds it.
    /// </summary>
    internal sealed class ElsewherePermission : PermissionDefinition
    {
        public ElsewherePermission(string code = "elsewhere.Thing") : base(CodeShape.Verbatim, code, "Elsewhere") { }
    }
}
