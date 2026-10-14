using System.Reflection;
using kdyf.Authorization.Abstractions;
using kdyf.Authorization.Authorization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace kdyf.Authorization.Test;

/// <summary>
/// The shortcut for naming a policy, and why it has to be checked.
/// </summary>
/// <remarks>
/// <para>
/// A static class with one field per policy is just convenience: whatever REGISTERS and reports reads the
/// classes through reflection. The problem is that the two lists can drift apart without anyone noticing.
/// </para>
/// <para>
/// <c>DiscoverIn</c> only instantiates concrete classes with a public parameterless constructor. A
/// policy that does not meet that still compiles as a field of the shortcut, and the door that names it falls
/// through to the provider that reads the NAME as a permission code: a 403 for everybody, without a single line
/// at startup. Checking it at registration turns that silence into a failure when building the host.
/// </para>
/// </remarks>
[TestClass]
public class PolicyShortcutTests
{
    [TestMethod]
    public void A_shortcut_naming_a_registered_policy_is_accepted()
    {
        Build(typeof(GoodShortcuts));   // does not throw
    }

    /// <summary>
    /// The case that matters: the constructor is not public, so <c>DiscoverIn</c> skips it, but
    /// the field compiles because the shortcut lives in the same assembly.
    /// </summary>
    [TestMethod]
    public void A_policy_the_discovery_skips_is_refused_when_the_shortcut_names_it()
    {
        var error = Assert.ThrowsException<InvalidOperationException>(() => Build(typeof(BadShortcuts)));

        StringAssert.Contains(error.Message, "BadShortcuts.Hidden", "says WHICH field is extra");
        StringAssert.Contains(error.Message, "public parameterless constructor", "and why it was not found");
    }

    /// <summary>Without a shortcut there is nothing to check: the parameter is optional on purpose.</summary>
    [TestMethod]
    public void Without_a_shortcut_class_nothing_is_checked()
    {
        Build(shortcuts: null);   // does not throw
    }

    /// <summary>
    /// The other direction is NOT an error. A policy without a field works just the same; it only has to be
    /// written with <c>new</c>. Requiring the field would force touching two files per policy.
    /// </summary>
    [TestMethod]
    public void A_policy_without_a_shortcut_is_not_a_problem()
    {
        // GoodShortcuts names one of the two discovered policies; the other does not appear.
        var discovered = Policy.DiscoverIn(typeof(PolicyShortcutTests).Assembly);

        Assert.IsTrue(discovered.Any(p => p.Name == "Visible"));
        Assert.IsTrue(discovered.Any(p => p.Name == "Unnamed"), "discovered even though nobody names it");
        Assert.IsFalse(discovered.Any(p => p.Name == "Hidden"), "but not the one with the internal constructor");

        Build(typeof(GoodShortcuts));   // does not throw even though 'Unnamed' has no field
    }

    private static void Build(Type? shortcuts)
    {
        var services = new ServiceCollection();
        services.AddAuthorizationCore();
        services.AddSingleton<IPermissionStore, EmptyStore>();

        services
            .AddPermissionAuthorization()
            .AddPolicies(typeof(PolicyShortcutTests).Assembly, shortcuts);
    }
}

// ── The test's policies ──────────────────────────────────────────────────────────

internal sealed class TestAreaPermission : PermissionDefinition
{
    public TestAreaPermission() : base("Something", "Something", "For the shortcut tests") { }
}

/// <summary>Concrete and with a public constructor: DiscoverIn finds it.</summary>
public sealed class VisiblePolicy : Policy
{
    public VisiblePolicy() : base("Visible") => RequireAny(new TestAreaPermission());
}

/// <summary>Also discovered, but no shortcut names it. That is valid.</summary>
public sealed class UnnamedPolicy : Policy
{
    public UnnamedPolicy() : base("Unnamed") => RequireAny(new TestAreaPermission());
}

/// <summary>
/// The constructor is internal: it compiles from the shortcut, but <c>GetConstructor(Type.EmptyTypes)</c>
/// only looks at public ones, so discovery never sees it.
/// </summary>
public sealed class HiddenPolicy : Policy
{
    internal HiddenPolicy() : base("Hidden") => RequireAny(new TestAreaPermission());
}

internal static class GoodShortcuts
{
    public static readonly VisiblePolicy Visible = new();
}

internal static class BadShortcuts
{
    public static readonly VisiblePolicy Visible = new();
    public static readonly HiddenPolicy Hidden = new();
}

internal sealed class EmptyStore : IPermissionStore
{
    public Task<IReadOnlySet<string>> GetPermissionsAsync(
        UserIdentity user, CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlySet<string>>(new HashSet<string>(StringComparer.Ordinal));
}
