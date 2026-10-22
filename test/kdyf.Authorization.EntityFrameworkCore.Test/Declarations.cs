using kdyf.Authorization.Abstractions;

// No namespace on purpose: this is how a permission that belongs to no area is declared, and its
// code is then exactly what it says, whole.
internal sealed class BaseAccessPermission : PermissionDefinition
{
    public BaseAccessPermission() : base("Default", "Base access", "Being registered") { }
}

/// <summary>A code longer than the 50 characters of <c>PermissionCode</c>.</summary>
internal sealed class TooLongPermission : PermissionDefinition
{
    public TooLongPermission()
        : base("ThisCodeIsDeliberatelyFarLongerThanTheFiftyCharactersTheColumnAllows",
            "Too long", "Longer than the column") { }
}

namespace demo
{
    using kdyf.Authorization.Abstractions;

    /// <summary>The namespace is the area: this is <c>demo.Controlling</c>.</summary>
    internal sealed class ControllingPermission : PermissionDefinition
    {
        public ControllingPermission() : base("Controlling", "Controlling", "The controlling screens") { }
    }

    /// <summary><c>demo.Invoices</c>.</summary>
    internal sealed class InvoicesPermission : PermissionDefinition
    {
        public InvoicesPermission() : base("Invoices", "Invoices", "Issue and void invoices") { }
    }

    /// <summary><c>demo.*</c> — a wildcard class left over from before 1.2.0. The node <c>demo</c> stands for the
    /// area now, so this gets no row.</summary>
    internal sealed class LegacyAreaWildcard : PermissionDefinition
    {
        public LegacyAreaWildcard() : base("*", "All demo.*", "Wildcard: all of demo") { }
    }
}
