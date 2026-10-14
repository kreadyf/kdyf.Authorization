using kdyf.Authorization.Abstractions;

namespace kdyf.Authorization.EntityFrameworkCore.Test;

/// <summary>
/// The declarations the tests run against, shaped like a consumer's: two codes of one area, that
/// area's wildcard, and one that belongs to no area.
/// </summary>
/// <remarks>
/// Handed to the service EXPLICITLY rather than found by scanning. Scanning a test assembly gives
/// every test every declaration in it, so the case built around a deliberately invalid declaration
/// would break all the others — see <c>PermissionCatalogSyncOptions.Declarations</c>.
/// </remarks>
internal static class TestPermissions
{
    internal static PermissionDefinition Controlling() => new demo.ControllingPermission();
    internal static PermissionDefinition Invoices() => new demo.InvoicesPermission();
    internal static PermissionDefinition Wildcard() => new demo.AreaWildcard();
    internal static PermissionDefinition NoArea() => new BaseAccessPermission();
    internal static PermissionDefinition TooLong() => new TooLongPermission();

    internal static PermissionDefinition[] All() => new[] { Controlling(), Invoices(), Wildcard(), NoArea() };
}
