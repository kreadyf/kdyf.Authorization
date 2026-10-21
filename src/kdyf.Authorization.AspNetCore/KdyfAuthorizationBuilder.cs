using System.Reflection;
using kdyf.Authorization.Abstractions;
using kdyf.Authorization.Authorization;
using kdyf.Authorization.Hosting;

namespace kdyf.Authorization.AspNetCore
{
    /// <summary>
    /// The decisions of <c>AddKdyfAuthorization</c> that belong to the host's CODE, not to its configuration: where
    /// the permissions and policies are declared, what every member of the access group holds, and which providers
    /// store the roles and say who may use the application.
    /// </summary>
    /// <remarks>
    /// Authorization only. The policies that guard the administration and the tokens belong to
    /// <c>AddKdyfAuthorizationAdministration</c> (kdyf.Authorization.Administration), and the one that turns simulation on
    /// to <c>AddKdyfAuthorizationSimulation</c> — each registered by whoever owns that feature.
    /// </remarks>
    public sealed class KdyfAuthorizationBuilder : IKdyfAuthorizationBuilder
    {
        private readonly List<(Assembly Assembly, Type? Shortcuts)> _declarations = [];
        private readonly List<(string Name, Action<KdyfAuthorizationProviderContext> Register)> _providers = [];

        internal KdyfAuthorizationBuilder()
        {
        }

        internal IReadOnlyList<Assembly> DeclarationAssemblies => _declarations.Select(d => d.Assembly).Distinct().ToList();

        internal IReadOnlyList<Type> ShortcutTypes => _declarations.Where(d => d.Shortcuts is not null).Select(d => d.Shortcuts!).Distinct().ToList();

        internal IReadOnlyList<(string Name, Action<KdyfAuthorizationProviderContext> Register)> Providers => _providers;

        /// <summary>
        /// An assembly holding <c>PermissionDefinition</c> and <c>Policy</c> classes: the permissions a role can be
        /// configured to grant, and the policies registered as named policies. Call it once per assembly — a host
        /// whose modules each declare their own permissions and doors names every one of them; they become ONE
        /// catalog, and a code or a policy name declared in two of them stops the host at registration.
        /// </summary>
        /// <param name="assembly">The host's own (<c>Assembly.GetExecutingAssembly()</c>), or a module's.</param>
        /// <param name="shortcuts">
        /// That assembly's shortcut class (<c>AppPolicies</c>): every field is checked against what was really
        /// registered, which turns a badly declared policy into a startup failure instead of a 403 for everyone.
        /// </param>
        public KdyfAuthorizationBuilder Declarations(Assembly assembly, Type? shortcuts = null)
        {
            ArgumentNullException.ThrowIfNull(assembly);
            _declarations.Add((assembly, shortcuts));
            return this;
        }

        /// <summary>
        /// What every member of the access group holds without any role: normally the base access, the
        /// permission that means "may use the application". Without it, a member with no role holds nothing.
        /// </summary>
        /// <remarks>
        /// An exact permission, never a wildcard: it goes to everybody in the group. Checked at registration.
        /// </remarks>
        public KdyfAuthorizationBuilder EveryMemberHolds(PermissionDefinition permission)
        {
            ArgumentNullException.ThrowIfNull(permission);
            if (permission.IsPattern)
                throw new ArgumentException($"'{permission.Code}' is a wildcard: every member would hold everything it covers.", nameof(permission));

            MemberPermissionCodes.Add(permission.Code);
            return this;
        }

        /// <summary>
        /// Gives every area a wildcard without writing its class: a host that declares <c>fabrikam.Controlling</c> and
        /// <c>fabrikam.Invoices</c> gets <c>fabrikam.*</c>, its row is written at startup, and a role may grant it. See
        /// <see cref="kdyf.Authorization.Authorization.AreaWildcards"/>.
        /// </summary>
        /// <remarks>
        /// The area is the first segment of a code, and needs at least two permissions. A wildcard declared by a class
        /// wins. Without this call, an area has a wildcard only if a class declares it.
        /// </remarks>
        /// <param name="except">
        /// Areas that must not be granted as a whole — those holding a permission that is never to come through a
        /// wildcard. Each must be an area the host declares permissions in: a misspelt one stops the host at
        /// registration rather than deriving the wildcard it meant to prevent.
        /// </param>
        public KdyfAuthorizationBuilder AreaWildcards(params string[] except)
        {
            ArgumentNullException.ThrowIfNull(except);
            if (DeriveAreaWildcards)
                throw new InvalidOperationException("AddKdyfAuthorization: .AreaWildcards(...) is called twice. Call it once, with every excepted area.");

            DeriveAreaWildcards = true;
            foreach (var area in except)
            {
                ArgumentException.ThrowIfNullOrWhiteSpace(area, nameof(except));
                AreaWildcardExceptions.Add(area);
            }

            return this;
        }

        internal bool DeriveAreaWildcards { get; private set; }

        internal HashSet<string> AreaWildcardExceptions { get; } = new(StringComparer.Ordinal);

        /// <inheritdoc />
        public void AddProvider(string name, Action<KdyfAuthorizationProviderContext> register)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(name);
            ArgumentNullException.ThrowIfNull(register);
            if (_providers.Any(p => p.Name == name))
                throw new InvalidOperationException($"AddKdyfAuthorization: .{name}(...) is called twice. Call it once.");

            _providers.Add((name, register));
        }

        /// <summary>
        /// Makes a session enough for the fallback policy (every endpoint without authorization metadata) and the default
        /// one (a bare <c>RequireAuthorization()</c>), as before 1.0: any account of the tenant that can get a token gets
        /// in, inside the access gate or not. Only for a host whose every endpoint names its permission.
        /// </summary>
        /// <remarks>
        /// By default both policies demand the access gate too (<see cref="kdyf.Authorization.Authorization.AccessGateRequirement"/>):
        /// a person holding at least one permission, or a token carrying one.
        /// </remarks>
        public KdyfAuthorizationBuilder SignedInIsEnough()
        {
            SessionIsEnough = true;
            return this;
        }

        internal bool SessionIsEnough { get; private set; }

        internal HashSet<string> MemberPermissionCodes { get; } = new(StringComparer.Ordinal);

        /// <summary>Refuses an incomplete setup at registration, with the call that is missing.</summary>
        internal void EnsureComplete()
        {
            if (_declarations.Count == 0)
                throw new InvalidOperationException("AddKdyfAuthorization: call .Declarations(assembly, shortcuts) — the permissions and policies come from it.");
        }

        /// <summary>The one permission a policy demands, or a registration error naming what it demands instead.</summary>
        /// <remarks>Internal, and shared with the simulation and with kdyf.Authorization.Administration, whose
        /// policies have the same rule.</remarks>
        internal static string SinglePermission(Policy policy, string purpose)
        {
            ArgumentNullException.ThrowIfNull(policy);

            var codes = policy.Rules.SelectMany(rule => rule).Select(p => p.Code).Distinct(StringComparer.Ordinal).ToList();
            if (policy.Rules.Count != 1 || codes.Count != 1)
                throw new ArgumentException(
                    $"The {purpose} policy '{policy.Name}' must demand exactly one permission. "
                    + $"It demands: {(codes.Count == 0 ? "(none)" : string.Join(", ", codes))}.",
                    nameof(policy));

            return codes[0];
        }
    }
}
