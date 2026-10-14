using System.Reflection;
using kdyf.Authorization.Authorization;

namespace kdyf.Authorization.Abstractions
{
    /// <summary>
    /// One permission, declared in code: its code, and the name and description that belong with it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The code alone was never the whole permission — a row in <c>auth.Permission</c> carries a name
    /// and a description too, and until now those lived only in the database while the code lived
    /// only in a <c>const</c>. Two halves of one fact, kept in two places, drifting apart with
    /// nobody to notice. A subclass declares all three together, so the row can be DERIVED from the
    /// code rather than maintained alongside it.
    /// </para>
    /// <para>
    /// A class per permission rather than entries in a list: it gives each one a place for its own
    /// remarks, and it is what makes <see cref="PermissionDefinition.DiscoverIn(System.Reflection.Assembly)"/> able to find them without any registry
    /// to keep in step.
    /// </para>
    /// <para>
    /// <b>It converts to its code implicitly</b>, so it goes wherever the string went —
    /// <c>RequireAuthorization(...)</c>, <c>AuthorizeAsync(...)</c>, a comparison against a stored
    /// code. What it CANNOT do is stand in an attribute argument: those are compile-time only, so
    /// anything gated by <c>[Authorize(Policy = ...)]</c> still needs a <c>const</c>.
    /// </para>
    /// </remarks>
    /// <summary>Where a permission's code comes from.</summary>
    public enum CodeShape
    {
        /// <summary>The namespace is the area and prefixes the code: a class in <c>fabrikam</c>
        /// declaring "Controlling" is <c>fabrikam.Controlling</c>. A class with no namespace
        /// declares its code whole.</summary>
        AreaFromNamespace = 0,

        /// <summary>The code is written whole and the namespace is ignored, wherever the class
        /// lives.</summary>
        Verbatim = 1,
    }

    public abstract class PermissionDefinition : IEquatable<PermissionDefinition>
    {
        /// <summary>
        /// Separator for a policy name that accepts several permissions in OR. See
        /// <see cref="AnyOf"/>.
        /// </summary>
        /// <remarks>
        /// It has to agree with <c>PermissionAuthorizationOptions.AnyOfSeparator</c>, which is
        /// configurable and defaults to this. A consumer that changes one has to change the other —
        /// they are the same convention read from two sides, and a mismatch produces a policy name
        /// nobody holds, which denies in silence.
        /// </remarks>
        public const char AnyOfSeparator = '|';

        /// <param name="code">
        /// The permission's own name WITHIN its area — "Controlling", not "fabrikam.Controlling".
        /// <see cref="Code"/> explains where the rest comes from.
        /// </param>
        /// <param name="name">The short label, as the administration screens show it.</param>
        /// <param name="description">What holding it actually allows.</param>
        protected PermissionDefinition(string code, string name, string? description = null)
            : this(CodeShape.AreaFromNamespace, code, name, description) { }

        /// <param name="shape">Where the code comes from. See <see cref="CodeShape"/>.</param>
        /// <param name="code">
        /// The permission's own name within its area, or the whole code when
        /// <paramref name="shape"/> is <see cref="CodeShape.Verbatim"/>.
        /// </param>
        /// <param name="name">The short label, as the administration screens show it.</param>
        /// <param name="description">What holding it actually allows.</param>
        protected PermissionDefinition(CodeShape shape, string code, string name, string? description = null)
        {
            if (string.IsNullOrWhiteSpace(code))
                throw new ArgumentException("A permission needs a code.", nameof(code));

            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentException($"The permission '{code}' needs a name.", nameof(name));

            // GetType() is not virtual and reports the RUNTIME type even here, inside the base
            // constructor — so a subclass declared in namespace 'fabrikam' passing "Controlling"
            // yields "fabrikam.Controlling" without having to repeat the area.
            var area = shape == CodeShape.Verbatim ? null : GetType().Namespace;

            Code = area is null ? code : $"{area}.{code}";
            Name = name;
            Description = description;
        }

        /// <summary>
        /// The code the authorization system compares. Matches <c>auth.Permission.PermissionCode</c>
        /// EXACTLY — a difference here is a permanent 403, not an error.
        /// </summary>
        /// <remarks>
        /// <para>
        /// <b>The NAMESPACE is the area, and it is part of the code.</b> A class in namespace
        /// <c>fabrikam</c> declaring "Controlling" is the permission <c>fabrikam.Controlling</c>; one
        /// in <c>fabrikam.Invoicing</c> declaring "Invoices" is <c>fabrikam.Invoicing.Invoices</c>. A
        /// class with NO namespace declares its code whole — which is how <c>Default</c> and
        /// <c>*</c>, the two that belong to no area, are written.
        /// </para>
        /// <para>
        /// So the prefix is said once, and a new permission in an area inherits it by being put
        /// there. The price is that the namespace is DATA: renaming it, or moving the file in a way
        /// that changes it, changes the permission. Pin the declared codes in a test if you take
        /// this route — it is the only thing that catches a namespace that drifted.
        /// </para>
        /// <para>
        /// <b>Or say the code whole</b>, with <see cref="CodeShape.Verbatim"/>. Then the namespace is
        /// ignored and nothing about where the file lives can change the permission. Prefer it when
        /// the areas are names you do not control — an area called <c>Amazon</c> would otherwise force
        /// a namespace that merges with the AWS SDK's — or simply when a code being data, and only
        /// data, is worth more than saying the prefix once.
        /// </para>
        /// </remarks>
        public string Code { get; }

        /// <summary>The short label. Matches the <c>name</c> column.</summary>
        public string Name { get; }

        /// <summary>What it allows. Matches the <c>description</c> column.</summary>
        public string? Description { get; }

        /// <summary>
        /// Whether this is a WILDCARD rather than a capability — <c>*</c> or <c>prefix.*</c>.
        /// </summary>
        /// <remarks>
        /// A pattern is a row like any other (<c>auth.RolePermission</c> has a foreign key to
        /// <c>auth.Permission</c>, so a role could not grant one otherwise), but it gates nothing on
        /// its own: it stands for the codes it covers. Never write one into a
        /// <c>RequireAuthorization</c> — the handler compares exact strings and would demand the
        /// literal <c>*</c>. See <see cref="PermissionWildcards"/>.
        /// </remarks>
        public bool IsPattern => PermissionWildcards.IsPattern(Code);

        /// <summary>
        /// The policy name that grants to whoever holds ANY of these — what a screen shared by
        /// several capabilities needs.
        /// </summary>
        public static string AnyOf(params PermissionDefinition[] permissions)
        {
            if (permissions is null || permissions.Length == 0)
                throw new ArgumentException("AnyOf needs at least one permission.", nameof(permissions));

            return string.Join(AnyOfSeparator, permissions.Select(p => p.Code));
        }

        /// <summary>
        /// Every permission declared in <paramref name="assembly"/>: one instance per concrete
        /// subclass, ordered by code.
        /// </summary>
        /// <remarks>
        /// <para>
        /// This is the seam the database seeding hangs off — the declarations are the source, the
        /// rows are derived from them. It is also what a startup check reads to say which declared
        /// codes have no row yet.
        /// </para>
        /// <para>
        /// It refuses duplicates rather than picking one: two classes claiming the same code is a
        /// copy-paste that would otherwise show up as one of them silently not existing.
        /// </para>
        /// </remarks>
        public static IReadOnlyList<PermissionDefinition> DiscoverIn(Assembly assembly)
        {
            var declared = assembly
                .GetTypes()
                .Where(t => t is { IsAbstract: false, IsClass: true }
                            && typeof(PermissionDefinition).IsAssignableFrom(t)
                            && t.GetConstructor(Type.EmptyTypes) is not null)
                .Select(t => (PermissionDefinition)Activator.CreateInstance(t)!)
                .OrderBy(p => p.Code, StringComparer.Ordinal)
                .ToList();

            // Case-insensitive: auth.Permission's key is, so two such codes could not both be rows.
            var duplicated = declared
                .GroupBy(p => p.Code, StringComparer.OrdinalIgnoreCase)
                .Where(g => g.Count() > 1)
                .Select(g => g.Key)
                .ToList();

            if (duplicated.Count > 0)
                throw new InvalidOperationException(
                    $"These permission codes are declared more than once in {assembly.GetName().Name}: "
                    + $"{string.Join(", ", duplicated)}.");

            return declared;
        }

        /// <summary>The code, so string interpolation and log messages read as the code.</summary>
        public override string ToString() => Code;

        /// <summary>Goes wherever the code went.</summary>
        public static implicit operator string(PermissionDefinition permission) => permission.Code;

        /// <summary>Two permissions are the same when their codes are. The name and the description
        /// are what the code MEANS, not what it is.</summary>
        public bool Equals(PermissionDefinition? other) =>
            other is not null && string.Equals(Code, other.Code, StringComparison.Ordinal);

        public override bool Equals(object? obj) => Equals(obj as PermissionDefinition);

        public override int GetHashCode() => StringComparer.Ordinal.GetHashCode(Code);
    }
}
