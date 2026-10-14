using System.Reflection;
using kdyf.Authorization.Abstractions;
using Microsoft.AspNetCore.Authorization;

namespace kdyf.Authorization.Authorization
{
    /// <summary>
    /// A named authorization decision: which permissions open it, and under what rule.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Why this exists at all.</b> Without it a policy IS a permission code — the name passed to
    /// <c>RequireAuthorization</c> is parsed as codes by <see cref="PermissionPolicyProvider"/>. That
    /// works, and it is why nothing had to be registered; but it makes the two concepts the same
    /// thing, and they are not. A permission is a capability somebody can hold. A policy is a
    /// DECISION at one door: it may take several permissions, it may combine them in more than one
    /// way, and it may say something the permissions themselves do not.
    /// </para>
    /// <para>
    /// <b>The rule model, and why it needs no new machinery.</b> Each call to
    /// <see cref="RequireAny"/> adds ONE requirement holding several codes — the handler grants it to
    /// whoever has any of them. ASP.NET Core demands that EVERY requirement of a policy succeed. So
    /// several rules compose with AND for free, and a policy expresses <c>(a OR b) AND c</c> without
    /// a new requirement type and without the handler learning anything: <see cref="RequireAll"/> is
    /// just one rule per permission.
    /// </para>
    /// <para>
    /// This is what lets an ADDITIVE permission be stated honestly. "Read everyone's authenticators"
    /// is not <c>global.Authenticator</c> on its own — it is that AND <c>my.Authenticator</c>, which
    /// today is only true because one is checked by the route group and the other in the body of the
    /// endpoint. As a policy it is one line, in one place.
    /// </para>
    /// <para>
    /// A policy with NO rules requires nothing but an authenticated caller — the honest way to say
    /// "any signed-in user", instead of a bare <c>RequireAuthorization()</c> whose meaning depends on
    /// the default policy configured elsewhere.
    /// </para>
    /// </remarks>
    public abstract class Policy
    {
        private readonly List<IReadOnlyList<PermissionDefinition>> _rules = new();

        /// <param name="name">
        /// What the policy is called at the door: <c>RequireAuthorization(Policies.Controlling)</c>.
        /// It is NOT a permission code — a registered policy takes precedence over the code parsing,
        /// so the two namespaces stay apart and nothing that already names a code stops working.
        /// </param>
        protected Policy(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentException("A policy needs a name.", nameof(name));

            Name = name;
        }

        /// <summary>The policy's name.</summary>
        public string Name { get; }

        /// <summary>The rules, in the order declared. All of them must be satisfied (AND); within
        /// one, any permission is enough (OR).</summary>
        public IReadOnlyList<IReadOnlyList<PermissionDefinition>> Rules => _rules;

        /// <summary>Every permission the policy mentions, once each. What a screen would list to
        /// explain the door, and what a coverage check reads.</summary>
        public IReadOnlyList<PermissionDefinition> Permissions =>
            _rules.SelectMany(r => r).Distinct().ToList();

        /// <summary>Holding ANY of these satisfies this rule.</summary>
        protected void RequireAny(params PermissionDefinition[] permissions)
        {
            if (permissions is null || permissions.Length == 0)
                throw new ArgumentException($"The policy '{Name}' declared a rule with no permissions.", nameof(permissions));

            // A pattern would be demanded literally: the effective set holds the codes a wildcard
            // stands for, so gating on 'fabrikam.*' admits only whoever was granted that very pattern
            // and nobody else. Always a mistake, and a silent one.
            var pattern = permissions.FirstOrDefault(p => p.IsPattern);
            if (pattern is not null)
                throw new ArgumentException(
                    $"The policy '{Name}' cannot be gated on '{pattern.Code}': a wildcard stands for codes, "
                    + "it is not one. Name the permissions it covers.", nameof(permissions));

            _rules.Add(permissions);
        }

        /// <summary>ALL of these are needed. Shorthand for one <see cref="RequireAny"/> per
        /// permission — what an additive permission looks like.</summary>
        protected void RequireAll(params PermissionDefinition[] permissions)
        {
            if (permissions is null || permissions.Length == 0)
                throw new ArgumentException($"The policy '{Name}' declared a rule with no permissions.", nameof(permissions));

            foreach (var permission in permissions)
                RequireAny(permission);
        }

        /// <summary>
        /// The policy as ASP.NET Core wants it.
        /// </summary>
        /// <param name="authenticationSchemes">
        /// EVERY scheme a caller may arrive with. A missing one does not fail: its tokens are ignored
        /// and the caller shows up anonymous, which is a permanent 403 for that whole client.
        /// </param>
        public AuthorizationPolicy Build(params string[] authenticationSchemes)
        {
            var builder = new AuthorizationPolicyBuilder();

            if (authenticationSchemes.Length > 0)
                builder.AddAuthenticationSchemes(authenticationSchemes);

            builder.RequireAuthenticatedUser();

            foreach (var rule in _rules)
                builder.AddRequirements(new PermissionRequirement(rule.Select(p => p.Code).ToArray()));

            return builder.Build();
        }

        /// <summary>Every policy declared in <paramref name="assembly"/>, ordered by name.</summary>
        /// <remarks>Refuses duplicate names: two policies answering to one name would leave which
        /// one guards the door to registration order.</remarks>
        public static IReadOnlyList<Policy> DiscoverIn(Assembly assembly)
        {
            var declared = assembly
                .GetTypes()
                .Where(t => t is { IsAbstract: false, IsClass: true }
                            && typeof(Policy).IsAssignableFrom(t)
                            && t.GetConstructor(Type.EmptyTypes) is not null)
                .Select(t => (Policy)Activator.CreateInstance(t)!)
                .OrderBy(p => p.Name, StringComparer.Ordinal)
                .ToList();

            // Case-insensitive, because that is how AuthorizationOptions keys its policies: two
            // names differing only in case would be one door to it and two to the catalog.
            var duplicated = declared
                .GroupBy(p => p.Name, StringComparer.OrdinalIgnoreCase)
                .Where(g => g.Count() > 1)
                .Select(g => g.Key)
                .ToList();

            if (duplicated.Count > 0)
                throw new InvalidOperationException(
                    $"These policy names are declared more than once in {assembly.GetName().Name}: "
                    + $"{string.Join(", ", duplicated)}.");

            return declared;
        }

        public override string ToString() => Name;

        /// <summary>Goes wherever the policy name went.</summary>
        public static implicit operator string(Policy policy) => policy.Name;
    }
}
