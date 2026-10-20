using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

namespace kdyf.Authorization.Authorization
{
    /// <summary>
    /// Builds a policy for each requested name, treating it as a permission code.
    /// Avoids having to register a policy per permission by hand and removes the runtime exception
    /// caused by using a policy nobody registered.
    /// </summary>
    /// <remarks>
    /// Accepted trade-off: by accepting any name, a typo does not blow up, it denies
    /// silently. This is offset by the startup validation (PolicyValidationHostedService), which
    /// checks the used names against the permission catalog.
    /// </remarks>
    internal sealed class PermissionPolicyProvider : IAuthorizationPolicyProvider
    {
        private readonly DefaultAuthorizationPolicyProvider _fallback;
        private readonly PermissionAuthorizationOptions _options;

        public PermissionPolicyProvider(
            IOptions<AuthorizationOptions> authorizationOptions,
            PermissionAuthorizationOptions options)
        {
            _fallback = new DefaultAuthorizationPolicyProvider(authorizationOptions);
            _options = options;
        }

        public async Task<AuthorizationPolicy?> GetPolicyAsync(string policyName)
        {
            // An explicitly registered policy wins: it lets policies with their own
            // semantics that are not permissions coexist.
            var registered = await _fallback.GetPolicyAsync(policyName);
            if (registered is not null)
                return registered;

            // "A|B" = have A or have B. A single code is the normal case.
            var codes = policyName
                .Split(_options.AnyOfSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

            if (codes.Length == 0)
                return null;   // empty name or only separators: not a valid policy

            var builder = new AuthorizationPolicyBuilder();

            // Without this, the policy would only consider the default scheme and clients
            // arriving through another scheme (e.g. PAT) would end up as anonymous.
            if (_options.AuthenticationSchemes.Length > 0)
                builder.AddAuthenticationSchemes(_options.AuthenticationSchemes);

            return builder
                .RequireAuthenticatedUser()
                .AddRequirements(new PermissionRequirement(codes))
                .Build();
        }

        public Task<AuthorizationPolicy> GetDefaultPolicyAsync() => _fallback.GetDefaultPolicyAsync();

        public Task<AuthorizationPolicy?> GetFallbackPolicyAsync() => _fallback.GetFallbackPolicyAsync();
    }
}
