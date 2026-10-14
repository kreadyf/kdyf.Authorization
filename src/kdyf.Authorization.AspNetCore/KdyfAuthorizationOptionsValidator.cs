using Microsoft.Extensions.Options;

namespace kdyf.Authorization.AspNetCore
{
    /// <summary>
    /// Validates the composition's part of the section when the host starts (<c>ValidateOnStart</c>): a host with a
    /// broken security configuration refuses to start, and the message names the key. The providers validate their
    /// own parts.
    /// </summary>
    internal sealed class KdyfAuthorizationOptionsValidator : IValidateOptions<KdyfAuthorizationOptions>
    {
        /// <summary>Beyond this, a removal from the access group takes too long to be called a revocation.</summary>
        internal static readonly TimeSpan MaximumCacheDuration = TimeSpan.FromMinutes(15);

        private readonly string _section;

        public KdyfAuthorizationOptionsValidator(string section) => _section = section;

        public ValidateOptionsResult Validate(string? name, KdyfAuthorizationOptions options)
        {
            var errors = new List<string>();

            var authorization = options.Authorization;
            if (authorization.CacheDuration <= TimeSpan.Zero)
                errors.Add($"{_section}:Authorization:CacheDuration must be positive.");
            if (authorization.CacheDuration > MaximumCacheDuration)
                errors.Add($"{_section}:Authorization:CacheDuration must not exceed {MaximumCacheDuration}: it is how long somebody taken out of the access group keeps their access.");
            if (authorization.EmptyResultCacheDuration <= TimeSpan.Zero)
                errors.Add($"{_section}:Authorization:EmptyResultCacheDuration must be positive.");
            if (authorization.EmptyResultCacheDuration > authorization.CacheDuration)
                errors.Add($"{_section}:Authorization:EmptyResultCacheDuration must not exceed CacheDuration: an empty result is cached SHORTER so that somebody just given access does not keep getting 403.");

            return errors.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(errors);
        }
    }
}
