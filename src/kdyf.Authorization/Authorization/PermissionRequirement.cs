using Microsoft.AspNetCore.Authorization;

namespace kdyf.Authorization.Authorization
{
    /// <summary>
    /// Requires the user to have AT LEAST ONE of the given permissions (OR).
    /// The policy name IS the list of codes: there is no translation between the two.
    /// </summary>
    /// <remarks>
    /// With a single code, "have that permission". With several, "have any of them": this is what
    /// endpoints shared by several screens need, e.g. the ComplianceController actions used by both
    /// the List screen and the Cases screen.
    ///
    /// AND (requiring several at once) is deliberately not supported: no real case has come up and
    /// each extra mode multiplies the ways to get an [Authorize] wrong.
    /// </remarks>
    public sealed class PermissionRequirement : IAuthorizationRequirement
    {
        /// <param name="codes">The accepted codes: at least one, none empty.</param>
        /// <exception cref="ArgumentException">No code given, or one is null or blank.</exception>
        public PermissionRequirement(params string[] codes)
        {
            if (codes is null || codes.Length == 0)
                throw new ArgumentException("At least one permission code must be given.", nameof(codes));

            if (codes.Any(string.IsNullOrWhiteSpace))
                throw new ArgumentException("No permission code may be empty.", nameof(codes));

            Codes = codes;
        }

        /// <summary>Accepted codes. Having one is enough.</summary>
        public IReadOnlyList<string> Codes { get; }

        /// <summary>For logs: <c>Permission:</c> and the codes joined by <c>|</c>.</summary>
        public override string ToString() => $"Permission:{string.Join("|", Codes)}";
    }
}
