using kdyf.Authorization.Abstractions;
using kdyf.Authorization.Simulation;
using Microsoft.AspNetCore.Http;

namespace kdyf.Authorization.Authorization
{
    /// <summary>
    /// <see cref="IUserContext"/> over the current request's principal.
    /// </summary>
    /// <remarks>
    /// Deliberately thin. It resolves the identity through the same
    /// <see cref="IUserIdentityResolver"/> the authorization handler uses, off the same
    /// <c>HttpContext.User</c> — so "may this caller do X?" and "whose rows are these?" can never
    /// answer about two different people. Simulation needs no special case here at all: the
    /// principal is already the borrowed one by the time anything asks.
    /// </remarks>
    public sealed class ClaimsUserContext : IUserContext
    {
        private readonly IHttpContextAccessor _http;
        private readonly IUserIdentityResolver _identities;
        private readonly UserSimulationOptions? _simulation;

        public ClaimsUserContext(
            IHttpContextAccessor http,
            IUserIdentityResolver identities,
            UserSimulationOptions? simulation = null)
        {
            _http = http;
            _identities = identities;
            _simulation = simulation;
        }

        private UserIdentity? Identity =>
            _http.HttpContext?.User is { Identity.IsAuthenticated: true } principal
                ? _identities.Resolve(principal)
                : null;

        public bool IsAuthenticated => Identity is not null;

        public string? Email => Identity?.Email;

        public string? SubjectId => Identity?.SubjectId;

        public bool IsSimulating => SimulatedBy is not null;

        /// <summary>Falls back to <see cref="Email"/>, so callers that only want "who did this" —
        /// an audit line, a stamp on a row — need no branch of their own.</summary>
        public string? RealEmail => SimulatedBy ?? Email;

        /// <summary>The administrator behind a borrowed identity, or null on an ordinary request.</summary>
        private string? SimulatedBy
        {
            get
            {
                // Null when simulation is not installed at all: the claim can then never appear, and
                // IsSimulating is constantly false — the truth for that consumer.
                var claimType = _simulation?.SimulatedByClaimType;
                if (string.IsNullOrEmpty(claimType))
                    return null;

                return _http.HttpContext?.User?.FindFirst(claimType)?.Value;
            }
        }

        /// <summary>Falls back to <see cref="SubjectId"/> outside a simulation, like <see cref="RealEmail"/>.</summary>
        public string? RealSubjectId => IsSimulating ? SimulatedByObjectId : SubjectId;

        private string? SimulatedByObjectId
        {
            get
            {
                var claimType = _simulation?.SimulatedByObjectIdClaimType;
                return string.IsNullOrEmpty(claimType) ? null : _http.HttpContext?.User?.FindFirst(claimType)?.Value;
            }
        }
    }
}
