namespace kdyf.Authorization.Simulation
{
    /// <summary>
    /// Configuration of "simulate user". Everything that varies between consumers lives here.
    /// </summary>
    public sealed class UserSimulationOptions
    {
        /// <summary>The request header naming the user to appear as. Absent means an ordinary
        /// request and the middleware does nothing at all.</summary>
        public string HeaderName { get; set; } = "X-Simulate-User";

        /// <summary>
        /// The permission the REAL caller must hold. There is no default: simulating another user
        /// reads their data, and a package cannot guess which of a consumer's codes is allowed to.
        /// </summary>
        public string RequiredPermission { get; set; } = string.Empty;

        /// <summary>
        /// Refuse every request that may change something while a simulation is on: PUT, PATCH, DELETE, and
        /// any POST whose endpoint is not marked <see cref="ReadOnlyOperationAttribute"/>. GET, HEAD and
        /// OPTIONS pass.
        /// </summary>
        /// <remarks>
        /// On by default, and worth leaving on. Writing as somebody else is a different feature with
        /// a different risk: actions land in their name, and any "nobody may do this to themselves"
        /// rule compares against the borrowed identity rather than the real one. One check removes
        /// that whole class. Turn it off only with a deliberate answer to those two.
        /// </remarks>
        public bool ReadOnly { get; set; } = true;

        /// <summary>Claim carrying the real caller's e-mail on a borrowed principal. Read by
        /// <see cref="Abstractions.IUserContext.RealEmail"/> and useful for a banner or an audit line.</summary>
        public string SimulatedByClaimType { get; set; } = "simulated_by";

        /// <summary>Claim carrying the real caller's immutable id ('oid') on a borrowed principal. Read by
        /// <see cref="Abstractions.IUserContext.RealSubjectId"/>: the e-mail can change, this cannot.</summary>
        public string SimulatedByObjectIdClaimType { get; set; } = "simulated_by_oid";

        /// <summary>
        /// How long a simulation lasts without a request. After it, the next simulated request records a new
        /// start. The end is recorded when the client calls the end endpoint; an abandoned simulation simply
        /// expires.
        /// </summary>
        public TimeSpan SessionIdleTimeout { get; set; } = TimeSpan.FromMinutes(30);

        /// <summary>
        /// How many people the list of candidates describes at once: enough for a group to load in one go, few enough
        /// for the directory's throttling. Each one reads what the person holds, through the cached permission store.
        /// </summary>
        public int CandidatesMaxConcurrency { get; set; } = 8;

        /// <summary>
        /// The name of the policy that demands <see cref="RequiredPermission"/>: the door of the endpoints that start,
        /// end and list simulations. Set by whoever switches simulation on, from the policy it was given.
        /// </summary>
        public string? PolicyName { get; set; }

        /// <summary>Headers a client must not be able to turn into "be somebody else".</summary>
        private static readonly string[] ReservedHeaders =
        [
            "Authorization", "Cookie", "Set-Cookie", "Host", "Origin", "Referer", "Content-Type", "Content-Length",
            "Accept", "Connection", "Upgrade", "Forwarded", "Proxy-Authorization",
        ];

        /// <summary>Claims a token may carry: a simulation claim with one of these names could be forged by the token itself.</summary>
        private static readonly string[] TokenClaimTypes =
        [
            "oid", "sub", "email", "emails", "upn", "unique_name", "name", "preferred_username", "roles", "role",
            "groups", "tid", "scp", "aud", "iss", "appid", "azp",
            System.Security.Claims.ClaimTypes.Email, System.Security.Claims.ClaimTypes.Name,
            System.Security.Claims.ClaimTypes.NameIdentifier, System.Security.Claims.ClaimTypes.Role,
            System.Security.Claims.ClaimTypes.Upn,
        ];

        internal void Validate()
        {
            if (SessionIdleTimeout < TimeSpan.FromMinutes(1) || SessionIdleTimeout > TimeSpan.FromHours(8))
                throw new InvalidOperationException(
                    $"UserSimulationOptions.SessionIdleTimeout is {SessionIdleTimeout}: it must be between 1 minute and 8 hours.");

            if (CandidatesMaxConcurrency is < 1 or > 32)
                throw new InvalidOperationException(
                    $"UserSimulationOptions.CandidatesMaxConcurrency is {CandidatesMaxConcurrency}: it must be between 1 and 32.");

            if (string.IsNullOrWhiteSpace(RequiredPermission))
                throw new InvalidOperationException(
                    "UserSimulationOptions.RequiredPermission has to name a permission code. Without it "
                    + "the middleware would let anybody read anybody's data.");

            if (string.IsNullOrWhiteSpace(HeaderName))
                throw new InvalidOperationException("UserSimulationOptions.HeaderName cannot be empty.");

            // An HTTP token (RFC 9110): letters, digits and !#$%&'*+-.^_`|~.
            if (!HeaderName.All(c => char.IsAsciiLetterOrDigit(c) || "!#$%&'*+-.^_`|~".Contains(c)))
                throw new InvalidOperationException($"UserSimulationOptions.HeaderName '{HeaderName}' is not a valid HTTP header name.");

            if (ReservedHeaders.Contains(HeaderName, StringComparer.OrdinalIgnoreCase)
                || HeaderName.StartsWith("X-Forwarded-", StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException(
                    $"UserSimulationOptions.HeaderName '{HeaderName}' is a standard or infrastructure header: name one of the application's own.");

            foreach (var (name, value) in new[] { (nameof(SimulatedByClaimType), SimulatedByClaimType), (nameof(SimulatedByObjectIdClaimType), SimulatedByObjectIdClaimType) })
            {
                if (string.IsNullOrWhiteSpace(value))
                    throw new InvalidOperationException($"UserSimulationOptions.{name} cannot be empty.");
                if (TokenClaimTypes.Contains(value, StringComparer.OrdinalIgnoreCase))
                    throw new InvalidOperationException(
                        $"UserSimulationOptions.{name} is '{value}', a claim a token may carry: a token could then claim to be a simulation.");
            }

            if (string.Equals(SimulatedByClaimType, SimulatedByObjectIdClaimType, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException(
                    "UserSimulationOptions.SimulatedByClaimType and SimulatedByObjectIdClaimType must be different claims.");
        }
    }
}
