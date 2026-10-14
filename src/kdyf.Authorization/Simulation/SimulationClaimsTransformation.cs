using System.Security.Claims;
using kdyf.Authorization.Abstractions;
using kdyf.Authorization.Authorization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace kdyf.Authorization.Simulation
{
    /// <summary>
    /// Turns the request into the simulated user — the whole of "simulate user", decision included.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Why here and not in middleware.</b> The obvious design is a middleware between
    /// <c>UseAuthentication</c> and <c>UseAuthorization</c> that assigns <c>HttpContext.User</c>. It
    /// does not work, and it fails silently: when an authorization policy names authentication
    /// schemes, <c>AuthorizationMiddleware</c> re-authenticates and assigns the result back over
    /// <c>context.User</c> — and the authentication handler CACHES its result for the request, so
    /// what comes back is the original principal. Claims transformation is not re-run for that
    /// cached result either. The swap is undone before any endpoint sees it, the logs still say a
    /// simulation happened, and the caller quietly gets their own data.
    /// </para>
    /// <para>
    /// Transformation runs inside the FIRST authentication instead, so the principal is already the
    /// borrowed one before authorization evaluates a single policy. That is what makes the simulated
    /// user's permissions the ones that gate endpoints, rather than the administrator's.
    /// </para>
    /// <para>
    /// <b>Why it can still refuse properly.</b> A transformation cannot write a 403. It records the
    /// refusal on <see cref="HttpContext.Items"/> and leaves the principal alone;
    /// <see cref="UserSimulationMiddleware"/> — a few lines, straight after authentication — turns
    /// that into the response. Fail-closed either way: a request that could not be simulated is
    /// served as nobody's but the caller's own, and refused before it reaches an endpoint.
    /// </para>
    /// </remarks>
    public sealed class SimulationClaimsTransformation : IClaimsTransformation
    {
        /// <summary>The decision for this request, computed once. See <see cref="SimulationDecision"/>.</summary>
        internal const string DecisionItemKey = "kdyf.authorization.simulation-decision";

        private readonly IHttpContextAccessor _http;
        private readonly UserSimulationOptions _options;
        private readonly PermissionAuthorizationOptions _identityOptions;
        private readonly ILogger<SimulationClaimsTransformation> _logger;
        private readonly IClaimsTransformation? _inner;

        /// <param name="http">The request being decided.</param>
        /// <param name="options">How simulation is configured: the header, the permission, read-only.</param>
        /// <param name="identityOptions">Which claims name a person, for building the borrowed identity.</param>
        /// <param name="logger">Where every simulated request and every refusal is logged.</param>
        /// <param name="inner">
        /// A transformation the consumer already had — directory roles, tenant claims, anything.
        /// ASP.NET Core resolves <see cref="IClaimsTransformation"/> as a SINGLE service, so
        /// registering this one would otherwise silently replace it; chaining keeps both. It runs
        /// AFTER the swap and on the swapped principal, so a simulated session gets the target's own
        /// enrichment instead of inheriting the administrator's.
        /// </param>
        public SimulationClaimsTransformation(
            IHttpContextAccessor http,
            UserSimulationOptions options,
            PermissionAuthorizationOptions identityOptions,
            ILogger<SimulationClaimsTransformation> logger,
            IClaimsTransformation? inner = null)
        {
            _http = http;
            _options = options;
            _identityOptions = identityOptions;
            _logger = logger;
            _inner = inner;
        }

        public async Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
        {
            var context = _http.HttpContext;
            if (context is null)
                return await RunInner(principal);

            // Decided once per request. Transformation may be invoked more than once, and the
            // decision costs two database reads — but more importantly it must not change halfway
            // through a request.
            if (context.Items.TryGetValue(DecisionItemKey, out var cached) && cached is SimulationDecision decided)
                return await RunInner(decided.Principal ?? principal);

            var decision = await Decide(context, principal);
            context.Items[DecisionItemKey] = decision;

            return await RunInner(decision.Principal ?? principal);
        }

        private async Task<SimulationDecision> Decide(HttpContext context, ClaimsPrincipal principal)
        {
            if (!context.Request.Headers.TryGetValue(_options.HeaderName, out var raw))
                return SimulationDecision.None;

            var wanted = raw.ToString().Trim();
            if (wanted.Length == 0)
                return SimulationDecision.None;

            // Nothing to simulate FROM. Not a refusal: the endpoint's own policy answers 401, which
            // is the right answer and the one the client already handles.
            if (principal.Identity?.IsAuthenticated != true)
                return SimulationDecision.None;

            var services = context.RequestServices;
            var identities = services.GetRequiredService<IUserIdentityResolver>();

            // A principal with no e-mail is a non-person client (an application token, a PAT). It
            // belongs to its owner rather than being wielded by them in a browser, and simulation is
            // an interactive tool — an integration asking for it is a mistake worth naming.
            //
            // The subject id is required too: it is how the simulation is recorded and how the real caller
            // stays identifiable once the principal is the borrowed one.
            var caller = identities.Resolve(principal);
            if (string.IsNullOrWhiteSpace(caller?.Email) || string.IsNullOrWhiteSpace(caller.SubjectId))
                return SimulationDecision.Refused(StatusCodes.Status403Forbidden, SimulationRules.InteractiveSignInOnly);

            var permissions = services.GetRequiredService<IPrincipalPermissionResolver>();
            var effective = await permissions.ResolveAsync(principal, context.RequestAborted);

            if (!effective.Contains(_options.RequiredPermission))
            {
                _logger.LogWarning(
                    "Simulation refused for {Caller}: {Permission} is required.",
                    caller!.Email, _options.RequiredPermission);

                return SimulationDecision.Refused(
                    StatusCodes.Status403Forbidden, SimulationRules.RequiresPermission(_options.RequiredPermission));
            }

            if (_options.ReadOnly && Writes(context))
            {
                return SimulationDecision.Refused(
                    StatusCodes.Status403Forbidden,
                    "Simulation is read-only. Stop simulating to make changes.");
            }

            var targets = services.GetRequiredService<ISimulationTargetResolver>();
            var target = await targets.ResolveAsync(wanted, context.RequestAborted);

            if (target is null)
                return SimulationDecision.Refused(
                    StatusCodes.Status400BadRequest, $"No active user is registered with the e-mail {wanted}.");

            // Nobody reads as somebody who holds MORE than they do: the same rule a start and the list of
            // candidates apply (SimulationRules).
            var store = services.GetRequiredService<IPermissionStore>();
            var borrowed = await store.GetPermissionsAsync(
                new UserIdentity(target.SubjectId, target.Email), context.RequestAborted);

            var beyond = SimulationRules.HeldBeyond(borrowed, effective);
            if (beyond.Count > 0)
            {
                _logger.LogWarning(
                    "Simulation refused for {Caller}: {Simulated} holds permissions the caller does not ({Beyond}).",
                    caller!.Email, target.Email, string.Join(", ", beyond));

                return SimulationDecision.Refused(StatusCodes.Status403Forbidden, SimulationRules.CannotSimulateWhoHoldsMore);
            }

            if (string.IsNullOrWhiteSpace(target.SubjectId))
                return SimulationDecision.Refused(
                    StatusCodes.Status400BadRequest, $"The user {wanted} has no immutable id to be simulated by.");

            // The start of a simulation is recorded once per session, BEFORE the first borrowed response
            // is served. A recording that fails refuses: reading somebody else's data without a trace is
            // what the record exists to prevent.
            var sessions = services.GetRequiredService<SimulationSessions>();
            if (!sessions.IsActive(caller.SubjectId!, target.SubjectId!))
            {
                try
                {
                    await services.GetRequiredService<ISimulationRecorder>().StartedAsync(
                        new SimulationSession(caller.SubjectId!, caller.Email!, target.SubjectId!, target.Email, context.Request.Path),
                        CancellationToken.None);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Simulation refused for {Caller}: its start could not be recorded.", caller.Email);
                    return SimulationDecision.Refused(
                        StatusCodes.Status503ServiceUnavailable, "The simulation could not be recorded. Try again later.");
                }

                sessions.Begin(caller.SubjectId!, target.SubjectId!);
            }

            // Every request also leaves a log line: the audit log records the session, the log what was read.
            _logger.LogInformation(
                "Simulation: {Caller} is reading {Path} as {Simulated}.",
                caller.Email, context.Request.Path, target.Email);

            return SimulationDecision.Simulating(
                BuildPrincipal(target, caller.Email!, caller.SubjectId!, principal.Identity!.AuthenticationType));
        }

        /// <summary>
        /// Whether a request may change something, as far as a read-only simulation is concerned.
        /// </summary>
        /// <remarks>
        /// GET, HEAD and OPTIONS read. PUT, PATCH, DELETE and any other verb write. POST writes unless its
        /// endpoint says it only reads (<see cref="ReadOnlyOperationAttribute"/>) — a search whose filter goes in
        /// the body. Failing closed: an unmarked POST is refused, and so is a POST whose endpoint is not known
        /// yet. The endpoint is normally known here: routing runs before authentication.
        /// </remarks>
        internal static bool Writes(HttpContext context)
        {
            var method = context.Request.Method;
            if (HttpMethods.IsGet(method) || HttpMethods.IsHead(method) || HttpMethods.IsOptions(method))
                return false;

            return !(HttpMethods.IsPost(method)
                     && context.GetEndpoint()?.Metadata.GetMetadata<ReadOnlyOperationAttribute>() is not null);
        }

        /// <summary>
        /// The borrowed identity, built from scratch rather than by editing the caller's.
        /// </summary>
        /// <remarks>
        /// Copying the token's claims and overwriting two of them would carry the administrator's
        /// ROLE claims across — and role claims are what a consumer's legacy role policies read, so
        /// the simulated session would keep opening doors that belong to the person behind it.
        ///
        /// The claims written are the FIRST of each configured identity claim type, so this agrees
        /// with whatever <see cref="IUserIdentityResolver"/> reads back out of it. The authentication
        /// type is carried over so the endpoints' scheme requirements still match.
        /// </remarks>
        private ClaimsPrincipal BuildPrincipal(SimulationTarget target, string realEmail, string realSubjectId, string? authenticationType)
        {
            var claims = new List<Claim>
            {
                new(_identityOptions.EmailClaimTypes[0], target.Email),
                new(_options.SimulatedByClaimType, realEmail),
                new(_options.SimulatedByObjectIdClaimType, realSubjectId),
                new(ClaimTypes.Name, target.DisplayName ?? target.Email),
            };

            if (!string.IsNullOrWhiteSpace(target.SubjectId) && _identityOptions.SubjectClaimTypes.Length > 0)
                claims.Add(new Claim(_identityOptions.SubjectClaimTypes[0], target.SubjectId!));

            return new ClaimsPrincipal(
                new ClaimsIdentity(claims, authenticationType, ClaimTypes.Name, ClaimTypes.Role));
        }

        private Task<ClaimsPrincipal> RunInner(ClaimsPrincipal principal) =>
            _inner is null ? Task.FromResult(principal) : _inner.TransformAsync(principal);
    }

    /// <summary>What was decided about simulation for one request.</summary>
    /// <param name="Principal">The borrowed identity, or null when not simulating.</param>
    /// <param name="StatusCode">Set when the attempt was refused.</param>
    /// <param name="Error">The refusal, in words.</param>
    internal sealed record SimulationDecision(ClaimsPrincipal? Principal, int? StatusCode, string? Error)
    {
        internal static readonly SimulationDecision None = new(null, null, null);

        internal static SimulationDecision Simulating(ClaimsPrincipal principal) => new(principal, null, null);

        internal static SimulationDecision Refused(int statusCode, string error) => new(null, statusCode, error);
    }
}
