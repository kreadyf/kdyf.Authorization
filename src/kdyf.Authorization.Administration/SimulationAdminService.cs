using System.Diagnostics;
using System.Security.Claims;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using kdyf.Authorization.Abstractions;
using kdyf.Authorization.Administration.Abstractions;
using kdyf.Authorization.Administration.Models;
using kdyf.Authorization.Simulation;

namespace kdyf.Authorization.Administration
{
    /// <inheritdoc cref="ISimulationAdminService"/>
    /// <remarks>
    /// Each operation runs in an <see cref="Activity"/> of its own (<see cref="ActivitySourceName"/>), named as the
    /// operation, and leaves a log line with the real caller and the person.
    /// </remarks>
    internal sealed class SimulationAdminService : ISimulationAdminService
    {
        /// <summary>The source of the operations' activities: listen to it to trace them.</summary>
        public const string ActivitySourceName = "kdyf.Authorization.Simulation";

        private static readonly ActivitySource Activities = new(ActivitySourceName);

        private readonly IUserIdentityResolver _identities;
        private readonly IPrincipalPermissionResolver _permissions;
        private readonly IPermissionStore _store;
        private readonly ISimulationRecorder _recorder;
        private readonly IAccessDirectory _access;
        private readonly IServiceScopeFactory _scopes;
        private readonly ILogger<SimulationAdminService> _logger;
        private readonly UserSimulationOptions? _options;
        private readonly ISimulationTargetResolver? _targets;
        private readonly SimulationSessions? _sessions;
        private readonly IMembershipSource? _directory;

        /// <param name="identities">Who the caller is: their e-mail and immutable id.</param>
        /// <param name="permissions">What the caller holds.</param>
        /// <param name="store">What the person to simulate holds.</param>
        /// <param name="recorder">Where starts and ends are recorded.</param>
        /// <param name="access">Who has access: the candidates.</param>
        /// <param name="scopes">A scope per candidate, so their permissions are read in parallel.</param>
        /// <param name="logger">Where each start and end is logged.</param>
        /// <param name="options">Null when simulation is not switched on: every operation then refuses.</param>
        /// <param name="targets">Registered with simulation, like <paramref name="sessions"/>.</param>
        /// <param name="sessions">Which simulations are running.</param>
        /// <param name="directory">Finds the person an ending simulation was about after they lost their access.</param>
        public SimulationAdminService(
            IUserIdentityResolver identities,
            IPrincipalPermissionResolver permissions,
            IPermissionStore store,
            ISimulationRecorder recorder,
            IAccessDirectory access,
            IServiceScopeFactory scopes,
            ILogger<SimulationAdminService> logger,
            UserSimulationOptions? options = null,
            ISimulationTargetResolver? targets = null,
            SimulationSessions? sessions = null,
            IMembershipSource? directory = null)
        {
            _identities = identities;
            _permissions = permissions;
            _store = store;
            _recorder = recorder;
            _targets = targets;
            _sessions = sessions;
            _access = access;
            _scopes = scopes;
            _logger = logger;
            _options = options;
            _directory = directory;
        }

        public async Task<SimulationResult<SimulationStart>> StartAsync(ClaimsPrincipal caller, string? email, string? path, CancellationToken ct)
        {
            ArgumentNullException.ThrowIfNull(caller);
            using var activity = Activities.StartActivity("StartSimulation");

            if (CheckEmail<SimulationStart>(email) is { } malformed)
                return malformed;
            var wanted = Normalize(email!);

            if (Caller<SimulationStart>(caller, out var real) is { } refused)
                return refused;
            if (Required<SimulationStart>(out var required) is { } off)
                return off;

            // The person, by the same resolver every simulated request uses: in the access group, enabled, holding something.
            var target = await _targets!.ResolveAsync(wanted, ct);
            if (target is null)
                return SimulationResult<SimulationStart>.Missing(wanted);

            // The immutable id is what the audit records and what the session is keyed by.
            if (string.IsNullOrWhiteSpace(target.SubjectId))
                return SimulationResult<SimulationStart>.Refused($"The user {wanted} has no immutable id to be simulated by.");

            // The permission is also the door of the endpoint; checked again so the rule does not depend on which policy a
            // route happens to name.
            var held = await _permissions.ResolveAsync(caller, ct);
            if (!held.Contains(required))
                return SimulationResult<SimulationStart>.Refused(SimulationRules.RequiresPermission(required));

            var borrowed = await _store.GetPermissionsAsync(new UserIdentity(target.SubjectId, target.Email), ct);
            if (SimulationRules.HoldsMoreThan(borrowed, held))
                return SimulationResult<SimulationStart>.Refused(SimulationRules.CannotSimulateWhoHoldsMore);

            // One start per session, as the per-request simulation counts them. The recording comes first and is not
            // cancelled with the request: if it fails nothing is marked and the start fails, because reading somebody
            // else's data without a trace is what the record exists to prevent.
            var resumed = _sessions!.IsActive(real.SubjectId!, target.SubjectId);
            if (!resumed)
            {
                await _recorder.StartedAsync(
                    new SimulationSession(real.SubjectId!, real.Email!, target.SubjectId, target.Email, path),
                    CancellationToken.None);
                _sessions.Begin(real.SubjectId!, target.SubjectId);
            }

            _logger.LogInformation(
                "Simulation {Outcome}: {Caller} reads as {Simulated}.", resumed ? "resumed" : "started", real.Email, target.Email);

            var options = _options!;
            var context = new SimulationContext(
                IsSimulating: true,
                RealUser: new SimulationUser(real.SubjectId, real.Email),
                EffectiveUser: new SimulationUser(target.SubjectId, target.Email),
                ReadOnly: options.ReadOnly);

            return SimulationResult<SimulationStart>.Ok(
                new SimulationStart(context, options.HeaderName, target.Email, options.SessionIdleTimeout, resumed));
        }

        public async Task<SimulationResult<bool>> EndAsync(ClaimsPrincipal caller, string? email, CancellationToken ct)
        {
            ArgumentNullException.ThrowIfNull(caller);
            using var activity = Activities.StartActivity("EndSimulation");

            if (CheckEmail<bool>(email) is { } malformed)
                return malformed;
            var wanted = Normalize(email!);

            if (Caller<bool>(caller, out var real) is { } refused)
                return refused;
            if (Required<bool>(out _) is { } off)
                return off;

            // Found even if they lost their access meanwhile, through the directory: the end is recorded regardless.
            var target = await _targets!.ResolveAsync(wanted, ct);
            var subjectId = !string.IsNullOrWhiteSpace(target?.SubjectId)
                ? target.SubjectId
                : _directory is null ? null : (await _directory.FindByEmailAsync(wanted, ct))?.SubjectId;
            if (subjectId is null)
                return SimulationResult<bool>.Missing(wanted);

            await _recorder.EndedAsync(new SimulationSession(real.SubjectId!, real.Email!, subjectId, wanted), CancellationToken.None);
            _sessions!.End(real.SubjectId!, subjectId);

            _logger.LogInformation("Simulation ended: {Caller} no longer reads as {Simulated}.", real.Email, wanted);
            return SimulationResult<bool>.Ok(true);
        }

        public async Task<SimulationResult<IReadOnlyList<SimulationCandidate>>> ListCandidatesAsync(ClaimsPrincipal caller, CancellationToken ct)
        {
            ArgumentNullException.ThrowIfNull(caller);
            using var activity = Activities.StartActivity("ListSimulationCandidates");

            if (Caller<IReadOnlyList<SimulationCandidate>>(caller, out var real) is { } refused)
                return refused;
            if (Required<IReadOnlyList<SimulationCandidate>>(out var required) is { } off)
                return off;

            var held = await _permissions.ResolveAsync(caller, ct);
            if (!held.Contains(required))
                return SimulationResult<IReadOnlyList<SimulationCandidate>>.Refused(SimulationRules.RequiresPermission(required));

            var people = (await _access.ListWithAccessAsync(ct))
                .Where(p => !string.Equals(p.User.ObjectId, real.SubjectId, StringComparison.OrdinalIgnoreCase))
                .ToList();

            // In parallel, each in a scope of its own — the store reads through a scoped DbContext, which is not shared
            // across threads — so a cold cache costs about one round trip instead of one per person.
            var candidates = new SimulationCandidate[people.Count];
            await Parallel.ForEachAsync(
                Enumerable.Range(0, people.Count),
                new ParallelOptions { MaxDegreeOfParallelism = _options!.CandidatesMaxConcurrency, CancellationToken = ct },
                async (index, token) =>
                {
                    await using var scope = _scopes.CreateAsyncScope();
                    var store = scope.ServiceProvider.GetRequiredService<IPermissionStore>();
                    candidates[index] = await DescribeAsync(people[index], held, store, token);
                });

            return SimulationResult<IReadOnlyList<SimulationCandidate>>.Ok(candidates
                .OrderBy(c => c.Name ?? c.Email ?? c.ObjectId, StringComparer.OrdinalIgnoreCase)
                .ToList());
        }

        /// <summary>
        /// A person as a candidate: refused for what makes the target resolver answer "not found" (a disabled account, no
        /// e-mail to be named by, nothing held) and for holding more than the caller.
        /// </summary>
        private static async Task<SimulationCandidate> DescribeAsync(
            DirectoryAccount account, IReadOnlySet<string> held, IPermissionStore store, CancellationToken ct)
        {
            var user = account.User;
            var email = string.IsNullOrWhiteSpace(user.Email) ? null : Normalize(user.Email);

            SimulationCandidate Refused(string reason) => new(user.ObjectId, email, user.DisplayName, CanSimulate: false, reason);

            if (!account.AccountEnabled)
                return Refused("The account is disabled.");

            // A simulation names its target by e-mail.
            if (email is null)
                return Refused("Has no e-mail address to be simulated by.");

            var borrowed = await store.GetPermissionsAsync(new UserIdentity(user.ObjectId, email), ct);
            if (borrowed.Count == 0)
                return Refused("Holds no access.");

            if (SimulationRules.HoldsMoreThan(borrowed, held))
                return Refused(SimulationRules.HoldsMore);

            return new SimulationCandidate(user.ObjectId, email, user.DisplayName, CanSimulate: true, Reason: null);
        }

        /// <summary>The e-mail is required and has to look like one.</summary>
        private static SimulationResult<T>? CheckEmail<T>(string? email)
        {
            if (string.IsNullOrWhiteSpace(email))
                return SimulationResult<T>.FieldError("email", "This field is required.");
            if (!email.Contains('@'))
                return SimulationResult<T>.FieldError("email", "This is not an e-mail address.");
            return null;
        }

        /// <summary>
        /// The real caller: never from inside a simulation, and only an interactive sign-in — a principal without an
        /// e-mail and an immutable id is a non-person client, and the audit has to name a person.
        /// </summary>
        private SimulationResult<T>? Caller<T>(ClaimsPrincipal principal, out UserIdentity caller)
        {
            caller = null!;
            var simulatedBy = (_options ?? new UserSimulationOptions()).SimulatedByClaimType;
            if (principal.HasClaim(claim => claim.Type == simulatedBy))
                return SimulationResult<T>.Refused("Stop simulating first: a simulation cannot be started or ended from inside one.");

            var resolved = _identities.Resolve(principal);
            if (string.IsNullOrWhiteSpace(resolved?.Email) || string.IsNullOrWhiteSpace(resolved.SubjectId))
                return SimulationResult<T>.Refused(SimulationRules.InteractiveSignInOnly);

            caller = resolved;
            return null;
        }

        /// <summary>The dedicated permission — the same value every simulated request checks. Refused when simulation is off.</summary>
        private SimulationResult<T>? Required<T>(out string required)
        {
            required = _options?.RequiredPermission ?? string.Empty;
            return string.IsNullOrWhiteSpace(required) || _targets is null || _sessions is null
                ? SimulationResult<T>.Refused("User simulation is not enabled.")
                : null;
        }

        /// <summary>The way the permission store and the directory compare e-mails: trimmed, lower-case.</summary>
        private static string Normalize(string email) => email.Trim().ToLowerInvariant();
    }
}
