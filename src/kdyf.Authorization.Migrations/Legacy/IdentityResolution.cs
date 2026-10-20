using System.Security.Cryptography;
using System.Text;
using kdyf.Authorization.Abstractions;

namespace kdyf.Authorization.Migrations.Legacy
{
    /// <summary>A person as the directory knows them.</summary>
    internal sealed record DirectoryPerson(string ObjectId, string? UserPrincipalName, string? Mail, string? UserType, bool AccountEnabled)
    {
        public bool IsGuest => string.Equals(UserType, "Guest", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// What the legacy import asks the directory. Exact lookups only: by object id, or by a <c>userPrincipalName</c> or
    /// <c>mail</c> equal to the e-mail; never <c>otherMails</c> or <c>proxyAddresses</c>, where an address can belong to
    /// somebody else.
    /// </summary>
    internal interface ILegacyDirectory
    {
        /// <summary>The person with this object id, or null.</summary>
        Task<DirectoryPerson?> GetAsync(string objectId, CancellationToken cancellationToken = default);

        /// <summary>Everybody whose UPN or mail is exactly <paramref name="email"/>: zero, one, or (a problem) more.</summary>
        Task<IReadOnlyList<DirectoryPerson>> FindExactAsync(string email, CancellationToken cancellationToken = default);

        /// <summary>Whether the person is in the LEGACY access group (transitively). Only for <see cref="LegacyGate.Group"/>.</summary>
        Task<bool> InLegacyGroupAsync(string objectId, CancellationToken cancellationToken = default);
    }

    /// <summary>Who passed the legacy application's gate.</summary>
    public enum LegacyGate
    {
        /// <summary>
        /// Group-gated legacy hosts: the members of an Entra group. Users without an object id were let through, and so were tokens: both
        /// exemptions are recorded, and the invariant compares against them.
        /// </summary>
        Group,

        /// <summary>Table-gated legacy hosts: every active row of auth.[User] (anybody signing in got one, with the base role).</summary>
        ActiveUsers,
    }

    /// <summary>The legacy import, as a host configures it.</summary>
    public sealed class LegacyImportOptions
    {
        /// <summary>The legacy schema to read (default <c>auth</c>).</summary>
        public string LegacySchema { get; set; } = "auth";

        /// <summary>
        /// Who passed the legacy application's gate (default <see cref="LegacyGate.Group"/>, which requires
        /// <see cref="LegacyGroupId"/>). With <see cref="LegacyGate.Group"/>, tokens are exempt from the gate in the invariant.
        /// </summary>
        public LegacyGate Gate { get; set; } = LegacyGate.Group;

        /// <summary>The legacy access group, for <see cref="LegacyGate.Group"/>.</summary>
        public string? LegacyGroupId { get; set; }

        /// <summary>How old the identities and the gate snapshot may be when the import applies them (default 12 h).</summary>
        public TimeSpan MaxSnapshotAge { get; set; } = TimeSpan.FromHours(12);

        /// <summary>The legacy role given to everybody who signed in (<c>Default</c>): not copied.</summary>
        public string? AutoProvisionedRole { get; set; }

        /// <summary>The hash (hex) of a bootstrap token published in a repository's history: copied inactive.</summary>
        public string? BootstrapTokenHash { get; set; }

        /// <summary>Role values chosen by hand (RoleId → roleValue), frozen before the first copy.</summary>
        public Dictionary<int, string> RoleValueOverrides { get; set; } = new();

        /// <summary>
        /// Codes that must be held after the import by exactly who held them before (the administration code always is):
        /// a host's own <c>global.Vault</c>, for instance.
        /// </summary>
        public List<string> ExactCodes { get; set; } = new();

        /// <summary>How many people must administer access after the import.</summary>
        public int MinAdministrators { get; set; } = 2;
    }

    /// <summary>How a legacy user was matched to a person in the directory.</summary>
    internal static class IdentityStatus
    {
        /// <summary>One enabled member: imported.</summary>
        public const string Ok = "ok";

        /// <summary>A guest: imported only with an approval.</summary>
        public const string Guest = "guest";

        /// <summary>A disabled account: imported only with an approval.</summary>
        public const string Disabled = "disabled";

        /// <summary>Several people match the e-mail: nothing is imported for them until a person picks one.</summary>
        public const string Ambiguous = "ambiguous";

        /// <summary>Nobody matches: their roles are lost unless a person gives the object id.</summary>
        public const string NotFound = "notFound";

        /// <summary>A person gave the object id by hand: imported only with an approval.</summary>
        public const string Manual = "manual";

        /// <summary>Whether an identity in this status can be imported, given whether somebody approved it.</summary>
        public static bool Importable(string status, bool approved) =>
            status == Ok || (approved && status is Guest or Disabled or Manual);
    }

    /// <summary>One legacy user, resolved: who they are in the directory, how that was decided, and what the gates said.</summary>
    internal sealed record ResolvedIdentity(
        int LegacyUserId,
        string Email,
        string? LegacyObjectId,
        string? ObjectId,
        string Method,
        int Matches,
        string? UserType,
        bool? AccountEnabled,
        string Status,
        string SourceRowVersion,
        bool PassedLegacyGate,
        bool? PassesNewGate,
        DateTime ResolvedAt,
        string? ApprovedBy = null,
        DateTime? ApprovedAt = null)
    {
        public bool Approved => ApprovedBy is not null;

        public bool Importable => ObjectId is not null && IdentityStatus.Importable(Status, Approved);
    }

    /// <summary>
    /// Resolves the legacy users against the directory and takes the snapshot of both gates in the same pass. Never
    /// invents an identity: a user it cannot resolve exactly is left for a person to decide.
    /// </summary>
    internal sealed class IdentityResolver
    {
        private readonly ILegacyDirectory _directory;
        private readonly IMembershipSource _newGate;
        private readonly LegacyImportOptions _options;
        private readonly TimeProvider _time;

        public IdentityResolver(ILegacyDirectory directory, IMembershipSource newGate, LegacyImportOptions options, TimeProvider? time = null)
        {
            _time = time ?? TimeProvider.System;
            _directory = directory;
            _newGate = newGate;
            _options = options;
            if (options.Gate == LegacyGate.Group && string.IsNullOrWhiteSpace(options.LegacyGroupId))
                throw new ArgumentException("The legacy gate is a group: LegacyGroupId is required.");
        }

        /// <summary>
        /// Resolves <paramref name="users"/>. With <paramref name="previous"/>, a user whose legacy row did not change
        /// keeps their resolution and its approval (incremental); otherwise it is resolved again and an approval is lost.
        /// </summary>
        public async Task<IReadOnlyList<ResolvedIdentity>> ResolveAsync(
            IEnumerable<LegacyUser> users, IReadOnlyDictionary<int, ResolvedIdentity>? previous = null, CancellationToken cancellationToken = default)
        {
            var result = new List<ResolvedIdentity>();
            foreach (var user in users.OrderBy(u => u.UserId))
            {
                var version = RowVersion(user);
                if (previous is not null && previous.TryGetValue(user.UserId, out var kept) && kept.SourceRowVersion == version)
                {
                    result.Add(kept);
                    continue;
                }
                result.Add(await ResolveAsync(user, version, cancellationToken));
            }
            return result;
        }

        private async Task<ResolvedIdentity> ResolveAsync(LegacyUser user, string version, CancellationToken cancellationToken)
        {
            var email = user.Email.Trim().ToLowerInvariant();
            var hasObjectId = Guid.TryParse(user.ObjectId, out var given);

            DirectoryPerson? person;
            string method;
            int matches;
            if (hasObjectId)
            {
                // The row's object id is used as it is, once the directory confirms it exists. Never replaced by a
                // search: an e-mail can have moved to somebody else.
                person = await _directory.GetAsync(given.ToString(), cancellationToken);
                method = "existing";
                matches = person is null ? 0 : 1;
            }
            else
            {
                var found = await _directory.FindExactAsync(email, cancellationToken);
                matches = found.Count;
                person = found.Count == 1 ? found[0] : null;
                method = person is null ? "email"
                    : string.Equals(person.UserPrincipalName, email, StringComparison.OrdinalIgnoreCase) ? "upn" : "mail";
            }

            var status = person is null ? (matches > 1 ? IdentityStatus.Ambiguous : IdentityStatus.NotFound)
                : person.IsGuest ? IdentityStatus.Guest
                : !person.AccountEnabled ? IdentityStatus.Disabled
                : IdentityStatus.Ok;
            var objectId = person is null ? null : Guid.Parse(person.ObjectId).ToString();

            return new ResolvedIdentity(
                user.UserId, email, user.ObjectId, objectId, method, matches, person?.UserType, person?.AccountEnabled, status, version,
                await PassedLegacyGateAsync(user, objectId, cancellationToken),
                objectId is null ? null : (await _newGate.GetMembershipAsync(objectId, cancellationToken))?.HasAccess ?? false,
                _time.GetUtcNow().UtcDateTime);
        }

        /// <summary>The legacy gate, as the legacy application decided it, read now.</summary>
        private async Task<bool> PassedLegacyGateAsync(LegacyUser user, string? objectId, CancellationToken cancellationToken)
        {
            if (!user.IsActive)
                return false;
            if (_options.Gate == LegacyGate.ActiveUsers)
                return true;
            // A group-gated legacy host let a user without an object id through: the gate could not be asked about them.
            if (!Guid.TryParse(user.ObjectId, out var given))
                return true;
            return await _directory.InLegacyGroupAsync(given.ToString(), cancellationToken);
        }

        /// <summary>
        /// The fingerprint of what the resolution depends on in the legacy row: e-mail, object id and whether it is active.
        /// A change after the resolution blocks the import until it is resolved again.
        /// </summary>
        public static string RowVersion(LegacyUser user) =>
            Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
                $"{user.Email.Trim().ToLowerInvariant()}\n{user.ObjectId?.Trim().ToLowerInvariant()}\n{user.IsActive}")))[..16].ToLowerInvariant();
    }

    /// <summary>Whether the identities still describe the legacy users, and are recent enough to import from.</summary>
    internal static class IdentityFreshness
    {
        /// <summary>Why the import may not use these identities now; empty when it may.</summary>
        public static IReadOnlyList<string> Problems(
            IEnumerable<LegacyUser> users, IReadOnlyCollection<ResolvedIdentity> identities, DateTime now, TimeSpan maxAge)
        {
            var problems = new List<string>();
            DateTime? takenAt = identities.Count == 0 ? null : identities.Min(i => i.ResolvedAt);
            if (takenAt is null)
            {
                problems.Add("The identities have not been resolved: run 'kdyf-auth resolve'.");
                return problems;
            }
            if (now - takenAt.Value > maxAge)
                problems.Add($"The oldest identity and gate snapshot were taken {(now - takenAt.Value).TotalHours:0.#} h ago (at most {maxAge.TotalHours:0.#} h): resolve again, in full.");

            var byId = identities.ToDictionary(i => i.LegacyUserId);
            var list = users.ToList();
            var added = list.Where(u => !byId.ContainsKey(u.UserId)).Select(u => u.UserId).ToList();
            var changed = list.Where(u => byId.TryGetValue(u.UserId, out var i) && i.SourceRowVersion != IdentityResolver.RowVersion(u)).Select(u => u.UserId).ToList();
            var removed = byId.Keys.Except(list.Select(u => u.UserId)).ToList();

            if (added.Count > 0)
                problems.Add($"Users added since the resolution: {string.Join(", ", added)}. Resolve again ('--incremental').");
            if (changed.Count > 0)
                problems.Add($"Users changed since the resolution (e-mail, object id or active): {string.Join(", ", changed)}. Resolve again ('--incremental').");
            if (removed.Count > 0)
                problems.Add($"Users removed since the resolution: {string.Join(", ", removed)}. Resolve again ('--incremental').");
            return problems;
        }
    }
}
