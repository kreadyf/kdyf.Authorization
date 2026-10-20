using System.Text.Json;
using kdyf.Authorization.Administration.Abstractions;
using kdyf.Authorization.Administration.Models;
using kdyf.Authorization.Administration.Validation;
using kdyf.Authorization;
using kdyf.Authorization.Abstractions;
using kdyf.Authorization.Authentication;
using kdyf.Authorization.Authorization;
using kdyf.Authorization.EntityFrameworkCore.Entities;
using Microsoft.EntityFrameworkCore;

namespace kdyf.Authorization.Administration
{
    /// <inheritdoc cref="IPatAdminService"/>
    /// <typeparam name="TContext">Consumer's DbContext with the auth model applied.</typeparam>
    /// <remarks>
    /// A token has no roles of its own: it grants what its owner holds (access group and roles) at any given
    /// moment, resolved on every request. So there is nothing to keep in sync, and a token can never do
    /// more than the person it belongs to.
    /// </remarks>
    public sealed class PatAdminService<TContext> : IPatAdminService where TContext : DbContext
    {
        private readonly TContext _context;
        private readonly IPermissionStore _permissions;
        private readonly IAuditLog _audit;
        private readonly IAccessDirectory? _directory;
        private readonly string _administrationCode;

        /// <summary>Creates the service. Normally resolved from DI.</summary>
        /// <remarks>
        /// <c>options</c> supplies the administration permission code (<see cref="AuthPolicies.Admin"/> when absent).
        /// <c>directory</c> is needed to create a token for another owner; without it that is refused as an unknown user.
        /// </remarks>
        public PatAdminService(
            TContext context,
            IPermissionStore permissions,
            IAuditLog audit,
            PermissionAuthorizationOptions? options = null,
            IAccessDirectory? directory = null)
        {
            _context = context;
            _permissions = permissions;
            _audit = audit;
            _directory = directory;
            _administrationCode = options?.AdministrationPermissionCode ?? AuthPolicies.Admin;
        }

        /// <inheritdoc />
        public async Task<ValidationResult<CreatePatResponse>> CreateAsync(
            CreatePatRequest request, AdminActor actor, CancellationToken ct)
        {
            if (Refuse(actor) is { } refusal)
                return Outcome.Error<CreatePatResponse>("actor", refusal);

            if (string.IsNullOrWhiteSpace(request.Name))
                return Outcome.Error<CreatePatResponse>("name", "Name is required.");
            if (request.Name.Trim().Length > 100)
                return Outcome.Error<CreatePatResponse>("name", "At most 100 characters.");

            // Expiration is always stored and compared in UTC, regardless of the host or client time zone.
            var expiresAt = ToUtc(request.ExpiresAt);
            if (expiresAt.HasValue && expiresAt.Value <= DateTime.UtcNow)
                return Outcome.Error<CreatePatResponse>("expiresAt", "Expiration must be in the future.");

            // Stored the way the roles are keyed: a token typed for an upper-case id must find its owner's roles and cache.
            var ownerId = UserRole.Normalize(string.IsNullOrWhiteSpace(request.OwnerObjectId) ? actor.Identity.SubjectId! : request.OwnerObjectId);
            var forAnother = !actor.Is(ownerId);
            string ownerLabel;

            if (!forAnother)
            {
                ownerLabel = actor.Identity.Email ?? ownerId;
            }
            else
            {
                if (!IsAdministrator(actor))
                    return Outcome.Error<CreatePatResponse>("ownerObjectId", "Only an administrator can create tokens for another user.");

                if (!Guid.TryParse(ownerId, out _))
                    return Outcome.Error<CreatePatResponse>("ownerObjectId", "Not a valid Entra object id.");

                var owner = _directory is null ? null : await _directory.GetUserAsync(ownerId, ct);
                if (owner is null)
                    return Outcome.Error<CreatePatResponse>("ownerObjectId", "The directory has no user with this id.");
                ownerLabel = owner.User.Label;
            }

            var ownerPermissions = await _permissions.GetPermissionsAsync(new UserIdentity(ownerId, null), ct);

            // Refused instead of created dead: a token of an owner without access grants nothing, and
            // finding that out on first use costs far more than seeing it here.
            if (ownerPermissions.Count == 0)
                return Outcome.Error<CreatePatResponse>("ownerObjectId", $"'{ownerLabel}' holds no access (not in the access group, or a disabled account): their token would grant nothing.");

            // A token for somebody who holds more than the administrator would hand the administrator a
            // credential worth more than themselves.
            if (forAnother)
            {
                var beyond = ownerPermissions.Where(code => !PermissionWildcards.Covers(actor.Permissions, code)).ToList();
                if (beyond.Count > 0)
                    return Outcome.Error<CreatePatResponse>("ownerObjectId",
                        $"'{ownerLabel}' holds permissions you do not: you cannot create a token that acts as them.");
            }

            var (token, prefix, hash) = PatToken.Create();

            var pat = new PersonalAccessToken
            {
                Name = request.Name.Trim(),
                TokenHash = hash,
                TokenPrefix = prefix,
                OwnerObjectId = ownerId,
                OwnerLabel = ownerLabel,
                IsActive = true,
                ExpiresAt = expiresAt,
                CreatedAt = DateTime.UtcNow
            };

            // One transaction, two saves: the audit entry names the token by its id, which only exists
            // after the insert — and a token must never exist without its entry.
            await using (var transaction = await _context.Database.BeginTransactionAsync(ct))
            {
                _context.Add(pat);
                await _context.SaveChangesAsync(ct);

                // Neither the token nor its hash goes into the audit log: only the prefix, which
                // identifies without revealing.
                Audit(actor, "pat.created", pat,
                    new { owner = ownerLabel, ownerObjectId = ownerId, prefix, expiresAt, forAnotherUser = forAnother });
                await _context.SaveChangesAsync(ct);

                await transaction.CommitAsync(ct);
            }

            return Outcome.Ok(new CreatePatResponse
            {
                PersonalAccessTokenId = pat.PersonalAccessTokenId,
                Name = pat.Name,
                Token = token,               // plaintext, shown only once
                TokenPrefix = prefix,
                ExpiresAt = pat.ExpiresAt,
                OwnerObjectId = ownerId,
                OwnerEmail = ownerLabel,
                Permissions = ownerPermissions.OrderBy(c => c, StringComparer.Ordinal).ToList()
            });
        }

        /// <inheritdoc />
        public async Task<ValidationResult<List<PatResponse>>> ListAsync(AdminActor actor, CancellationToken ct)
        {
            // A read: allowed while simulating — the simulated person's own tokens are exactly what a
            // read-only view of their session shows. Only a caller that is not a person is refused.
            if (!actor.IsPerson)
                return Outcome.Error<List<PatResponse>>("actor", "Tokens can only be managed from an interactive sign-in.");

            var query = _context.Set<PersonalAccessToken>().AsNoTracking();

            if (!IsAdministrator(actor))
                query = query.Where(t => t.OwnerObjectId == actor.Identity.SubjectId);

            var pats = await query.ToListAsync(ct);

            // What each token grants is its owner's, right now — through the cached store, once per owner.
            var owners = new Dictionary<string, IReadOnlySet<string>>(StringComparer.OrdinalIgnoreCase);
            foreach (var ownerId in pats.Select(p => p.OwnerObjectId).Distinct(StringComparer.OrdinalIgnoreCase))
                owners[ownerId] = await _permissions.GetPermissionsAsync(new UserIdentity(ownerId, null), ct);

            return Outcome.Ok(pats
                .Select(pat => ToResponse(pat, owners[pat.OwnerObjectId]))
                .OrderByDescending(p => p.CreatedAt)
                .ToList());
        }

        /// <inheritdoc />
        public async Task<ValidationResult<bool>> SetActiveAsync(int patId, bool active, AdminActor actor, CancellationToken ct)
        {
            var (pat, error) = await LoadOwnedAsync(patId, actor, ct);
            if (error is not null) return error;

            // Anybody's token may be switched OFF by an administrator: it only takes access away, and a leaked token has
            // to be stopped at once. Switching one back ON hands out what its owner holds: as when creating it.
            if (active && await BeyondTheActorAsync(pat!, actor, ct) is { } refused)
                return refused;

            // A token an administrator stopped (a leak, an owner under review) stays stopped until an administrator says so:
            // otherwise its owner would switch it back on with the next click.
            if (active && !pat!.IsActive && !IsAdministrator(actor) && await StoppedBySomebodyElseAsync(pat, ct))
                return Outcome.Error<bool>("patId", "An administrator switched this token off: ask one to switch it back on.");

            pat!.IsActive = active;
            Audit(actor, active ? "pat.activated" : "pat.deactivated", pat, new { pat.TokenPrefix, owner = pat.OwnerLabel });
            await _context.SaveChangesAsync(ct);
            return Outcome.Ok(true);
        }

        /// <inheritdoc />
        public async Task<ValidationResult<bool>> DeleteAsync(int patId, AdminActor actor, CancellationToken ct)
        {
            var (pat, error) = await LoadOwnedAsync(patId, actor, ct);
            if (error is not null) return error;

            // Deleting somebody's token who holds more than the administrator would break their integrations from below.
            if (await BeyondTheActorAsync(pat!, actor, ct) is { } refused)
                return refused;

            _context.Remove(pat!);
            Audit(actor, "pat.deleted", pat!, new { pat!.TokenPrefix, owner = pat.OwnerLabel });
            await _context.SaveChangesAsync(ct);
            return Outcome.Ok(true);
        }

        // ── Internal ───────────────────────────────────────────────────────────────

        private static string? Refuse(AdminActor actor)
        {
            if (actor.IsSimulating)
                return "Tokens cannot be managed while simulating another user.";

            if (!actor.IsPerson)
                return "Tokens can only be managed from an interactive sign-in.";

            return null;
        }

        private async Task<(PersonalAccessToken? pat, ValidationResult<bool>? error)> LoadOwnedAsync(
            int patId, AdminActor actor, CancellationToken ct)
        {
            if (Refuse(actor) is { } refusal)
                return (null, Outcome.Error<bool>("actor", refusal));

            var pat = await _context.Set<PersonalAccessToken>().FirstOrDefaultAsync(t => t.PersonalAccessTokenId == patId, ct);

            // Somebody else's token answers exactly like a missing one: a different message would confirm
            // that the id exists.
            if (pat is null || (!actor.Is(pat.OwnerObjectId) && !IsAdministrator(actor)))
                return (null, Outcome.Error<bool>("patId", $"Token {patId} not found."));

            return (pat, null);
        }

        /// <summary>
        /// For somebody else's token: refused when its owner holds permissions the administrator does not. Null when the
        /// actor owns the token or covers what its owner holds.
        /// </summary>
        private async Task<ValidationResult<bool>?> BeyondTheActorAsync(PersonalAccessToken pat, AdminActor actor, CancellationToken ct)
        {
            if (actor.Is(pat.OwnerObjectId))
                return null;

            var owner = await _permissions.GetPermissionsAsync(new UserIdentity(pat.OwnerObjectId, null), ct);
            return owner.All(code => PermissionWildcards.Covers(actor.Permissions, code))
                ? null
                : Outcome.Error<bool>("patId", $"'{pat.OwnerLabel}' holds permissions you do not: only an administrator who holds them can do this to their token.");
        }

        /// <summary>Whether the last time the token was switched off, it was by somebody other than its owner.</summary>
        private async Task<bool> StoppedBySomebodyElseAsync(PersonalAccessToken pat, CancellationToken ct)
        {
            var id = pat.PersonalAccessTokenId.ToString(System.Globalization.CultureInfo.InvariantCulture);
            var last = await _context.Set<Persistence.AuditLogEntry>().AsNoTracking()
                .Where(e => e.TargetType == "pat" && e.TargetId == id && e.Action == "pat.deactivated")
                .OrderByDescending(e => e.AuditLogId)
                .Select(e => e.ActorObjectId)
                .FirstOrDefaultAsync(ct);

            return last is not null && UserRole.Normalize(last) != UserRole.Normalize(pat.OwnerObjectId);
        }

        /// <summary>Whether the actor administers access — the configured code, or a pattern covering it.</summary>
        private bool IsAdministrator(AdminActor actor) => PermissionWildcards.Covers(actor.Permissions, _administrationCode);

        /// <summary>Stages the entry; the caller's SaveChanges stores it.</summary>
        private void Audit(AdminActor actor, string action, PersonalAccessToken pat, object details) =>
            _audit.Record(AuditActor.From(actor.Identity), new AuditEntry(
                action, "pat", pat.PersonalAccessTokenId.ToString(System.Globalization.CultureInfo.InvariantCulture),
                pat.Name, JsonSerializer.Serialize(details)));

        /// <summary>Normalizes to UTC: offset/local are converted; "Unspecified" is assumed UTC (not local).</summary>
        private static DateTime? ToUtc(DateTime? value) => value switch
        {
            null => null,
            { Kind: DateTimeKind.Utc } => value,
            { Kind: DateTimeKind.Local } => value.Value.ToUniversalTime(),
            _ => DateTime.SpecifyKind(value.Value, DateTimeKind.Utc)
        };

        private static PatResponse ToResponse(PersonalAccessToken pat, IReadOnlySet<string> ownerPermissions) => new()
        {
            PersonalAccessTokenId = pat.PersonalAccessTokenId,
            Name = pat.Name,
            TokenPrefix = pat.TokenPrefix,
            OwnerObjectId = pat.OwnerObjectId,
            OwnerEmail = pat.OwnerLabel,
            IsActive = pat.IsActive,
            OwnerHasAccess = ownerPermissions.Count > 0,
            ExpiresAt = pat.ExpiresAt,
            CreatedAt = pat.CreatedAt,
            LastUsedAt = pat.LastUsedAt,
            Permissions = ownerPermissions.OrderBy(c => c, StringComparer.Ordinal).ToList()
        };
    }
}
