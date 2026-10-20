using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using kdyf.Authorization.Administration.Abstractions;
using kdyf.Authorization.Administration.Models;
using kdyf.Authorization.Administration.Validation;
using kdyf.Authorization;
using kdyf.Authorization.Abstractions;
using kdyf.Authorization.Authorization;
using kdyf.Authorization.Roles;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using RoleRow = kdyf.Authorization.EntityFrameworkCore.Entities.Role;
using PermissionRow = kdyf.Authorization.EntityFrameworkCore.Entities.Permission;
using RolePermissionRow = kdyf.Authorization.EntityFrameworkCore.Entities.RolePermission;
using UserRoleRow = kdyf.Authorization.EntityFrameworkCore.Entities.UserRole;
using UserProfileRow = kdyf.Authorization.EntityFrameworkCore.Entities.UserProfile;

namespace kdyf.Authorization.Administration
{
    /// <inheritdoc cref="IAccessAdminService"/>
    /// <typeparam name="TContext">The consumer's DbContext with both models applied: roles, who holds them and
    /// audit entries are saved through it.</typeparam>
    public sealed partial class AccessAdminService<TContext> : IAccessAdminService where TContext : DbContext
    {
        [GeneratedRegex("^[A-Za-z][A-Za-z0-9._-]{0,99}$")]
        private static partial Regex RoleValueShape();

        private readonly TContext _context;
        private readonly IAccessDirectory _group;
        private readonly RolePermissionMapProvider _roles;
        private readonly DeclaredPermissions _declared;
        private readonly IPermissionCache _cache;
        private readonly IAuditLog _audit;
        private readonly IAccessChangeNotifier _notifier;
        private readonly ILogger<AccessAdminService<TContext>> _logger;
        private readonly IMemoryCache? _memory;

        /// <summary>Whether the schema keeps profiles (suspension, last access): without them there is no table to read.</summary>
        private readonly bool _profiles;

        /// <summary>The code that means "administers access": what the lockout guard counts.</summary>
        private readonly string _administrationCode;

        /// <summary>Creates the service. Normally resolved from DI, registered by <c>AddKdyfAuthorizationAdministration</c>.</summary>
        /// <remarks>
        /// <c>options</c> supplies the administration permission code the lockout guard counts
        /// (<see cref="AuthPolicies.Admin"/> when absent). With <c>memory</c>, a suspension also clears the person's
        /// cached answer as a simulation target. <c>store</c> says whether the schema keeps user profiles (assumed on
        /// when absent); without them suspension is refused.
        /// </remarks>
        public AccessAdminService(
            TContext context,
            IAccessDirectory group,
            RolePermissionMapProvider roles,
            DeclaredPermissions declared,
            IPermissionCache cache,
            IAuditLog audit,
            IAccessChangeNotifier notifier,
            ILogger<AccessAdminService<TContext>> logger,
            PermissionAuthorizationOptions? options = null,
            IMemoryCache? memory = null,
            Microsoft.Extensions.Options.IOptions<kdyf.Authorization.EntityFrameworkCore.AuthorizationStoreOptions>? store = null)
        {
            _memory = memory;
            _profiles = store?.Value.UserProfiles ?? true;
            _context = context;
            _group = group;
            _roles = roles;
            _declared = declared;
            _cache = cache;
            _audit = audit;
            _notifier = notifier;
            _logger = logger;
            _administrationCode = options?.AdministrationPermissionCode ?? AuthPolicies.Admin;
        }

        // ── People: reads ────────────────────────────────────────────────────────

        /// <inheritdoc />
        public async Task<ValidationResult<List<AccessUserResponse>>> ListUsersAsync(AdminActor actor, CancellationToken ct)
        {
            try
            {
                var members = await _group.ListWithAccessAsync(ct);
                var held = await HeldRolesAsync(ct);
                var context = await RoleContextAsync(actor, held, ct);
                var profiles = await ProfilesAsync(ct);

                var memberIds = members.Select(m => UserRoleRow.Normalize(m.User.ObjectId)).ToHashSet(StringComparer.Ordinal);

                // Roles left behind for somebody outside the group: listed, flagged, holding nothing.
                var outsiders = held.Keys.Where(id => !memberIds.Contains(id)).ToList();
                var known = outsiders.Count == 0
                    ? new Dictionary<string, DirectoryAccount>(StringComparer.Ordinal)
                    : (await _group.GetUsersAsync(outsiders, ct)).ToDictionary(a => UserRoleRow.Normalize(a.User.ObjectId), StringComparer.Ordinal);

                var people = members
                    .Select(m => ToResponse(m.User, inDirectory: true, m.AccountEnabled, isMember: true, RolesIn(held, m.User.ObjectId), ProfileOf(profiles, m.User.ObjectId), actor, context))
                    .Concat(outsiders.Select(id => known.TryGetValue(id, out var account)
                        ? ToResponse(account.User, inDirectory: true, account.AccountEnabled, isMember: false, held[id], ProfileOf(profiles, id), actor, context)
                        : ToResponse(Unknown(id), inDirectory: false, accountEnabled: false, isMember: false, held[id], ProfileOf(profiles, id), actor, context)));

                return Outcome.Ok(people
                    .OrderBy(user => user.DisplayName ?? user.Email ?? user.ObjectId, StringComparer.OrdinalIgnoreCase)
                    .ToList());
            }
            catch (DirectoryException ex)
            {
                _logger.LogError(ex, "The users with access could not be listed.");
                return Outcome.Error<List<AccessUserResponse>>("directory", ex.Message);
            }
        }

        /// <inheritdoc />
        public async Task<ValidationResult<AccessUserResponse>> GetUserAsync(string objectId, AdminActor actor, CancellationToken ct)
        {
            if (!Guid.TryParse(objectId, out _))
                return Outcome.Error<AccessUserResponse>("objectId", "Not a valid Entra object id.");

            try
            {
                var person = await ReadPersonAsync(objectId, ct);
                if (person is null)
                    return Outcome.Error<AccessUserResponse>("objectId", "The directory has no user with this id.");

                var context = await RoleContextAsync(actor, await HeldRolesAsync(ct), ct);
                return Outcome.Ok(ToResponse(person, actor, context));
            }
            catch (DirectoryException ex)
            {
                _logger.LogError(ex, "User {ObjectId} could not be read.", objectId);
                return Outcome.Error<AccessUserResponse>("directory", ex.Message);
            }
        }

        // ── People: changes ──────────────────────────────────────────────────────

        /// <inheritdoc />
        public async Task<ValidationResult<AccessUserResponse>> SetRolesAsync(
            string objectId, SetRolesRequest request, AdminActor actor, CancellationToken ct)
        {
            if (Refuse(actor) is { } refusal)
                return Outcome.Error<AccessUserResponse>("actor", refusal);

            if (!Guid.TryParse(objectId, out _))
                return Outcome.Error<AccessUserResponse>("objectId", "Not a valid Entra object id.");

            if (actor.Is(objectId))
                return Outcome.Error<AccessUserResponse>("objectId", "Nobody changes their own access. Ask another administrator.");

            var requested = (request?.Roles ?? new List<string>())
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Select(value => value.Trim())
                .Distinct(StringComparer.Ordinal)
                .ToList();

            Person? person;
            RoleContext context;
            try
            {
                person = await ReadPersonAsync(objectId, ct);
                if (person is not { InDirectory: true })
                    return Outcome.Error<AccessUserResponse>("objectId", "The directory has no user with this id.");

                _roles.Invalidate();
                context = await RoleContextAsync(actor, await HeldRolesAsync(ct), ct);
            }
            catch (DirectoryException ex)
            {
                _logger.LogError(ex, "Access of {ObjectId} could not be read before changing it.", objectId);
                return Outcome.Error<AccessUserResponse>("directory", ex.Message);
            }

            var map = context.Map;
            var missing = requested.Where(value => !map.Exists(value)).ToList();
            if (missing.Count > 0)
                return Outcome.Error<AccessUserResponse>("roles", $"There is no role {string.Join(", ", missing)}.");

            var current = person.Roles;
            var toAdd = requested.Where(value => !current.Contains(value)).ToList();
            var toRemove = current.Where(value => !requested.Contains(value)).ToList();

            // Nobody gives away, or takes away, more than they hold. Removing matters as much as granting:
            // otherwise somebody with a lesser administration role could demote a full administrator.
            var beyondGrant = toAdd.Where(value => !map.IsCoveredBy(value, actor.Permissions)).ToList();
            if (beyondGrant.Count > 0)
                return Outcome.Error<AccessUserResponse>("roles",
                    $"You cannot grant {string.Join(", ", beyondGrant)}: it grants permissions you do not hold.");

            var beyondRemove = toRemove.Where(value => !map.IsCoveredBy(value, actor.Permissions)).ToList();
            if (beyondRemove.Count > 0)
                return Outcome.Error<AccessUserResponse>("roles",
                    $"You cannot remove {string.Join(", ", beyondRemove)}: it grants permissions you do not hold. "
                    + "Send it back unchanged to leave it as it is.");

            // Somebody outside the group whose roles stayed behind: bringing them in switches those roles back on, so the
            // ones they keep are given now, by this administrator, and pass the same rule as a grant.
            if (!person.IsMember)
            {
                var revived = current.Except(toRemove, StringComparer.Ordinal).Where(value => !map.IsCoveredBy(value, actor.Permissions)).ToList();
                if (revived.Count > 0)
                    return Outcome.Error<AccessUserResponse>("roles",
                        $"You cannot bring them back into the access group: they still hold {string.Join(", ", revived)}, "
                        + "which grants permissions you do not hold. Ask an administrator who holds them.");
            }

            var remaining = current.Except(toRemove, StringComparer.Ordinal).Concat(toAdd).ToHashSet(StringComparer.Ordinal);
            var takesAdministration = person.HasAccess && Administers(map, current) && !Administers(map, remaining);
            if (takesAdministration)
            {
                var guard = await LeavesAnAdministratorAsync(map, context.Held, except: objectId, ct);
                if (guard is not null)
                    return Outcome.Error<AccessUserResponse>(guard.Value.Field, guard.Value.Message);
            }

            if (toAdd.Count == 0 && toRemove.Count == 0 && person.IsMember)
                return Outcome.Ok(ToResponse(person, actor, context));

            // Taking the administration away: counted again under the administrators' lock, until the change is saved.
            await using var administrators = takesAdministration ? await _context.Database.BeginTransactionAsync(CancellationToken.None) : null;
            if (takesAdministration && await RecheckAdministratorsAsync(objectId, CancellationToken.None) is { } stillOne)
                return Outcome.Error<AccessUserResponse>(stillOne.Field, stillOne.Message);

            // The group first: without it the roles grant nothing, and if Graph refuses nothing has changed yet.
            var joined = false;
            if (!person.IsMember)
            {
                try
                {
                    await _group.GrantAsync(objectId, CancellationToken.None);
                    joined = true;
                }
                catch (DirectoryException ex)
                {
                    _logger.LogError(ex, "{ObjectId} could not be added to the access group.", objectId);
                    return Outcome.Error<AccessUserResponse>("directory", ex.Message);
                }
            }

            var key = UserRoleRow.Normalize(objectId);
            var rows = _context.Set<UserRoleRow>();
            rows.RemoveRange(await rows.Where(r => r.ObjectId == key && toRemove.Contains(r.RoleValue)).ToListAsync(CancellationToken.None));
            rows.AddRange(toAdd.Select(value => new UserRoleRow { ObjectId = key, RoleValue = value }));

            var details = JsonSerializer.Serialize(new { added = toAdd, removed = toRemove });
            _audit.Record(AuditActor.From(actor.Identity), new AuditEntry(
                joined ? "access.granted" : "access.roles.changed", "user", key, person.User.Label, details));

            await SaveAuditedAsync(actor, $"the access of {person.User.Label} ({key})", joined ? $"added to the access group; {details}" : details);
            if (administrators is not null)
                await administrators.CommitAsync(CancellationToken.None);

            // At once on this instance; on others, within CacheDuration.
            _cache.Invalidate(new UserIdentity(key, null));
            await NotifyAsync(person.User, toAdd, toRemove, actor);

            return Outcome.Ok(ToResponse(person with { IsMember = true, Roles = remaining }, actor, context));
        }

        /// <inheritdoc />
        public async Task<ValidationResult<bool>> RevokeAsync(string objectId, AdminActor actor, CancellationToken ct)
        {
            if (Refuse(actor) is { } refusal)
                return Outcome.Error<bool>("actor", refusal);

            if (!Guid.TryParse(objectId, out _))
                return Outcome.Error<bool>("objectId", "Not a valid Entra object id.");

            if (actor.Is(objectId))
                return Outcome.Error<bool>("objectId", "Nobody changes their own access. Ask another administrator.");

            Person? person;
            RoleContext context;
            try
            {
                person = await ReadPersonAsync(objectId, ct);
                if (person is null)
                    return Outcome.Error<bool>("objectId", "The directory has no user with this id.");

                _roles.Invalidate();
                context = await RoleContextAsync(actor, await HeldRolesAsync(ct), ct);
            }
            catch (DirectoryException ex)
            {
                _logger.LogError(ex, "Access of {ObjectId} could not be read before revoking it.", objectId);
                return Outcome.Error<bool>("directory", ex.Message);
            }

            var map = context.Map;
            var removed = person.Roles.OrderBy(v => v, StringComparer.Ordinal).ToList();

            var beyond = removed.Where(value => !map.IsCoveredBy(value, actor.Permissions)).ToList();
            if (beyond.Count > 0)
                return Outcome.Error<bool>("roles",
                    $"You cannot remove {string.Join(", ", beyond)}: it grants permissions you do not hold.");

            var takesAdministration = person.HasAccess && Administers(map, person.Roles);
            if (takesAdministration)
            {
                var guard = await LeavesAnAdministratorAsync(map, context.Held, except: objectId, ct);
                if (guard is not null)
                    return Outcome.Error<bool>(guard.Value.Field, guard.Value.Message);
            }

            // Counted again under the administrators' lock, until the roles are gone.
            await using var administrators = takesAdministration ? await _context.Database.BeginTransactionAsync(CancellationToken.None) : null;
            if (takesAdministration && await RecheckAdministratorsAsync(objectId, CancellationToken.None) is { } stillOne)
                return Outcome.Error<bool>(stillOne.Field, stillOne.Message);

            // The database first: the roles go at once, whatever Graph does next. The other order would risk the
            // opposite failure — out of the group, but with roles that come back the moment somebody re-adds them.
            var key = UserRoleRow.Normalize(objectId);
            var rows = _context.Set<UserRoleRow>();
            rows.RemoveRange(await rows.Where(r => r.ObjectId == key).ToListAsync(CancellationToken.None));

            var details = JsonSerializer.Serialize(new { removed, fromGroup = person.IsMember });
            _audit.Record(AuditActor.From(actor.Identity), new AuditEntry("access.revoked", "user", key, person.User.Label, details));
            await SaveAuditedAsync(actor, $"the access of {person.User.Label} ({key})", details);
            if (administrators is not null)
                await administrators.CommitAsync(CancellationToken.None);

            _cache.Invalidate(new UserIdentity(key, null));
            await NotifyAsync(person.User, Array.Empty<string>(), removed, actor);

            if (!person.IsMember)
                return Outcome.Ok(true);

            // Then the group. The account itself is NOT deleted: deprovisioning it belongs to whoever
            // administers the tenant. A failure here is reported, not swallowed: until the person is out of the
            // group they can still sign in with the base access.
            try
            {
                await _group.RevokeAsync(objectId, CancellationToken.None);

                if (await _group.HasAccessAsync(objectId, CancellationToken.None))
                    return Outcome.Error<bool>("directory",
                        "Their roles were removed and their direct membership too, but they are still in the access group "
                        + "through a nested group. Remove them from that group in Entra; until then they keep the base access.");
            }
            catch (DirectoryException ex)
            {
                _logger.LogError(ex, "The roles of {ObjectId} were removed, but taking them out of the access group failed.", objectId);
                return Outcome.Error<bool>("directory",
                    $"Their roles were removed, but taking them out of the access group failed: {ex.Message} "
                    + "Until that is done they keep the base access. Try again.");
            }

            return Outcome.Ok(true);
        }

        /// <inheritdoc />
        public Task<ValidationResult<AccessUserResponse>> SuspendAsync(string objectId, AdminActor actor, CancellationToken ct) =>
            SetSuspendedAsync(objectId, suspended: true, actor, ct);

        /// <inheritdoc />
        public Task<ValidationResult<AccessUserResponse>> ReactivateAsync(string objectId, AdminActor actor, CancellationToken ct) =>
            SetSuspendedAsync(objectId, suspended: false, actor, ct);

        private async Task<ValidationResult<AccessUserResponse>> SetSuspendedAsync(string objectId, bool suspended, AdminActor actor, CancellationToken ct)
        {
            if (!_profiles)
                return Outcome.Error<AccessUserResponse>("suspension", "Suspension needs the profiles: turn UserProfiles on and apply schema version 4.");

            if (Refuse(actor) is { } refusal)
                return Outcome.Error<AccessUserResponse>("actor", refusal);

            if (!Guid.TryParse(objectId, out _))
                return Outcome.Error<AccessUserResponse>("objectId", "Not a valid Entra object id.");

            if (actor.Is(objectId))
                return Outcome.Error<AccessUserResponse>("objectId", "Nobody changes their own access. Ask another administrator.");

            Person? person;
            RoleContext context;
            try
            {
                person = await ReadPersonAsync(objectId, ct);
                if (person is null)
                    return Outcome.Error<AccessUserResponse>("objectId", "The directory has no user with this id.");

                _roles.Invalidate();
                context = await RoleContextAsync(actor, await HeldRolesAsync(ct), ct);
            }
            catch (DirectoryException ex)
            {
                _logger.LogError(ex, "Access of {ObjectId} could not be read before changing it.", objectId);
                return Outcome.Error<AccessUserResponse>("directory", ex.Message);
            }

            if (person.IsSuspended == suspended)
                return Outcome.Ok(ToResponse(person, actor, context));

            // Suspending takes away everything their roles grant: the rules of removing those roles apply. Lifting it
            // gives it back: the rules of granting them.
            var beyond = person.Roles.Where(value => !context.Map.IsCoveredBy(value, actor.Permissions)).OrderBy(v => v, StringComparer.Ordinal).ToList();
            if (beyond.Count > 0)
                return Outcome.Error<AccessUserResponse>("roles",
                    $"They hold {string.Join(", ", beyond)}, which grants permissions you do not hold: you cannot {(suspended ? "suspend" : "reactivate")} them.");

            var takesAdministration = suspended && person.HasAccess && Administers(context.Map, person.Roles);
            if (takesAdministration)
            {
                var guard = await LeavesAnAdministratorAsync(context.Map, context.Held, except: objectId, ct);
                if (guard is not null)
                    return Outcome.Error<AccessUserResponse>(guard.Value.Field, guard.Value.Message);
            }

            // Counted again under the administrators' lock, until the suspension is saved.
            await using var administrators = takesAdministration ? await _context.Database.BeginTransactionAsync(CancellationToken.None) : null;
            if (takesAdministration && await RecheckAdministratorsAsync(objectId, CancellationToken.None) is { } stillOne)
                return Outcome.Error<AccessUserResponse>(stillOne.Field, stillOne.Message);

            var key = UserRoleRow.Normalize(objectId);
            var profiles = _context.Set<UserProfileRow>();
            var profile = await profiles.FirstOrDefaultAsync(p => p.ObjectId == key, CancellationToken.None);
            if (profile is null)
            {
                profile = new UserProfileRow { ObjectId = key, CreatedAt = DateTime.UtcNow };
                profiles.Add(profile);
            }
            profile.IsActive = !suspended;
            profile.Email ??= person.User.Email?.Trim().ToLowerInvariant();
            profile.DisplayName ??= person.User.DisplayName;

            var details = JsonSerializer.Serialize(new { roles = person.Roles.OrderBy(v => v, StringComparer.Ordinal) });
            _audit.Record(AuditActor.From(actor.Identity), new AuditEntry(
                suspended ? "access.suspended" : "access.reactivated", "user", key, person.User.Label, details));
            await SaveAuditedAsync(actor, $"the suspension of {person.User.Label} ({key})", suspended ? "suspended" : "reactivated");
            if (administrators is not null)
                await administrators.CommitAsync(CancellationToken.None);

            // At once on this instance (their permissions, and their answer as a simulation target); elsewhere within
            // CacheDuration.
            _cache.Invalidate(new UserIdentity(key, null));
            if (_memory is not null)
                MembershipSimulationTargetResolver.Forget(_memory, person.User.Email);
            _logger.LogInformation("{Actor} {Change} {Person} ({ObjectId}).", actor.Identity.Email, suspended ? "suspended" : "reactivated", person.User.Label, key);

            return Outcome.Ok(ToResponse(person with { IsSuspended = suspended }, actor, context));
        }

        /// <inheritdoc />
        public async Task<ValidationResult<bool>> CheckGrantableAsync(IReadOnlyCollection<string> roles, AdminActor actor, CancellationToken ct)
        {
            if (Refuse(actor) is { } refusal)
                return Outcome.Error<bool>("actor", refusal);

            _roles.Invalidate();
            var map = await _roles.GetAsync(ct);
            var requested = roles.Where(v => !string.IsNullOrWhiteSpace(v)).Select(v => v.Trim()).Distinct(StringComparer.Ordinal).ToList();

            var missing = requested.Where(value => !map.Exists(value)).ToList();
            if (missing.Count > 0)
                return Outcome.Error<bool>("roles", $"There is no role {string.Join(", ", missing)}.");

            var beyond = requested.Where(value => !map.IsCoveredBy(value, actor.Permissions)).ToList();
            return beyond.Count > 0
                ? Outcome.Error<bool>("roles", $"You cannot grant {string.Join(", ", beyond)}: it grants permissions you do not hold.")
                : Outcome.Ok(true);
        }

        // ── Roles ────────────────────────────────────────────────────────────────

        /// <inheritdoc />
        public async Task<ValidationResult<List<RoleResponse>>> ListRolesAsync(AdminActor actor, CancellationToken ct)
        {
            var context = await RoleContextAsync(actor, await HeldRolesAsync(ct), ct);
            return Outcome.Ok(context.Map.Roles.Select(value => ToRoleResponse(value, context, actor)).ToList());
        }

        /// <inheritdoc />
        public async Task<ValidationResult<RoleResponse>> GetRoleAsync(string roleValue, AdminActor actor, CancellationToken ct)
        {
            var context = await RoleContextAsync(actor, await HeldRolesAsync(ct), ct);
            return context.Map.Exists(roleValue)
                ? Outcome.Ok(ToRoleResponse(roleValue, context, actor))
                : Outcome.Error<RoleResponse>("roleValue", $"There is no role '{roleValue}'.");
        }

        /// <inheritdoc />
        public async Task<ValidationResult<RoleResponse>> CreateRoleAsync(CreateRoleRequest request, AdminActor actor, CancellationToken ct)
        {
            if (Refuse(actor) is { } refusal)
                return Outcome.Error<RoleResponse>("actor", refusal);

            var value = request?.Value?.Trim() ?? string.Empty;
            if (!RoleValueShape().IsMatch(value))
                return Outcome.Error<RoleResponse>("value",
                    "A role value starts with a letter and has only letters, digits, '.', '_' and '-' (at most 100).");

            var name = string.IsNullOrWhiteSpace(request!.Name) ? value : request.Name.Trim();
            if (name.Length > 200)
                return Outcome.Error<RoleResponse>("name", "At most 200 characters.");

            var description = Clean(request.Description);
            if (description?.Length > 500)
                return Outcome.Error<RoleResponse>("description", "At most 500 characters.");

            var permissions = Codes(request.Permissions);
            var invalid = CheckGrants(permissions, Array.Empty<string>(), actor) ?? await MissingFromCatalogAsync(permissions, ct);
            if (invalid is not null)
                return Outcome.Error<RoleResponse>("permissions", invalid);

            // Case-insensitive on purpose: 'Portal.Admin' and 'portal.admin' side by side is a mistake waiting to
            // be made from a dropdown.
            var existing = await _context.Set<RoleRow>().Select(r => r.RoleValue).ToListAsync(ct);
            if (existing.Any(r => string.Equals(r, value, StringComparison.OrdinalIgnoreCase)))
                return Outcome.Error<RoleResponse>("value", $"There is already a role '{value}'.");

            _context.Add(new RoleRow { RoleValue = value, Name = name, Description = description, CreatedAt = DateTime.UtcNow });
            _context.Set<RolePermissionRow>().AddRange(permissions.Select(code => new RolePermissionRow { RoleValue = value, PermissionCode = code }));
            _audit.Record(AuditActor.From(actor.Identity), new AuditEntry(
                "role.created", "role", value, name, JsonSerializer.Serialize(new { name, description, permissions })));
            await _context.SaveChangesAsync(ct);

            _roles.Invalidate();
            _logger.LogInformation("{Actor} created the role {Role}: {Permissions}.", actor.Identity.Email, value, string.Join(", ", permissions));

            return await GetRoleAsync(value, actor, ct);
        }

        /// <inheritdoc />
        public async Task<ValidationResult<RoleResponse>> UpdateRoleAsync(
            string roleValue, UpdateRoleRequest request, AdminActor actor, CancellationToken ct)
        {
            if (Refuse(actor) is { } refusal)
                return Outcome.Error<RoleResponse>("actor", refusal);

            var name = request?.Name?.Trim() ?? string.Empty;
            if (name.Length is 0 or > 200)
                return Outcome.Error<RoleResponse>("name", "A name is required (at most 200 characters).");

            var description = Clean(request!.Description);
            if (description?.Length > 500)
                return Outcome.Error<RoleResponse>("description", "At most 500 characters.");

            if (request.Permissions is not null || !string.IsNullOrWhiteSpace(request.Version))
                return await UpdateRoleAtomicallyAsync(roleValue, name, description, request, actor, ct);

            var role = await _context.Set<RoleRow>().FirstOrDefaultAsync(r => r.RoleValue == roleValue, ct);
            if (role is null)
                return Outcome.Error<RoleResponse>("roleValue", $"There is no role '{roleValue}'.");

            if (role.Name == name && role.Description == description)
                return await GetRoleAsync(roleValue, actor, ct);

            // What a role is called is what another administrator reads when giving it: renaming one that grants more than
            // the caller holds is refused, as changing what it grants would be.
            _roles.Invalidate();
            if (!(await _roles.GetAsync(ct)).IsCoveredBy(roleValue, actor.Permissions))
                return Outcome.Error<RoleResponse>("roleValue", "It grants permissions you do not hold: you cannot rename it.");

            var details = JsonSerializer.Serialize(new
            {
                name = new { from = role.Name, to = name },
                description = new { from = role.Description, to = description }
            });
            role.Name = name;
            role.Description = description;
            _audit.Record(AuditActor.From(actor.Identity), new AuditEntry("role.updated", "role", roleValue, name, details));
            await _context.SaveChangesAsync(ct);

            return await GetRoleAsync(roleValue, actor, ct);
        }

        /// <inheritdoc />
        public async Task<ValidationResult<bool>> DeleteRoleAsync(string roleValue, AdminActor actor, CancellationToken ct)
        {
            if (Refuse(actor) is { } refusal)
                return Outcome.Error<bool>("actor", refusal);

            var role = await _context.Set<RoleRow>().FirstOrDefaultAsync(r => r.RoleValue == roleValue, ct);
            if (role is null)
                return Outcome.Error<bool>("roleValue", $"There is no role '{roleValue}'.");

            // Taken away from each person first: every one of those changes passes the four-eyes rule and the
            // lockout guard, which a delete that swept them all away at once would skip.
            var holders = await _context.Set<UserRoleRow>().CountAsync(r => r.RoleValue == roleValue, ct);
            if (holders > 0)
                return Outcome.Error<bool>("roleValue",
                    $"{holders} {(holders == 1 ? "person holds" : "people hold")} this role. Take it away from them first.");

            _roles.Invalidate();
            var map = await _roles.GetAsync(ct);
            if (!map.IsCoveredBy(roleValue, actor.Permissions))
                return Outcome.Error<bool>("roleValue", "It grants permissions you do not hold: you cannot delete it.");

            var grants = map.GrantsOf(roleValue).OrderBy(c => c, StringComparer.Ordinal).ToList();

            await using (var transaction = await _context.Database.BeginTransactionAsync(ct))
            {
                var rows = _context.Set<RolePermissionRow>();
                rows.RemoveRange(await rows.Where(r => r.RoleValue == roleValue).ToListAsync(ct));
                _context.Remove(role);
                _audit.Record(AuditActor.From(actor.Identity), new AuditEntry(
                    "role.deleted", "role", roleValue, role.Name, JsonSerializer.Serialize(new { permissions = grants })));

                await _context.SaveChangesAsync(ct);
                await transaction.CommitAsync(ct);
            }

            _roles.Invalidate();
            _logger.LogInformation("{Actor} deleted the role {Role}.", actor.Identity.Email, roleValue);

            return Outcome.Ok(true);
        }

        /// <inheritdoc />
        public async Task<ValidationResult<RoleResponse>> SetRolePermissionsAsync(
            string roleValue, SetRolePermissionsRequest request, AdminActor actor, CancellationToken ct)
        {
            if (Refuse(actor) is { } refusal)
                return Outcome.Error<RoleResponse>("actor", refusal);

            var plan = await PlanPermissionsAsync(roleValue, Codes(request?.Permissions), request?.Version, actor, ct);
            if (plan.Error is { } error)
                return Outcome.Error<RoleResponse>(error.Field, error.Message);

            var (context, added, removed, changed) = (plan.Context!, plan.Added, plan.Removed, plan.Changed!);
            if (added.Count == 0 && removed.Count == 0)
                return Outcome.Ok(ToRoleResponse(roleValue, context, actor));

            var details = JsonSerializer.Serialize(new { added, removed });

            await using (var transaction = await _context.Database.BeginTransactionAsync(ct))
            {
                var rows = _context.Set<RolePermissionRow>();
                rows.RemoveRange(await rows.Where(r => r.RoleValue == roleValue && removed.Contains(r.PermissionCode)).ToListAsync(ct));
                rows.AddRange(added.Select(code => new RolePermissionRow { RoleValue = roleValue, PermissionCode = code }));

                // Taking a permission away from a role can take the administration from everybody holding it: counted
                // again under the administrators' lock, on the current map.
                if (removed.Count > 0 && await RecheckAdministratorsAsync(null, ct, (roleValue, changed.GrantsOf(roleValue))) is { } stillOne)
                    return Outcome.Error<RoleResponse>(stillOne.Field, stillOne.Message);

                _audit.Record(AuditActor.From(actor.Identity), new AuditEntry(
                    "role.permissions.changed", "role", roleValue, context.NameOf(roleValue), details));

                await _context.SaveChangesAsync(ct);
                await transaction.CommitAsync(ct);
            }

            // Everybody holding the role is affected: the map and every cached person, at once on this instance.
            _roles.Invalidate();
            _cache.InvalidateAll();

            _logger.LogInformation("{Actor} changed what {Role} grants: {Details}.", actor.Identity.Email, roleValue, details);

            return Outcome.Ok(ToRoleResponse(roleValue, context with { Map = changed }, actor));
        }

        /// <summary>The outcome of checking a new set of permissions for a role, before anything is written.</summary>
        private sealed record PermissionPlan(
            (string Field, string Message)? Error, RoleContext? Context, List<string> Added, List<string> Removed, RolePermissionMap? Changed)
        {
            public static PermissionPlan Refused(string field, string message) => new((field, message), null, new(), new(), null);
        }

        /// <summary>
        /// Every rule a change of what a role grants passes: the codes are declared and in the catalog, the role exists
        /// and is the version the caller read, the caller does not hold it (four eyes), grants and removes nothing
        /// beyond what they hold, and nobody is left unable to administer.
        /// </summary>
        private async Task<PermissionPlan> PlanPermissionsAsync(string roleValue, List<string> requested, string? version, AdminActor actor, CancellationToken ct)
        {
            var undeclared = requested.Where(code => _declared.Find(code) is null).ToList();
            if (undeclared.Count > 0)
                return PermissionPlan.Refused("permissions", $"These permissions do not exist: {string.Join(", ", undeclared)}. See GET /permissions.");

            _roles.Invalidate();
            var context = await RoleContextAsync(actor, await HeldRolesAsync(ct), ct);

            if (!context.Map.Exists(roleValue))
                return PermissionPlan.Refused("roleValue", $"There is no role '{roleValue}'.");

            var currentGrants = context.Map.GrantsOf(roleValue);
            if (!string.IsNullOrWhiteSpace(version) && version != VersionOf(roleValue, context))
                return PermissionPlan.Refused("version", "Somebody changed this role since you read it. Reload it and apply your change again.");

            var added = requested.Where(code => !currentGrants.Contains(code)).ToList();
            var removed = currentGrants.Where(code => !requested.Contains(code)).OrderBy(c => c, StringComparer.Ordinal).ToList();
            if (added.Count == 0 && removed.Count == 0)
                return new PermissionPlan(null, context, added, removed, context.Map);

            // Four eyes: changing what your own role grants is changing your own access.
            if (context.ActorRoles.Contains(roleValue))
                return PermissionPlan.Refused("roleValue", "You hold this role: what it grants must be changed by another administrator.");

            if (CheckGrants(added, removed, actor) is { } beyond)
                return PermissionPlan.Refused("permissions", beyond);

            if (await MissingFromCatalogAsync(added, ct) is { } notInCatalog)
                return PermissionPlan.Refused("permissions", notInCatalog);

            var changed = context.Map.With(roleValue, requested);

            // The lockout guard: editing a role can take the administration permission away from everybody who holds it.
            if (removed.Count > 0 && await LeavesAnAdministratorAsync(changed, context.Held, except: null, ct) is { } guard)
                return PermissionPlan.Refused(guard.Field, guard.Message);

            return new PermissionPlan(null, context, added, removed, changed);
        }

        /// <summary>Name, description and permissions in one transaction and one audit entry, or nothing.</summary>
        private async Task<ValidationResult<RoleResponse>> UpdateRoleAtomicallyAsync(
            string roleValue, string name, string? description, UpdateRoleRequest request, AdminActor actor, CancellationToken ct)
        {
            var role = await _context.Set<RoleRow>().FirstOrDefaultAsync(r => r.RoleValue == roleValue, ct);
            if (role is null)
                return Outcome.Error<RoleResponse>("roleValue", $"There is no role '{roleValue}'.");

            // Read fresh: a stale map here would carry this instance's old grants into a rename and undo a change another
            // instance saved.
            _roles.Invalidate();
            var current = (await _roles.GetAsync(ct)).GrantsOf(roleValue);
            var requested = request.Permissions is null ? current.ToList() : Codes(request.Permissions);
            var plan = await PlanPermissionsAsync(roleValue, requested, request.Version, actor, ct);
            if (plan.Error is { } error)
                return Outcome.Error<RoleResponse>(error.Field, error.Message);

            var (context, added, removed) = (plan.Context!, plan.Added, plan.Removed);
            var renamed = role.Name != name || role.Description != description;
            if (!renamed && added.Count == 0 && removed.Count == 0)
                return Outcome.Ok(ToRoleResponse(roleValue, context, actor));

            // The same rule as a rename alone: the plan checks only what changes in the grants, not what the role already grants.
            if (renamed && !context.Map.IsCoveredBy(roleValue, actor.Permissions))
                return Outcome.Error<RoleResponse>("roleValue", "It grants permissions you do not hold: you cannot rename it.");

            var details = JsonSerializer.Serialize(new
            {
                name = new { from = role.Name, to = name },
                description = new { from = role.Description, to = description },
                permissions = new { added, removed }
            });

            await using (var transaction = await _context.Database.BeginTransactionAsync(ct))
            {
                role.Name = name;
                role.Description = description;

                var rows = _context.Set<RolePermissionRow>();
                rows.RemoveRange(await rows.Where(r => r.RoleValue == roleValue && removed.Contains(r.PermissionCode)).ToListAsync(ct));
                rows.AddRange(added.Select(code => new RolePermissionRow { RoleValue = roleValue, PermissionCode = code }));

                if (removed.Count > 0 && await RecheckAdministratorsAsync(null, ct, (roleValue, plan.Changed!.GrantsOf(roleValue))) is { } stillOne)
                    return Outcome.Error<RoleResponse>(stillOne.Field, stillOne.Message);

                _audit.Record(AuditActor.From(actor.Identity), new AuditEntry("role.updated", "role", roleValue, name, details));
                await _context.SaveChangesAsync(ct);
                await transaction.CommitAsync(ct);
            }

            _roles.Invalidate();
            if (added.Count > 0 || removed.Count > 0)
                _cache.InvalidateAll();
            _logger.LogInformation("{Actor} updated the role {Role}: {Details}.", actor.Identity.Email, roleValue, details);

            return await GetRoleAsync(roleValue, actor, ct);
        }

        // ── What is left behind ──────────────────────────────────────────────────

        /// <inheritdoc />
        public async Task<ValidationResult<RoleConsistencyResponse>> CheckRoleConsistencyAsync(AdminActor actor, CancellationToken ct)
        {
            try
            {
                return Outcome.Ok(await ConsistencyAsync(ct));
            }
            catch (DirectoryException ex)
            {
                _logger.LogError(ex, "The configuration could not be checked against the access group.");
                return Outcome.Error<RoleConsistencyResponse>("directory", ex.Message);
            }
        }

        /// <inheritdoc />
        public async Task<ValidationResult<OrphanCleanupResponse>> DeleteOrphansAsync(AdminActor actor, CancellationToken ct)
        {
            if (Refuse(actor) is { } refusal)
                return Outcome.Error<OrphanCleanupResponse>("actor", refusal);

            RoleConsistencyResponse consistency;
            try
            {
                // Decided from the group and the tables as they are NOW, not from a report the caller read earlier
                // (nor from a cached map). A failure to read the group deletes nothing — everybody would look gone.
                _roles.Invalidate();
                consistency = await ConsistencyAsync(ct);
            }
            catch (DirectoryException ex)
            {
                _logger.LogError(ex, "The access group could not be read; nothing was removed.");
                return Outcome.Error<OrphanCleanupResponse>("directory", ex.Message);
            }

            var cleanup = new OrphanCleanupResponse
            {
                RemovedPermissions = consistency.UnknownPermissions,
                RemovedCatalogPermissions = consistency.UndeclaredCatalogPermissions,
                RemovedMembers = consistency.FormerMembers
            };

            if (cleanup.RemovedPermissions.Count == 0 && cleanup.RemovedCatalogPermissions.Count == 0 && cleanup.RemovedMembers.Count == 0)
                return Outcome.Ok(cleanup);

            await using (var transaction = await _context.Database.BeginTransactionAsync(ct))
            {
                var grants = _context.Set<RolePermissionRow>();
                foreach (var unknown in cleanup.RemovedPermissions)
                {
                    grants.RemoveRange(await grants
                        .Where(r => r.RoleValue == unknown.Value && unknown.Permissions.Contains(r.PermissionCode))
                        .ToListAsync(ct));

                    _audit.Record(AuditActor.From(actor.Identity), new AuditEntry(
                        "role.permissions.changed", "role", unknown.Value, unknown.Value,
                        JsonSerializer.Serialize(new { reason = "not declared by the application", added = Array.Empty<string>(), removed = unknown.Permissions })));
                }

                // Then the catalog rows themselves: every grant of an undeclared code went just above (they
                // are all in UnknownPermissions), so the foreign key lets them go.
                var catalog = _context.Set<PermissionRow>();
                var retired = cleanup.RemovedCatalogPermissions;
                catalog.RemoveRange(await catalog.Where(p => retired.Contains(p.PermissionCode)).ToListAsync(ct));
                foreach (var code in retired)
                    _audit.Record(AuditActor.From(actor.Identity), new AuditEntry(
                        "permission.deleted", "permission", code, code,
                        JsonSerializer.Serialize(new { reason = "not declared by the application" })));

                var held = _context.Set<UserRoleRow>();
                foreach (var former in cleanup.RemovedMembers)
                {
                    held.RemoveRange(await held.Where(r => r.ObjectId == former.ObjectId).ToListAsync(ct));

                    // One entry per person: "what happened to X's access?" is answered by filtering on them.
                    _audit.Record(AuditActor.From(actor.Identity), new AuditEntry(
                        "access.roles.changed", "user", former.ObjectId, former.Label ?? former.ObjectId,
                        JsonSerializer.Serialize(new { reason = "not a member of the access group", added = Array.Empty<string>(), removed = former.Roles })));
                }

                await _context.SaveChangesAsync(ct);
                await transaction.CommitAsync(ct);
            }

            // Nothing removed granted anything: the map is re-read, and the former members forgotten.
            _roles.Invalidate();
            foreach (var former in cleanup.RemovedMembers)
                _cache.Invalidate(new UserIdentity(former.ObjectId, null));

            _logger.LogInformation(
                "{Actor} cleaned up the configuration: undeclared grants [{Codes}], catalog rows [{Catalog}], roles of former members [{Members}].",
                actor.Identity.Email,
                string.Join(", ", cleanup.RemovedPermissions.Select(u => $"{u.Value}: {string.Join("/", u.Permissions)}")),
                string.Join(", ", cleanup.RemovedCatalogPermissions),
                string.Join(", ", cleanup.RemovedMembers.Select(m => $"{m.Label ?? m.ObjectId}: {string.Join("/", m.Roles)}")));

            return Outcome.Ok(cleanup);
        }

        private async Task<RoleConsistencyResponse> ConsistencyAsync(CancellationToken ct)
        {
            var map = await _roles.GetAsync(ct);
            var held = await HeldRolesAsync(ct);

            var formerIds = new List<string>();
            if (held.Count > 0)
            {
                var members = (await _group.ListWithAccessAsync(ct))
                    .Select(m => UserRoleRow.Normalize(m.User.ObjectId))
                    .ToHashSet(StringComparer.Ordinal);
                formerIds = held.Keys.Where(id => !members.Contains(id)).OrderBy(id => id, StringComparer.Ordinal).ToList();
            }

            var known = formerIds.Count == 0
                ? new Dictionary<string, DirectoryAccount>(StringComparer.Ordinal)
                : (await _group.GetUsersAsync(formerIds, ct)).ToDictionary(a => UserRoleRow.Normalize(a.User.ObjectId), StringComparer.Ordinal);

            var catalog = await _context.Set<PermissionRow>().AsNoTracking().Select(p => p.PermissionCode).ToListAsync(ct);

            return new RoleConsistencyResponse
            {
                UnconfiguredRoles = map.Roles.Where(value => map.EffectivePermissions(new[] { value }).Count == 0).ToList(),
                UndeclaredCatalogPermissions = catalog
                    .Where(code => _declared.Find(code) is null)
                    .OrderBy(code => code, StringComparer.Ordinal)
                    .ToList(),
                UnknownPermissions = map.Undeclared
                    .Select(u => new ConfiguredRoleResponse { Value = u.Key, Permissions = u.Value.ToList() })
                    .OrderBy(u => u.Value, StringComparer.Ordinal)
                    .ToList(),
                FormerMembers = formerIds.Select(id => new FormerMemberResponse
                {
                    ObjectId = id,
                    Label = known.TryGetValue(id, out var account) ? account.User.Label : null,
                    InDirectory = known.ContainsKey(id),
                    Roles = held[id].OrderBy(r => r, StringComparer.Ordinal).ToList()
                }).ToList()
            };
        }

        /// <inheritdoc />
        public Task<ValidationResult<List<PermissionResponse>>> ListPermissionsAsync(CancellationToken ct) =>
            Task.FromResult(Outcome.Ok(_declared.Permissions.Select(p => new PermissionResponse
            {
                PermissionCode = p.Code,
                Name = p.Name,
                Description = p.Description,
                IsPattern = p.IsPattern,
                HeldByEveryMember = _roles.MemberCodes.Contains(p.Code)
            }).ToList()));

        // ── Rules ────────────────────────────────────────────────────────────────

        /// <summary>The refusals that depend only on who is asking.</summary>
        private static string? Refuse(AdminActor actor)
        {
            if (actor.IsSimulating)
                return "Access cannot be changed while simulating another user. Stop simulating first.";

            if (!actor.IsPerson)
                return "Access can only be changed from an interactive sign-in: the audit log has to name the administrator.";

            return null;
        }

        /// <summary>
        /// Null when the actor may make a role grant <paramref name="added"/> and stop granting <paramref name="removed"/>:
        /// every code is declared and covered by what they hold. A code no declaration matches any more grants
        /// nothing, and removing it is always allowed.
        /// </summary>
        private string? CheckGrants(IEnumerable<string> added, IEnumerable<string> removed, AdminActor actor)
        {
            var addedList = added.ToList();

            var undeclared = addedList.Where(code => _declared.Find(code) is null).ToList();
            if (undeclared.Count > 0)
                return $"These permissions do not exist: {string.Join(", ", undeclared)}. See GET /permissions.";

            var beyond = addedList.Concat(removed.Where(code => _declared.Find(code) is not null))
                .Where(code => !PermissionWildcards.Covers(actor.Permissions, code))
                .ToList();

            return beyond.Count == 0 ? null : $"You do not hold {string.Join(", ", beyond)}: you cannot grant or remove it.";
        }

        /// <summary>
        /// Null when every code is a row of <c>auth.Permission</c>. A declared code missing there means the
        /// startup synchronisation could not write it: the grant would break the foreign key, so it is refused
        /// with the reason instead.
        /// </summary>
        private async Task<string?> MissingFromCatalogAsync(IReadOnlyCollection<string> codes, CancellationToken ct)
        {
            if (codes.Count == 0)
                return null;

            var present = await _context.Set<PermissionRow>().AsNoTracking()
                .Where(p => codes.Contains(p.PermissionCode))
                .Select(p => p.PermissionCode)
                .ToListAsync(ct);

            var missing = codes.Except(present, StringComparer.Ordinal).ToList();
            return missing.Count == 0
                ? null
                : $"Not in the permission catalog (auth.Permission) yet: {string.Join(", ", missing)}. The startup "
                  + "synchronisation did not write them — see the host's log.";
        }

        /// <summary>Whether a member holding these roles administers access.</summary>
        private bool Administers(RolePermissionMap map, IEnumerable<string> roleValues) =>
            PermissionWildcards.Covers(map.ForMember(roleValues), _administrationCode);

        /// <summary>
        /// Null when, under <paramref name="map"/>, somebody other than <paramref name="except"/> still administers:
        /// holds a role that grants it, with an enabled account, in the access group. Graph is asked only about
        /// the candidates, and stops at the first one that qualifies. A directory failure refuses the change.
        /// </summary>
        private async Task<(string Field, string Message)?> LeavesAnAdministratorAsync(
            RolePermissionMap map, IReadOnlyDictionary<string, IReadOnlySet<string>> held, string? except, CancellationToken ct)
        {
            var exceptKey = except is null ? null : UserRoleRow.Normalize(except);

            // Roles that grant it by themselves; if being a member were enough, everybody in the group would count.
            if (Administers(map, Array.Empty<string>()))
                return null;

            // A suspended administrator administers nothing.
            var suspended = !_profiles
                ? new HashSet<string>(StringComparer.Ordinal)
                : (await _context.Set<UserProfileRow>().AsNoTracking()
                        .Where(p => !p.IsActive).Select(p => p.ObjectId).ToListAsync(ct))
                    .ToHashSet(StringComparer.Ordinal);

            var candidates = held
                .Where(h => h.Key != exceptKey && !suspended.Contains(h.Key) && Administers(map, h.Value))
                .Select(h => h.Key)
                .ToList();

            try
            {
                if (candidates.Count > 0)
                {
                    var enabled = (await _group.GetUsersAsync(candidates, ct))
                        .Where(a => a.AccountEnabled)
                        .Select(a => a.User.ObjectId);

                    foreach (var objectId in enabled)
                        if (await _group.HasAccessAsync(objectId, ct))
                            return null;
                }
            }
            catch (DirectoryException ex)
            {
                _logger.LogError(ex, "The administrators could not be counted; the change is refused.");
                return ("directory", ex.Message);
            }

            return ("roles", "This change would leave nobody able to administer access. Give the administration to somebody else first.");
        }

        /// <summary>
        /// The lockout guard again, made safe against a concurrent change: inside the caller's transaction, takes the
        /// administrators' lock (SQL Server: <c>sp_getapplock</c>, held until the transaction ends) and counts on fresh data.
        /// Two administrators removing each other at the same moment are then serialized: the second one sees the first
        /// change, and is refused if it would leave nobody.
        /// </summary>
        /// <param name="except">The person whose administration the change takes away, if it is one person's.</param>
        /// <param name="ct">Cancels the wait for the lock and the reads.</param>
        /// <param name="change">The role this change edits and what it will grant, if it edits one.</param>
        /// <remarks>
        /// What the roles grant is read here, after the lock and through this transaction — not from the map provider, whose
        /// copy may predate a change another administrator committed while this one waited for the lock.
        /// </remarks>
        private async Task<(string Field, string Message)?> RecheckAdministratorsAsync(
            string? except, CancellationToken ct, (string RoleValue, IReadOnlySet<string> Grants)? change = null)
        {
            try
            {
                if (_context.Database.ProviderName == "Microsoft.EntityFrameworkCore.SqlServer")
                    await _context.Database.ExecuteSqlRawAsync($"""
                        DECLARE @result INT;
                        EXEC @result = sp_getapplock @Resource = N'kdyf.authorization.administrators', @LockMode = N'Exclusive',
                                                     @LockOwner = N'Transaction', @LockTimeout = 15000;
                        IF @result < 0 THROW 50000, N'{LockBusy}', 1;
                        """, ct);
            }
            catch (System.Data.Common.DbException ex) when (ex.Message.Contains(LockBusy, StringComparison.Ordinal))
            {
                // Another administrator held the lock for the whole wait: a refusal to retry, not a server error.
                _context.ChangeTracker.Clear();
                return ("roles", LockBusy);
            }

            var map = await CommittedMapAsync(ct);
            if (change is { } edit)
                map = map.With(edit.RoleValue, edit.Grants.ToList());

            var refusal = await LeavesAnAdministratorAsync(map, await HeldRolesAsync(ct), except, ct);

            // What the caller staged for this change must not ride along on a later save in the same scope.
            if (refusal is not null)
                _context.ChangeTracker.Clear();
            return refusal;
        }

        private const string LockBusy = "Somebody else is changing the administrators right now: try again.";

        /// <summary>What the roles grant, as committed: the rows this context has staged and not saved yet are not in it.</summary>
        private async Task<RolePermissionMap> CommittedMapAsync(CancellationToken ct)
        {
            var roles = await _context.Set<RoleRow>().AsNoTracking().Select(r => r.RoleValue).ToListAsync(ct);
            var grants = (await _context.Set<RolePermissionRow>().AsNoTracking()
                    .Select(r => new { r.RoleValue, r.PermissionCode }).ToListAsync(ct))
                .ToLookup(r => r.RoleValue, r => r.PermissionCode, StringComparer.Ordinal);

            return new RolePermissionMap(
                roles.ToDictionary(role => role, role => (IReadOnlySet<string>)grants[role].ToHashSet(StringComparer.Ordinal), StringComparer.Ordinal),
                _declared.Codes,
                _roles.MemberCodes);
        }

        /// <summary>Saves the staged change and its audit entry. If Graph already changed, the log line is the record.</summary>
        private async Task SaveAuditedAsync(AdminActor actor, string what, string details)
        {
            try
            {
                await _context.SaveChangesAsync(CancellationToken.None);
            }
            catch (Exception ex)
            {
                _logger.LogCritical(ex,
                    "AUDIT WRITE FAILED. {Actor} ({ActorId}) changed {What}: {Details}.",
                    actor.Identity.Email, actor.Identity.SubjectId, what, details);
                throw;
            }
        }

        private async Task NotifyAsync(DirectoryUser target, IReadOnlyList<string> added, IReadOnlyList<string> removed, AdminActor actor)
        {
            try
            {
                await _notifier.NotifyAsync(new AccessChange(
                    UserRoleRow.Normalize(target.ObjectId),
                    target.Label,
                    added,
                    removed,
                    actor.Identity.SubjectId,
                    actor.Identity.Email ?? actor.Identity.SubjectId ?? "(unknown)",
                    DateTimeOffset.UtcNow), CancellationToken.None);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "The access change of {ObjectId} was applied but could not be published.", target.ObjectId);
            }
        }

        // ── Reading ──────────────────────────────────────────────────────────────

        /// <summary>A person as the administration sees them: Entra's half and the database's half.</summary>
        private sealed record Person(
            DirectoryUser User, bool InDirectory, bool AccountEnabled, bool IsMember, IReadOnlySet<string> Roles,
            bool IsSuspended = false, DateTime? LastLoginAt = null)
        {
            public bool HasAccess => InDirectory && AccountEnabled && IsMember && !IsSuspended;
        }

        /// <summary>The person, or null when neither Entra nor the database knows them.</summary>
        private async Task<Person?> ReadPersonAsync(string objectId, CancellationToken ct)
        {
            var key = UserRoleRow.Normalize(objectId);

            // The two Graph calls go out together, and the database is read while they travel: one round trip.
            var accountCall = _group.GetUserAsync(objectId, ct);
            var memberCall = _group.HasAccessAsync(objectId, ct);

            var roles = (await _context.Set<UserRoleRow>().AsNoTracking()
                    .Where(r => r.ObjectId == key).Select(r => r.RoleValue).ToListAsync(ct))
                .ToHashSet(StringComparer.Ordinal);
            var profile = !_profiles ? null : await _context.Set<UserProfileRow>().AsNoTracking().FirstOrDefaultAsync(p => p.ObjectId == key, ct);

            await Task.WhenAll(accountCall, memberCall);

            var account = await accountCall;
            if (account is null)
                return roles.Count == 0 ? null : new Person(Unknown(key), false, false, false, roles, profile is { IsActive: false }, profile?.LastLoginAt);

            return new Person(account.User, true, account.AccountEnabled, await memberCall, roles, profile is { IsActive: false }, profile?.LastLoginAt);
        }

        /// <summary>Who holds which role: object id → role values.</summary>
        private async Task<IReadOnlyDictionary<string, IReadOnlySet<string>>> HeldRolesAsync(CancellationToken ct)
        {
            var rows = await _context.Set<UserRoleRow>().AsNoTracking()
                .Select(r => new { r.ObjectId, r.RoleValue })
                .ToListAsync(ct);

            return rows
                .GroupBy(r => r.ObjectId, StringComparer.Ordinal)
                .ToDictionary(g => g.Key, g => (IReadOnlySet<string>)g.Select(r => r.RoleValue).ToHashSet(StringComparer.Ordinal), StringComparer.Ordinal);
        }

        /// <summary>The profiles: object id → profile. Most people have none (no row means active).</summary>
        private async Task<IReadOnlyDictionary<string, UserProfileRow>> ProfilesAsync(CancellationToken ct) =>
            !_profiles
                ? new Dictionary<string, UserProfileRow>(StringComparer.Ordinal)
                : await _context.Set<UserProfileRow>().AsNoTracking().ToDictionaryAsync(p => p.ObjectId, StringComparer.Ordinal, ct);

        private static UserProfileRow? ProfileOf(IReadOnlyDictionary<string, UserProfileRow> profiles, string objectId) =>
            profiles.TryGetValue(UserRoleRow.Normalize(objectId), out var profile) ? profile : null;

        private static IReadOnlySet<string> RolesIn(IReadOnlyDictionary<string, IReadOnlySet<string>> held, string objectId) =>
            held.TryGetValue(UserRoleRow.Normalize(objectId), out var roles) ? roles : new HashSet<string>(StringComparer.Ordinal);

        private static DirectoryUser Unknown(string objectId) => new(objectId, null, null, null, false);

        /// <summary>Everything a role answer needs, read once: the map, the roles' names, who holds what, the caller's roles.</summary>
        private sealed record RoleContext(
            RolePermissionMap Map,
            IReadOnlyDictionary<string, RoleRow> Rows,
            IReadOnlyDictionary<string, IReadOnlySet<string>> Held,
            IReadOnlySet<string> ActorRoles)
        {
            public string NameOf(string value) => Rows.TryGetValue(value, out var row) ? row.Name : value;
        }

        private async Task<RoleContext> RoleContextAsync(
            AdminActor actor, IReadOnlyDictionary<string, IReadOnlySet<string>> held, CancellationToken ct)
        {
            var map = await _roles.GetAsync(ct);
            var rows = await _context.Set<RoleRow>().AsNoTracking().ToDictionaryAsync(r => r.RoleValue, StringComparer.Ordinal, ct);

            var actorRoles = actor.IsPerson ? RolesIn(held, actor.Identity.SubjectId!) : new HashSet<string>(StringComparer.Ordinal);

            return new RoleContext(map, rows, held, actorRoles);
        }

        private RoleResponse ToRoleResponse(string value, RoleContext context, AdminActor actor)
        {
            context.Rows.TryGetValue(value, out var row);
            var grants = context.Map.GrantsOf(value);
            var covered = context.Map.IsCoveredBy(value, actor.Permissions);

            return new RoleResponse
            {
                Value = value,
                Name = row?.Name ?? value,
                Description = row?.Description,
                Permissions = grants.Where(c => _declared.Find(c) is not null).OrderBy(c => c, StringComparer.Ordinal).ToList(),
                UnknownPermissions = grants.Where(c => _declared.Find(c) is null).OrderBy(c => c, StringComparer.Ordinal).ToList(),
                Configured = grants.Any(c => _declared.Find(c) is not null),
                Assignable = covered,
                Editable = actor.IsPerson && !actor.IsSimulating && covered && !context.ActorRoles.Contains(value),
                UserCount = context.Held.Count(h => h.Value.Contains(value)),
                Version = VersionOf(value, context)
            };
        }

        private AccessUserResponse ToResponse(Person person, AdminActor actor, RoleContext context) =>
            ToResponse(person.User, person.InDirectory, person.AccountEnabled, person.IsMember, person.Roles,
                person.IsSuspended, person.LastLoginAt, actor, context);

        private AccessUserResponse ToResponse(
            DirectoryUser user, bool inDirectory, bool accountEnabled, bool isMember, IReadOnlySet<string> roles,
            UserProfileRow? profile, AdminActor actor, RoleContext context) =>
            ToResponse(user, inDirectory, accountEnabled, isMember, roles, profile is { IsActive: false }, profile?.LastLoginAt, actor, context);

        private AccessUserResponse ToResponse(
            DirectoryUser user, bool inDirectory, bool accountEnabled, bool isMember, IReadOnlySet<string> roles,
            bool isSuspended, DateTime? lastLoginAt, AdminActor actor, RoleContext context)
        {
            var hasAccess = inDirectory && accountEnabled && isMember && !isSuspended;
            return new AccessUserResponse
            {
                ObjectId = UserRoleRow.Normalize(user.ObjectId),
                DisplayName = user.DisplayName,
                Email = user.Email,
                UserPrincipalName = user.UserPrincipalName,
                IsGuest = user.IsGuest,
                InDirectory = inDirectory,
                AccountEnabled = accountEnabled,
                IsMember = isMember,
                HasAccess = hasAccess,
                IsSuspended = isSuspended,
                LastLoginAt = lastLoginAt,
                IsSelf = actor.Is(user.ObjectId),
                Roles = roles
                    .OrderBy(value => value, StringComparer.Ordinal)
                    .Select(value => new AssignedRoleResponse
                    {
                        Value = value,
                        Name = context.NameOf(value),
                        Configured = context.Map.EffectivePermissions(new[] { value }).Count > 0,
                        Assignable = context.Map.IsCoveredBy(value, actor.Permissions)
                    })
                    .ToList(),
                Permissions = hasAccess
                    ? context.Map.ForMember(roles).OrderBy(code => code, StringComparer.Ordinal).ToList()
                    : new List<string>()
            };
        }

        /// <summary>
        /// A short fingerprint of a role as read (name, description and what it grants), for optimistic concurrency.
        /// </summary>
        private static string VersionOf(string roleValue, RoleContext context)
        {
            context.Rows.TryGetValue(roleValue, out var row);
            var text = string.Join("\n", new[] { row?.Name ?? roleValue, row?.Description ?? string.Empty }
                .Concat(context.Map.GrantsOf(roleValue).OrderBy(c => c, StringComparer.Ordinal)));
            return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text)))[..16];
        }

        private static List<string> Codes(IEnumerable<string>? codes) =>
            (codes ?? Array.Empty<string>())
                .Where(code => !string.IsNullOrWhiteSpace(code))
                .Select(code => code.Trim())
                .Distinct(StringComparer.Ordinal)
                .ToList();

        private static string? Clean(string? text) => string.IsNullOrWhiteSpace(text) ? null : text.Trim();
    }
}
