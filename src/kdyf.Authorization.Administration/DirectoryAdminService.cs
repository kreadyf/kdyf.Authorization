using System.Text.Json;
using kdyf.Authorization.Administration.Abstractions;
using kdyf.Authorization.Administration.Models;
using kdyf.Authorization.Administration.Validation;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using UserRoleRow = kdyf.Authorization.EntityFrameworkCore.Entities.UserRole;

namespace kdyf.Authorization.Administration
{
    /// <inheritdoc cref="IDirectoryAdminService"/>
    /// <typeparam name="TContext">Consumer's DbContext with both models applied: the roles are read from it, and
    /// an invitation is audited.</typeparam>
    internal sealed class DirectoryAdminService<TContext> : IDirectoryAdminService where TContext : DbContext
    {
        /// <summary>Below this the tenant-wide search would list half the directory.</summary>
        private const int MinimumSearchLength = 2;

        private readonly TContext _context;
        private readonly IDirectoryService _directory;
        private readonly IAccessDirectory _group;
        private readonly IAuditLog _audit;
        private readonly ILogger<DirectoryAdminService<TContext>> _logger;
        private readonly IInvitationNotifier? _notifier;
        private readonly IAccessAdminService? _access;

        /// <remarks>
        /// <c>notifier</c> is optional: without it the invitation e-mail is left to the directory, or the
        /// redeem link comes back in the response for the administrator to pass along.
        /// </remarks>
        public DirectoryAdminService(
            TContext context,
            IDirectoryService directory,
            IAccessDirectory group,
            IAuditLog audit,
            ILogger<DirectoryAdminService<TContext>> logger,
            IInvitationNotifier? notifier = null,
            IAccessAdminService? access = null)
        {
            _access = access;
            _context = context;
            _directory = directory;
            _group = group;
            _audit = audit;
            _logger = logger;
            _notifier = notifier;
        }

        public async Task<ValidationResult<List<DirectoryUserResponse>>> SearchAsync(string? search, CancellationToken ct)
        {
            var term = search?.Trim() ?? string.Empty;
            if (term.Length < MinimumSearchLength)
                return Outcome.Error<List<DirectoryUserResponse>>("search", $"Type at least {MinimumSearchLength} characters.");

            try
            {
                var found = await _directory.SearchAsync(term, ct);
                var members = (await _group.ListWithAccessAsync(ct))
                    .Select(m => UserRoleRow.Normalize(m.User.ObjectId))
                    .ToHashSet(StringComparer.Ordinal);
                var held = await HeldRolesAsync(found.Select(u => UserRoleRow.Normalize(u.ObjectId)).ToList(), ct);

                return Outcome.Ok(found
                    .Select(user => ToResponse(user, members.Contains(UserRoleRow.Normalize(user.ObjectId)), held))
                    .ToList());
            }
            catch (DirectoryException ex)
            {
                _logger.LogError(ex, "The directory could not be searched.");
                return Outcome.Error<List<DirectoryUserResponse>>("directory", ex.Message);
            }
        }

        public async Task<ValidationResult<InviteResponse>> InviteAsync(InviteRequest request, AdminActor actor, CancellationToken ct)
        {
            if (actor.IsSimulating || !actor.IsPerson)
                return Outcome.Error<InviteResponse>("actor", "Invitations can only be sent from an interactive sign-in that is not simulating.");

            var email = (request.Email ?? string.Empty).Trim().ToLowerInvariant();
            if (email.Length == 0 || !email.Contains('@'))
                return Outcome.Error<InviteResponse>("email", "A valid e-mail is required.");

            // Roles are checked BEFORE anybody is invited: a refusal must not leave a guest behind.
            var roles = (request.Roles ?? new List<string>()).Where(r => !string.IsNullOrWhiteSpace(r)).Select(r => r.Trim()).Distinct(StringComparer.Ordinal).ToList();
            if (roles.Count > 0)
            {
                if (_access is null)
                    return Outcome.Error<InviteResponse>("roles", "Roles cannot be given with an invitation here: the access administration is not registered.");
                var grantable = await _access.CheckGrantableAsync(roles, actor, ct);
                if (!grantable.Validation.IsValid)
                    return Outcome.Error<InviteResponse>("roles", Messages(grantable));
            }

            try
            {
                // Somebody already in the tenant (a member, or a guest invited before) is not invited again: a
                // second invitation creates nothing and confuses the person. They are brought into the group.
                var existing = await _directory.FindByEmailAsync(email, ct);
                if (existing is not null)
                {
                    if (actor.Is(existing.ObjectId))
                        return Outcome.Error<InviteResponse>("email", "Nobody changes their own access. Ask another administrator.");

                    var wasMember = await _group.HasAccessAsync(existing.ObjectId, ct);
                    if (!wasMember)
                    {
                        // Roles left behind from before switch back on as they join: they are given now, by this
                        // administrator, under the same rule as the roles of the invitation. Checked before the group.
                        var key = UserRoleRow.Normalize(existing.ObjectId);
                        var leftBehind = (await HeldRolesAsync(new[] { key }, ct)).TryGetValue(key, out var kept) ? kept : new List<string>();
                        if (leftBehind.Count > 0)
                        {
                            if (_access is null)
                                return Outcome.Error<InviteResponse>("roles", "They still hold roles from before, and the access administration that checks them is not registered here.");
                            var revived = await _access.CheckGrantableAsync(leftBehind, actor, ct);
                            if (!revived.Validation.IsValid)
                                return Outcome.Error<InviteResponse>("roles",
                                    "They still hold roles from before, which joining the group would switch back on: " + Messages(revived));
                        }

                        await _group.GrantAsync(existing.ObjectId, CancellationToken.None);
                        Record(actor, "access.granted", existing.ObjectId, email, new { added = Array.Empty<string>(), removed = Array.Empty<string>() });
                        await _context.SaveChangesAsync(CancellationToken.None);
                    }

                    if (await GiveRolesAsync(existing.ObjectId, roles, actor, ct) is { } refused)
                        return refused;

                    var held = await HeldRolesAsync(new[] { UserRoleRow.Normalize(existing.ObjectId) }, ct);
                    return Outcome.Ok(new InviteResponse { User = ToResponse(existing, isMember: true, held), WasInvited = false });
                }

                var invitation = await _directory.InviteAsync(email, request.DisplayName, CancellationToken.None);

                // B2B creates the guest at once, so they can join the group before redeeming. If that fails the
                // guest exists and the invitation stands: the administrator retries, and is not invited twice.
                await _group.GrantAsync(invitation.User.ObjectId, CancellationToken.None);

                Record(actor, "directory.invited", invitation.User.ObjectId, email, new { displayName = request.DisplayName, addedToGroup = true, roles });
                await _context.SaveChangesAsync(CancellationToken.None);

                if (await GiveRolesAsync(invitation.User.ObjectId, roles, actor, ct) is { } notGiven)
                    return notGiven;

                var sent = invitation.EmailSent || await NotifyAsync(email, request.DisplayName, invitation, ct);

                return Outcome.Ok(new InviteResponse
                {
                    User = ToResponse(invitation.User, isMember: true, await HeldRolesAsync(new[] { UserRoleRow.Normalize(invitation.User.ObjectId) }, ct)),
                    WasInvited = true,
                    InvitationEmailSent = sent,
                    // Only when nothing went out: then it is the administrator's to pass on.
                    RedeemUrl = sent ? null : invitation.RedeemUrl
                });
            }
            catch (DirectoryException ex)
            {
                _logger.LogError(ex, "Bringing {Email} into the access group failed.", email);
                return Outcome.Error<InviteResponse>("email", ex.Message);
            }
        }

        private static string Messages(ValidationResult result) =>
            string.Join(" ", result.Validation.Errors.Concat(result.Validation.Fields.Values.SelectMany(f => f.Errors)));

        private static readonly IReadOnlyDictionary<string, List<string>> EmptyHeld = new Dictionary<string, List<string>>();

        /// <summary>
        /// Adds <paramref name="roles"/> to what the person holds, through the access administration: its rules and its
        /// audit entry. Null when done (or nothing to do); the refusal otherwise.
        /// </summary>
        private async Task<ValidationResult<InviteResponse>?> GiveRolesAsync(string objectId, List<string> roles, AdminActor actor, CancellationToken ct)
        {
            if (roles.Count == 0 || _access is null)
                return null;

            var current = await HeldRolesAsync(new[] { UserRoleRow.Normalize(objectId) }, ct);
            var all = (current.TryGetValue(UserRoleRow.Normalize(objectId), out var held) ? held : new List<string>())
                .Union(roles, StringComparer.Ordinal)
                .ToList();

            var result = await _access.SetRolesAsync(objectId, new SetRolesRequest { Roles = all }, actor, CancellationToken.None);
            return result.Validation.IsValid
                ? null
                : Outcome.Error<InviteResponse>("roles",
                    "They are in the access group, but their roles were not given: " + Messages(result));
        }

        private void Record(AdminActor actor, string action, string objectId, string label, object details) =>
            _audit.Record(AuditActor.From(actor.Identity), new AuditEntry(
                action, "user", UserRoleRow.Normalize(objectId), label, JsonSerializer.Serialize(details)));

        /// <summary>
        /// Sends the invitation ourselves when the directory did not. A failure does NOT fail the flow: the
        /// guest already exists, and the response carries the redeem link either way.
        /// </summary>
        private async Task<bool> NotifyAsync(string email, string? displayName, DirectoryInvitation invitation, CancellationToken ct)
        {
            if (_notifier is null || string.IsNullOrWhiteSpace(invitation.RedeemUrl))
                return false;

            try
            {
                await _notifier.SendAsync(new InvitationNotice(email, displayName, invitation.RedeemUrl), ct);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "{Email} was invited, but the invitation e-mail could not be sent.", email);
                return false;
            }
        }

        private async Task<IReadOnlyDictionary<string, List<string>>> HeldRolesAsync(IReadOnlyCollection<string> objectIds, CancellationToken ct)
        {
            if (objectIds.Count == 0)
                return EmptyHeld;

            var rows = await _context.Set<UserRoleRow>().AsNoTracking()
                .Where(r => objectIds.Contains(r.ObjectId))
                .Select(r => new { r.ObjectId, r.RoleValue })
                .ToListAsync(ct);

            return rows
                .GroupBy(r => r.ObjectId, StringComparer.Ordinal)
                .ToDictionary(g => g.Key, g => g.Select(r => r.RoleValue).OrderBy(v => v, StringComparer.Ordinal).ToList(), StringComparer.Ordinal);
        }

        private static DirectoryUserResponse ToResponse(DirectoryUser user, bool isMember, IReadOnlyDictionary<string, List<string>> held) => new()
        {
            ObjectId = UserRoleRow.Normalize(user.ObjectId),
            DisplayName = user.DisplayName,
            Email = user.Email,
            UserPrincipalName = user.UserPrincipalName,
            IsGuest = user.IsGuest,
            IsMember = isMember,
            Roles = held.TryGetValue(UserRoleRow.Normalize(user.ObjectId), out var roles) ? roles : new List<string>()
        };
    }
}
