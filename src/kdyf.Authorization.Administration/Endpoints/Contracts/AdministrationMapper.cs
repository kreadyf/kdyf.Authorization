using kdyf.Authorization.Administration.Models;

namespace kdyf.Authorization.Administration.Endpoints.Contracts
{
    /// <summary>Between the wire contract and the administration services' models, field by field.</summary>
    internal static class AdministrationMapper
    {
        // ── Into the services ────────────────────────────────────────────────

        public static SetRolesRequest ToRequest(SetRolesRequestDto request) =>
            new() { Roles = request.Roles.ToList() };

        public static CreateRoleRequest ToRequest(CreateRoleRequestDto request) => new()
        {
            Value = request.Value,
            Name = request.Name,
            Description = request.Description,
            Permissions = request.Permissions.ToList()
        };

        public static UpdateRoleRequest ToRequest(UpdateRoleRequestDto request) =>
            new() { Name = request.Name, Description = request.Description };

        public static SetRolePermissionsRequest ToRequest(SetRolePermissionsRequestDto request) =>
            new() { Permissions = request.Permissions.ToList(), Version = request.Version };

        public static InviteRequest ToRequest(InviteRequestDto request) =>
            new() { Email = request.Email, DisplayName = request.DisplayName };

        public static AuditFilter ToFilter(AuditFilterDto? filter) => new()
        {
            TargetType = filter?.TargetType,
            TargetId = filter?.TargetId,
            ActorObjectId = filter?.ActorObjectId,
            Action = filter?.Action,
            SearchBy = filter?.SearchBy,
            From = filter?.From,
            To = filter?.To
        };

        public static CreatePatRequest ToRequest(CreateTokenRequestDto request) =>
            new() { Name = request.Name, ExpiresAt = request.ExpiresAt, OwnerObjectId = request.OwnerObjectId };

        // ── Out of the services ──────────────────────────────────────────────

        public static AccessUserDto ToDto(AccessUserResponse user) => new()
        {
            ObjectId = user.ObjectId,
            DisplayName = user.DisplayName,
            Email = user.Email,
            UserPrincipalName = user.UserPrincipalName,
            IsGuest = user.IsGuest,
            InDirectory = user.InDirectory,
            AccountEnabled = user.AccountEnabled,
            IsMember = user.IsMember,
            HasAccess = user.HasAccess,
            IsSelf = user.IsSelf,
            Roles = user.Roles.Select(r => new AssignedRoleDto { Value = r.Value, Name = r.Name, Configured = r.Configured, Assignable = r.Assignable }).ToList(),
            Permissions = user.Permissions.ToList()
        };

        public static RoleDto ToDto(RoleResponse role) => new()
        {
            Value = role.Value,
            Name = role.Name,
            Description = role.Description,
            Permissions = role.Permissions.ToList(),
            UnknownPermissions = role.UnknownPermissions.ToList(),
            Configured = role.Configured,
            Assignable = role.Assignable,
            Editable = role.Editable,
            UserCount = role.UserCount,
            Version = role.Version
        };

        public static RoleOrphansDto ToDto(RoleConsistencyResponse report) => new()
        {
            UnconfiguredRoles = report.UnconfiguredRoles.ToList(),
            UnknownPermissions = report.UnknownPermissions.Select(ToDto).ToList(),
            UndeclaredCatalogPermissions = report.UndeclaredCatalogPermissions.ToList(),
            FormerMembers = report.FormerMembers.Select(ToDto).ToList()
        };

        public static OrphanCleanupDto ToDto(OrphanCleanupResponse cleanup) => new()
        {
            RemovedPermissions = cleanup.RemovedPermissions.Select(ToDto).ToList(),
            RemovedCatalogPermissions = cleanup.RemovedCatalogPermissions.ToList(),
            RemovedMembers = cleanup.RemovedMembers.Select(ToDto).ToList()
        };

        public static PermissionDto ToDto(PermissionResponse permission) => new()
        {
            PermissionCode = permission.PermissionCode,
            Name = permission.Name,
            Description = permission.Description,
            IsPattern = permission.IsPattern,
            HeldByEveryMember = permission.HeldByEveryMember
        };

        public static DirectoryUserDto ToDto(DirectoryUserResponse user) => new()
        {
            ObjectId = user.ObjectId,
            DisplayName = user.DisplayName,
            Email = user.Email,
            UserPrincipalName = user.UserPrincipalName,
            IsGuest = user.IsGuest,
            IsMember = user.IsMember,
            Roles = user.Roles.ToList()
        };

        public static InviteResponseDto ToDto(InviteResponse invitation) => new()
        {
            User = ToDto(invitation.User),
            WasInvited = invitation.WasInvited,
            InvitationEmailSent = invitation.InvitationEmailSent,
            RedeemUrl = invitation.RedeemUrl
        };

        public static PagedResultDto<AuditEntryDto> ToDto(PagedResult<AuditEntryResponse> page) => new()
        {
            TotalCount = page.TotalCount,
            Skip = page.Skip,
            Take = page.Take,
            Count = page.Count,
            Result = page.Result.Select(e => new AuditEntryDto
            {
                AuditLogId = e.AuditLogId,
                OccurredAt = e.OccurredAt,
                ActorObjectId = e.ActorObjectId,
                ActorEmail = e.ActorEmail,
                Action = e.Action,
                TargetType = e.TargetType,
                TargetId = e.TargetId,
                TargetLabel = e.TargetLabel,
                Details = e.Details
            }).ToList()
        };

        public static TokenDto ToDto(PatResponse token) => new()
        {
            PersonalAccessTokenId = token.PersonalAccessTokenId,
            Name = token.Name,
            TokenPrefix = token.TokenPrefix,
            OwnerObjectId = token.OwnerObjectId,
            OwnerEmail = token.OwnerEmail,
            IsActive = token.IsActive,
            OwnerHasAccess = token.OwnerHasAccess,
            ExpiresAt = token.ExpiresAt,
            CreatedAt = token.CreatedAt,
            LastUsedAt = token.LastUsedAt,
            Permissions = token.Permissions.ToList()
        };

        public static CreatedTokenDto ToDto(CreatePatResponse created) => new()
        {
            PersonalAccessTokenId = created.PersonalAccessTokenId,
            Name = created.Name,
            Token = created.Token,
            TokenPrefix = created.TokenPrefix,
            ExpiresAt = created.ExpiresAt,
            OwnerObjectId = created.OwnerObjectId,
            OwnerEmail = created.OwnerEmail,
            Permissions = created.Permissions.ToList()
        };

        private static ConfiguredRoleDto ToDto(ConfiguredRoleResponse role) =>
            new() { Value = role.Value, Permissions = role.Permissions.ToList() };

        private static FormerMemberDto ToDto(FormerMemberResponse member) => new()
        {
            ObjectId = member.ObjectId,
            Label = member.Label,
            InDirectory = member.InDirectory,
            Roles = member.Roles.ToList()
        };
    }
}
