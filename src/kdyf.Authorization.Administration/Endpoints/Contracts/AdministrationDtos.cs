namespace kdyf.Authorization.Administration.Endpoints.Contracts
{
    // The wire contract of the administration endpoints. Kept apart from the services' models so the JSON a client
    // reads changes only when this file does.

    // ── People ───────────────────────────────────────────────────────────────

    internal class AccessUserDto
    {
        public required string ObjectId { get; init; }
        public string? DisplayName { get; init; }
        public string? Email { get; init; }
        public string? UserPrincipalName { get; init; }
        public bool IsGuest { get; init; }
        public bool InDirectory { get; init; }
        public bool AccountEnabled { get; init; }
        public bool IsMember { get; init; }
        public bool HasAccess { get; init; }
        public bool IsSuspended { get; init; }
        public DateTime? LastLoginAt { get; init; }
        public bool IsSelf { get; init; }
        public List<AssignedRoleDto> Roles { get; init; } = new();
        public List<string> Permissions { get; init; } = new();
    }

    internal class AssignedRoleDto
    {
        public required string Value { get; init; }
        public required string Name { get; init; }
        public bool Configured { get; init; }
        public bool Assignable { get; init; }
    }

    internal class SetRolesRequestDto
    {
        public List<string> Roles { get; init; } = new();
    }

    // ── Roles and catalog ────────────────────────────────────────────────────

    internal class RoleDto
    {
        public required string Value { get; init; }
        public required string Name { get; init; }
        public string? Description { get; init; }
        public List<string> Permissions { get; init; } = new();
        public List<string> UnknownPermissions { get; init; } = new();
        public bool Configured { get; init; }
        public bool Assignable { get; init; }
        public bool Editable { get; init; }
        public int UserCount { get; init; }
        public required string Version { get; init; }
    }

    internal class CreateRoleRequestDto
    {
        public string Value { get; init; } = string.Empty;
        public string? Name { get; init; }
        public string? Description { get; init; }
        public List<string> Permissions { get; init; } = new();
    }

    internal class UpdateRoleRequestDto
    {
        public string Name { get; init; } = string.Empty;
        public string? Description { get; init; }

        /// <summary>Optional: the complete set of permissions, changed with the name in one transaction.</summary>
        public List<string>? Permissions { get; init; }

        public string? Version { get; init; }
    }

    internal class SetRolePermissionsRequestDto
    {
        public List<string> Permissions { get; init; } = new();
        public string? Version { get; init; }
    }

    internal class RoleOrphansDto
    {
        public List<string> UnconfiguredRoles { get; init; } = new();
        public List<ConfiguredRoleDto> UnknownPermissions { get; init; } = new();
        public List<string> UndeclaredCatalogPermissions { get; init; } = new();
        public List<FormerMemberDto> FormerMembers { get; init; } = new();
    }

    internal class OrphanCleanupDto
    {
        public List<ConfiguredRoleDto> RemovedPermissions { get; init; } = new();
        public List<string> RemovedCatalogPermissions { get; init; } = new();
        public List<FormerMemberDto> RemovedMembers { get; init; } = new();
    }

    internal class ConfiguredRoleDto
    {
        public required string Value { get; init; }
        public List<string> Permissions { get; init; } = new();
    }

    internal class FormerMemberDto
    {
        public required string ObjectId { get; init; }
        public string? Label { get; init; }
        public bool InDirectory { get; init; }
        public List<string> Roles { get; init; } = new();
    }

    internal class PermissionDto
    {
        public required string PermissionCode { get; init; }
        public string? Name { get; init; }
        public string? Description { get; init; }
        public bool IsPattern { get; init; }
        public bool HeldByEveryMember { get; init; }
    }

    // ── Directory ────────────────────────────────────────────────────────────

    internal class DirectoryUserDto
    {
        public required string ObjectId { get; init; }
        public string? DisplayName { get; init; }
        public string? Email { get; init; }
        public string? UserPrincipalName { get; init; }
        public bool IsGuest { get; init; }
        public bool IsMember { get; init; }
        public List<string> Roles { get; init; } = new();
    }

    internal class InviteRequestDto
    {
        public string Email { get; init; } = string.Empty;
        public string? DisplayName { get; init; }

        /// <summary>Optional: roles to add in the same operation.</summary>
        public List<string> Roles { get; init; } = new();
    }

    internal class InviteResponseDto
    {
        public required DirectoryUserDto User { get; init; }
        public bool WasInvited { get; init; }
        public bool InvitationEmailSent { get; init; }
        public string? RedeemUrl { get; init; }
    }

    // ── Audit log ────────────────────────────────────────────────────────────

    internal class AuditFilterDto
    {
        public string? TargetType { get; init; }
        public string? TargetId { get; init; }
        public string? ActorObjectId { get; init; }
        public string? Action { get; init; }
        public string? SearchBy { get; init; }
        public DateTime? From { get; init; }
        public DateTime? To { get; init; }
    }

    internal class AuditEntryDto
    {
        public long AuditLogId { get; init; }
        public DateTime OccurredAt { get; init; }
        public string? ActorObjectId { get; init; }
        public required string ActorEmail { get; init; }
        public required string Action { get; init; }
        public required string TargetType { get; init; }
        public string? TargetId { get; init; }
        public required string TargetLabel { get; init; }
        public string? Details { get; init; }
    }

    internal class PagedResultDto<T>
    {
        public int TotalCount { get; init; }
        public int Skip { get; init; }
        public int Take { get; init; }
        public int Count { get; init; }
        public List<T> Result { get; init; } = new();
    }

    // ── Personal access tokens ───────────────────────────────────────────────

    internal class CreateTokenRequestDto
    {
        public string Name { get; init; } = string.Empty;
        public DateTime? ExpiresAt { get; init; }
        public string? OwnerObjectId { get; init; }
    }

    internal class CreatedTokenDto
    {
        public int PersonalAccessTokenId { get; init; }
        public required string Name { get; init; }
        public required string Token { get; init; }
        public string? TokenPrefix { get; init; }
        public DateTime? ExpiresAt { get; init; }
        public required string OwnerObjectId { get; init; }
        public required string OwnerEmail { get; init; }
        public List<string> Permissions { get; init; } = new();
    }

    internal class TokenDto
    {
        public int PersonalAccessTokenId { get; init; }
        public required string Name { get; init; }
        public string? TokenPrefix { get; init; }
        public required string OwnerObjectId { get; init; }
        public required string OwnerEmail { get; init; }
        public bool IsActive { get; init; }
        public bool OwnerHasAccess { get; init; }
        public DateTime? ExpiresAt { get; init; }
        public DateTime CreatedAt { get; init; }
        public DateTime? LastUsedAt { get; init; }
        public List<string> Permissions { get; init; } = new();
    }
}
