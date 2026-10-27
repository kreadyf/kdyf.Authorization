# Changelog

Every package of a release carries the same version. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versions follow [SemVer 2](https://semver.org/).

## 1.2.1

No change to the code or the public API: documentation and package metadata only.

### Documentation

- **Each package has its own page on nuget.org.** A short `PACKAGE.md` per project says what that package does, how to
  install it, a small sample and its siblings, and links to the full README. Before, all seven pages showed the root README.
- README: a package table with links to nuget.org and version badges, and the `dotnet add package` /
  `dotnet tool install` commands.
- README corrections:
  - The first administrator's SQL grants the code the `AdministeredBy` policy demands, area included
    (`fabrikam.Administration`), not a literal `DataAdministration`.
  - `AcceptRoleClaimsForUserPrincipals` cannot be turned on through `AddKdyfAuthorization`.
  - Which obsolete wildcard APIs do nothing (`AreaWildcards()`) and which answer with the hierarchy
    (`PermissionWildcards`, `WildcardExpandingPermissionStore`, `ExpandWildcards()`).
  - The `Unsupported` schema state is listed.
  - The simulation is recorded in the audit log only with the administration package.
  - Writes refused during a simulation, and `[ReadOnlyOperation]` for a POST that only reads.
  - `Directory:TenantId` / `Directory:ClientId` for a separate Graph app registration.
  - The link to `docs/auth-migrate-permission-hierarchy.sql` is absolute, so it works on nuget.org.
- SECURITY.md: the fallback policy demands the access gate, not only a session. Minor versions keep the public API,
  and behaviour changes are listed under "Changed".

### Package metadata

- The `kdyf.Authorization` description names the permission tree instead of wildcards.
- `PackageReleaseNotes` points to this changelog, and each package adds tags of its own.

## 1.2.0

### Changed — read before upgrading

- **The permission tree replaces wildcards.** A granted code covers itself and every code below it, segment by segment:
  `fabrikam` covers `fabrikam.Controlling` and `fabrikam.Invoicing.Invoices`, not `fabrikamArchive.X`; the root `""`
  covers everything. Grant `""` where a role granted `*`, and `area` where it granted `area.*`.
- **Every ancestor and the root are in the catalog** without a class (`PermissionNode`), at every level and whatever the
  number of permissions below them, and the startup sync writes their rows. An implicit node never overwrites the name or
  description of its row; a class with an empty code in an area's namespace gives the node its name.
- **A role that grants a parent of other codes now holds them.** Check the stored grants before upgrading (README,
  "Upgrading from wildcards").
- **Wildcards are refused as input**: a declaration with `*` is left out of the catalog (warned at startup), an
  administration request granting `*` is refused, a policy cannot demand one.
- The handler, the policy report and the simulation check compare with `PermissionHierarchy.Covers`, also for role claims
  (personal access tokens, application tokens).

### Added

- `PermissionHierarchy`: `Root`, `IsValidCode`, `Covering`, `Ancestors`, `Covers`, `Expand`, and the reading of the
  legacy spellings (`TryNormalizeStoredGrant`, `NormalizeStoredGrants`, `LegacySpellingOf`).
- `PermissionNode` and `DeclaredPermissions.IsExplicit` / `IgnoredWildcards`.
- `HierarchyExpandingPermissionStore` and `PermissionAuthorizationBuilder.ExpandHierarchy()`.
- `docs/auth-migrate-permission-hierarchy.sql`: the post-deployment rewrite of `*` / `area.*` rows (dry run, one
  transaction, verified, optional `CHECK` constraints).
- Package validation against the published 1.1.0 API.

### Deprecated

- `PermissionWildcards`, `AreaWildcards`, `AreaWildcard`, `WildcardExpandingPermissionStore`, `ExpandWildcards()`,
  `KdyfAuthorizationBuilder.AreaWildcards()`, `PermissionAuthorizationOptions.AreaWildcards` / `AreaWildcardExceptions`
  and `PermissionDefinition.IsPattern`: they answer with the hierarchy or do nothing, and go in 2.0.
  `PermissionResponse.IsPattern` is always false.

### Transition

- Rows written before 1.2.0 are read as their nodes (`*` as `""`, `area.*` as `area`); a malformed one (`.*`, `a..*`,
  `*.*`) grants nothing. Removing a node from a role also removes its legacy row. The orphan cleanup leaves legacy
  wildcard rows to the migration script, and the legacy import copies `*` / `area.*` as their nodes.

## 1.1.0

### Added

- **Area wildcards without a class**: `auth.AreaWildcards()` declares `area.*` for every area (the first segment of a
  code) with at least two permissions, so a new area comes with its wildcard. Its row is written at startup and a role
  may grant it like any declared wildcard; a wildcard declared by a class wins. `AreaWildcards(except: ...)` leaves
  areas out, and an excepted name that is not an area stops the host at registration. Off by default. The derivation is
  public (`AreaWildcards.Derive`, `AreaWildcard`) for hosts composing with `AddPermissionAuthorization`
  (`PermissionAuthorizationOptions.AreaWildcards`, `AreaWildcardExceptions`).
- `PermissionCatalogSyncOptions.FromDeclaredPermissions`: the catalog sync writes the rows from the registered
  `DeclaredPermissions` — the catalog authorization reads — instead of scanning the assemblies. `UseEntityFrameworkStore`
  turns it on, so the rows and the role checks come from one list.

## 1.0.0

Changes since 1.0.0-preview.3.

### Changed — read before upgrading

- **The fallback and default policies demand the access gate**, not only a session (`AccessGateRequirement`): a person
  must hold at least one permission, a personal access token or an application token must carry one. An endpoint with
  no permission of its own is no longer open to every account of the tenant. `auth/me` and `auth/policies` use the new
  `KdyfAuthorizationPolicies.SignedIn` (a session only); `auth.SignedInIsEnough()` restores the previous behaviour.
  A host whose members all hold something through `EveryMemberHolds` sees no difference.
- **Public API reduced to what a host uses.** About 60 implementation types of `Migrations`, `Administration` and the
  core became internal. `AddSmtpInvitationNotifier` moved to `SmtpInvitationNotifierExtensions`.
- **Object ids are normalized** (lower-case GUID) when a token is resolved and when a personal access token is created
  for somebody, so one person has one cache entry and one owner key.
- `UserProfile.lastLoginAt` is written only for the person's own session: not for a personal access token (the token has
  its own `lastUsedAt`), not when somebody else's request looks them up, not during a simulation.

### Security

- Re-admitting somebody to the access group with roles left from before, and inviting somebody with such roles, require
  the administrator to cover those roles.
- Renaming a role (alone, with a version, or with its unchanged permissions) requires covering what it grants.
- The last-administrator guard counts again under the administrators' lock (`sp_getapplock`) on the roles and holders
  as committed, read through the change's own transaction: two administrators removing each other, or the
  administration out of two roles, cannot both go through. A refused change leaves nothing staged in the context.
- Personal access tokens: an administrator may switch off anybody's token; switching on and deleting require covering
  the owner's permissions; an owner cannot switch on a token an administrator switched off. Names are limited to
  100 characters.
- An application token is never taken for a person: a person has an e-mail, or delegated scopes, or `idtyp=user`.
- App assignments are read for users only (`principalType = User`), never through a group assignment.
- The permission cache and the role map do not keep a result read before an invalidation.
- Migrations: schema names are validated everywhere they reach SQL; the runtime role cannot change the legacy map or the
  migration issues; `contract` never renames or drops the target, a schema of the new model, or a schema that is not a
  legacy one; `contract drop` runs in one transaction; `promote` grants the runtime role again.

### Fixed

- Microsoft Graph paging stops at 100 pages with an error instead of returning a partial list.
- `Migrating`: a Graph timeout falls back to the group instead of denying.
- The identity review CSV escapes tabs and carriage returns, and a short row is an error.
- `kdyf-auth` help documents `--connection-string`.

### Build and release

- Package validation is on; sibling packages depend on each other with the exact version.
- Release workflow split into a read-only build job and a publish job (Trusted Publishing, `nuget` environment);
  re-running it uploads to an existing GitHub release.
- The SQL Server tests fail, instead of being skipped, when `KDYF_AUTHZ_TEST_SQLSERVER` is set and the server is not
  reachable.

## 1.0.0-preview.3 and earlier

See the [GitHub releases](https://github.com/kreadyf/kdyf.Authorization/releases).
