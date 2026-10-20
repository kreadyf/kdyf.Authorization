# Changelog

Every package of a release carries the same version. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versions follow [SemVer 2](https://semver.org/).

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
