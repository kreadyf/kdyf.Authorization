# kdyf.Authorization

Permission-based authorization for ASP.NET Core hosts that sign people in with Microsoft Entra ID: permissions and
policies declared as classes, the application's own roles in a database, personal access tokens (PAT), read-only user
simulation, and the administration of access — with optional, ready-made endpoints.

- **Who may use the application at all** is decided in Entra ID, on the server, on every request (cached): membership
  of a security group, or an assignment to the application's Enterprise application. The token's own `roles` and
  `groups` claims never authorize anybody: they are as old as the token.
- **What they may do** is the permissions their roles grant, stored in the application's database (`auth.*` tables,
  EF Core) and administered from the application.
- **Personal access tokens** (`Authorization: PAT <token>`) are worth what their owner holds at that moment.
- **User simulation** (`X-Simulate-User: <e-mail>`): an administrator reads the application as somebody else —
  read-only, only somebody who holds nothing beyond them, recorded in the audit log.

## Packages

All of them ship with the same version.

| Package | What for |
|---|---|
| `kdyf.Authorization` | Core: permissions, policies, cache, the PAT scheme, simulation |
| `kdyf.Authorization.EntityFrameworkCore` | The `auth.*` tables: roles, what they grant, who holds them, PATs, the permission catalog |
| `kdyf.Authorization.EntraId` | Entra ID sign-in and the access gate, through Microsoft Graph |
| `kdyf.Authorization.AspNetCore` | Composition for a host: `AddKdyfAuthorization`, `UseKdyfAuthorization`; optional `GET auth/me`, `GET auth/policies` |
| `kdyf.Authorization.Administration` | Administration: people, roles, PATs, directory and access gate through Graph, audit log, simulation; `AddKdyfAuthorizationAdministration` and the optional endpoints |
| `kdyf.Authorization.Migrations` | The versioned schema (SQL Server): detect, plan, script, apply, verify, adopt; and, temporarily, moving the access gate from a group to app assignments |
| `kdyf.Authorization.Tool` | The `kdyf-auth` dotnet tool: the schema commands without a host |

Every package targets .NET 8 and .NET 10. Namespaces did not change when the former `*.Endpoints`,
`Administration.EntraId` and `Administration.AspNetCore` packages were merged, nor when `EntraId.Migration` became
`Migrations`: a host only changes its package references.

The endpoints expose nothing unless the host calls their `Map…()`. A host that prefers its own endpoints
uses the administration services directly, and a host that keeps its own response envelope registers an
`IKdyfAuthorizationResultWriter`.

## Getting started

A host references `kdyf.Authorization.AspNetCore`, `kdyf.Authorization.EntityFrameworkCore` and
`kdyf.Authorization.EntraId`, plus `kdyf.Authorization.Administration` to administer access and
`kdyf.Authorization.Migrations` (or the `kdyf-auth` tool) to create the tables. In that order:

1. **The tables**: `kdyf-auth apply` (see [Schema versions](#schema-versions)). The host does not create them, and does not
   start below the version it requires.
2. **The declarations**: permissions and policies as classes, in the assemblies the host names.
3. **The composition** below. `UseKdyfAuthorization()` goes after `UseRouting()` (when the host calls it) and before the
   endpoints; it runs authentication, simulation and authorization in that order.
4. **The first administrator** (below): until somebody holds the administration permission, nobody can give roles.

```csharp
// The composition methods need no using: they live in the namespaces a host already imports.
using kdyf.Authorization.Abstractions;    // PermissionDefinition, for your permissions
using kdyf.Authorization.Authorization;   // Policy, for your policies
using kdyf.Authorization.AspNetCore;      // KdyfAuthorizationPolicies
using Microsoft.EntityFrameworkCore;      // UseSqlServer

// Permissions and policies are classes (PermissionDefinition, Policy), discovered in the assemblies you declare.
// A permission's namespace is its area: a class in namespace 'global' declaring "Reports" is 'global.Reports'.

builder.Services.AddKdyfAuthorization(builder.Configuration, "Authorization", auth => auth
    .Declarations(typeof(Program).Assembly)
    .EveryMemberHolds(new MyBaseAccess())     // optional: a permission of yours every member of the gate holds without a role
    .AreaWildcards()                          // optional: a wildcard per area (global.*) without writing its class
    .UseEntityFrameworkStore((db, connectionString) => db.UseSqlServer(connectionString))
    .UseEntraId());

// Optional: user simulation, guarded by one of your policies.
builder.Services.AddKdyfAuthorizationSimulation(MyPolicies.UserSimulation);

// Optional: administration of access, guarded by your policies.
builder.Services.AddKdyfAuthorizationAdministration(admin => admin
    .AdministeredBy(MyPolicies.UserAdministration)
    .TokensManagedBy(MyPolicies.PersonalAccessTokens));

var app = builder.Build();
app.UseKdyfAuthorization();                   // authentication, simulation, authorization
app.MapKdyfAuthorizationSession();            // auth/me, auth/policies
app.MapKdyfAuthorizationAdministration();     // auth/users, auth/roles, auth/pat, ...
app.MapKdyfAuthorizationSimulation();         // auth/simulation/start, end, candidates
```

### Who gets in

A token proves an account of the tenant, not that the application lets it in. So the fallback policy (every endpoint
without authorization metadata) and the default one (a bare `RequireAuthorization()` or `[Authorize]`) demand, besides
a session, the access gate (`AccessGateRequirement`): a person must hold at least one permission — inside the group
or assigned, not suspended, with a role or with what `EveryMemberHolds` gives every member —, and a personal access
token or an application token must carry one. A member with no role in a host without `EveryMemberHolds` gets 403.

- `KdyfAuthorizationPolicies.SignedIn` is a session only: `auth/me` and `auth/policies` use it, so the application can
  tell somebody they have no access. Use it for nothing that reads or changes data.
- `auth.SignedInIsEnough()` makes a session enough for the fallback and default policies, as before 1.0. Only for a
  host whose every endpoint names its permission.
- `AllowAnonymous` still opens an endpoint to everyone (the SPA shell, health checks).

The application's roles authorize people. Entra **app roles** in a token (`roles`) authorize only clients that are not
people — an application with client credentials, or a personal access token, whose permissions are its role claims —,
unless `AcceptRoleClaimsForUserPrincipals` is turned on, which skips the gate, the suspension and the revocation.

### The first administrator

The administration permission (`AdministrationPermissionCode`, `DataAdministration` unless the host names another; the
policy given to `AdministeredBy` must demand it) has to be held by somebody before anybody can give roles. Once, with the
tables created and the host started once (it fills the permission catalog), and with the person in the access gate:

```sql
INSERT INTO auth.Role (roleValue, name, description, createdAt) VALUES ('App.Admin', N'Administrators', NULL, SYSUTCDATETIME());
INSERT INTO auth.RolePermission (roleValue, PermissionCode) VALUES ('App.Admin', 'DataAdministration');
INSERT INTO auth.UserRole (objectId, roleValue) VALUES ('<the person''s Entra object id, lower case>', 'App.Admin');
```

From then on roles are given from the application, under its rules: four eyes, nothing beyond what the administrator
holds, never the last administrator.

### Wildcards

A role may grant `*` (everything) or `area.*` (everything in an area, at any depth) instead of each code. A wildcard is
granted, never demanded: the effective permissions are expanded before anything compares them, so the doors keep naming
exact codes. Only **declared** codes count — a wildcard row in the database that no declaration backs grants nothing.

- `*`, and a nested wildcard such as `fabrikam.Invoicing.*`, are declared like any permission: a class whose code is
  `*` (in namespace `fabrikam.Invoicing` for the nested one).
- `auth.AreaWildcards()` declares `area.*` for every area — the first segment of a code — that has at least two
  permissions, so a new area comes with its wildcard: add `aaa.Reports` and `aaa.Exports`, and `aaa.*` is declared, its
  row written at startup, and a role may grant it. A wildcard declared by a class wins. Off by default: a wildcard grants
  more than it looks like on a roles screen.
- `auth.AreaWildcards(except: "global")` leaves out the areas that must not be granted as a whole. A name that is not an
  area stops the host at registration (names are case-sensitive): a typo would otherwise derive the very wildcard it was
  meant to prevent.

## Configuration

One section, named by the host, validated at startup: with a missing or inconsistent value the host does not start,
and the message names the key.

```jsonc
"Authorization": {
  "ConnectionStringName": "Authorization",    // ConnectionStrings:{name}; the host may also name it in code
  "Schema": "auth",
  "RequireSchemaVersion": false,              // true once every environment is versioned
  "UserProfiles": false,                      // true: keep UserProfile (suspension, last access, legacy ids): schema version 4
  "LastAccessInterval": "00:15:00",           // UserProfile.lastLoginAt written at most this often; 00:00:00 turns it off
  "EntraId": { "TenantId": "…", "ClientId": "…", "Audience": "" },
  "Directory": {
    "Gate": "Group",                          // Group | Migrating | AppAssignment
    "GroupId": "…",                           // Group, Migrating
    "ServicePrincipalId": "…",                // Migrating, AppAssignment
    "AccessAppRoleId": "…",                   // Migrating, AppAssignment
    "MigrationSyncInterval": "00:10:00",      // Migrating: how often the assignments are brought in line with the group
    "InviteRedirectUrl": "https://…",         // where an invited guest lands; required to invite
    "SendInvitationMessage": true,            // false when the host sends its own invitation e-mail (AddSmtpInvitationNotifier)
    "ClientSecret": "…"                       // SECRET: user secrets, environment variables or a vault
  },
  "Authorization": { "CacheDuration": "00:02:00", "EmptyResultCacheDuration": "00:00:30" },
  "Simulation": { "HeaderName": "X-Simulate-User", "SessionIdleTimeout": "00:30:00" }
}
```

Secrets never belong in `appsettings.json`. The Microsoft Graph application permissions depend on the gate:
`User.Read.All`, plus `GroupMember.Read.All` (`GroupMember.ReadWrite.All` to administer) for a group, and
`AppRoleAssignment.ReadWrite.All` for app assignments; `Migrating` needs both, since the group decides while the
assignments are kept in line with it. Inviting guests needs `User.Invite.All`. `AppRoleAssignment.ReadWrite.All` is
powerful — it can assign any app role in the tenant — so give it to a separate app registration used only for Graph,
with its client secret kept in a vault and rotated.

The gate is read when the host starts: changing `Gate` takes a restart. `Gate: "Migrating"` in a host that administers
access also needs `builder.Services.AddKdyfAuthorizationGateMigration()` (kdyf.Authorization.Migrations), after the
administration: the host refuses to start without it.

## People: suspension, last access, invitations

- **Suspension** (`POST/DELETE auth/users/{objectId}/suspension`): the application's own "no". A suspended person holds
  nothing from their next request on, with a session, with a personal access token or as a simulation target; their
  roles and their membership stay for when they are reactivated. It passes the rules of removing their roles: four
  eyes, nothing beyond what the administrator holds, never the last administrator (a suspended one does not count).
- **Last access**: `UserProfile.lastLoginAt`, written when the person uses the application with their own session, at
  most once per `LastAccessInterval` (and only when their permissions are resolved again, after the cache). Not when one
  of their personal access tokens is used — a token has its own `lastUsedAt` —, not when somebody else's request looks
  them up (the administration, the vault of a host, a simulation), and not from a background job. A failure to write it
  never denies anybody.
- **Invitations with roles**: `Roles` on the invitation, checked before anybody is invited and added to what the
  person already holds, never replacing it.
- **A role in one go**: `PUT auth/roles/{role}` with `Permissions` (and `Version`) changes the name, the description
  and what it grants in one transaction and one audit entry. The version covers the name and description too.

People live in `UserProfile` only when something is known about them: no row means an active person.

`UserProfile` is optional. With `"UserProfiles": false` (the default) the schema is the six tables of version 3, as
the reference databases have them: nobody can be suspended and no last access is recorded. A host that imports a legacy
database, or suspends people, sets `"UserProfiles": true`, and `kdyf-auth apply` (which follows the host's setting, or
`--user-profiles`) takes the schema to version 4. It can be turned on later: the step is added to a schema that runs.

## Schema versions

The tables are versioned, the way Umbraco does it: `{Schema}.SchemaVersion` records each step applied, with its
checksum, and the packages require a version: `AuthorizationSchema.RequiredVersionFor(UserProfiles)`, 3 without the
profiles and 4 with them. The state of a database is read
from SQL Server's catalog, never deduced from a model:

| State | What happens |
|---|---|
| Empty | installed from scratch |
| Versioned | the missing steps are applied |
| Version 1 without a history (the hosts' script) | **adopted**: stamped, not rebuilt |
| Version 1 with case-insensitive keys | adopted after a collation repair, only with `--approve collation-repair` |
| The legacy kdyf.auth.* schema | never touched in place: imported into another schema |
| Anything else | nothing is done; the differences are reported |

Each step runs in its own transaction with its verification and its history row, one run at a time per schema. A step
that fails is recorded and the next run resumes it. A database whose tables hold rows is changed only with a recent
backup in `msdb` or `--backup-confirmed`.

```csharp
var app = builder.Build();
if (await app.RunKdyfAuthCommandAsync(args)) return;   // <host> kdyf-auth plan | apply | verify | ...
```

The tool needs the ASP.NET Core runtime. Without a host it does not know the host's `UserProfiles`: it works on the six
tables (version 3) unless `--user-profiles` is passed, so on a version-4 database pass it, or `verify` reports the
schema as ahead.

```bash
dotnet tool install --global kdyf.Authorization.Tool
kdyf-auth plan      # the connection string in KDYF_AUTH_CONNECTION_STRING (or --connection-string), an identity with DDL
kdyf-auth apply --backup-confirmed --app-user my_app_user
kdyf-auth verify
```

`script <file>` writes the SQL instead, for a DBA; run `verify` after it. The application's database user belongs in the
role `kdyf_{schema}_runtime`, which may read the version but not write the history, and may insert into the audit log but
not change it. That only holds if the user is not `db_owner` or `db_datawriter`.

Migrating a host that still has the legacy `kdyf.auth.*` schema takes one command per stage, run in the host
(`<host> kdyf-auth ...`, with `AddKdyfAuthorizationLegacyImport`):

```bash
kdyf-auth migrate                      # apply, resolve the users, import, verify: repeatable, the legacy schema stays as it is
kdyf-auth migrate --finalize --approver me --confirm [--rollback-window 48h]
                                       # the cutover, then (after the window) the contraction and the promotion to the legacy name
```

`migrate` runs the commands it names (`apply`, `resolve --incremental`, `import apply`, `verify`) and stops at the
first that refuses, with what stands in the way; the commands keep working one by one. It decides nothing for a person:
users it cannot resolve are decided with `identities export|import`, or their loss is approved with
`--approve unresolved-users`, and what each person loses is accepted with `import reductions-accept`. `--finalize`
cannot be repeated by mistake: it needs `--confirm`, and with a rollback window it is run twice (the cutover now, the
contraction when the window has closed). Afterwards the host's `Schema` override is removed and the application is
deployed. A database that was never on the new model needs `--schema authz` (the schema the copy is built in) on both
forms: without it the legacy and the target schema have the same name and there is nothing to import.

Once the window has closed and the application runs on the new schema, `kdyf-auth contract cleanup --confirm` drops the
import's working tables (`MigrationIdentity`, `MigrationGateSnapshot`, `MigrationIssue`, `MigrationException`: they hold
e-mails and nothing reads them); what was approved stays in the run log. `contract drop --legacy-schema <name> --confirm`
removes the renamed legacy schema when it is no longer wanted.

When the host starts it checks the version: below the required one, or with a failed step, it does not start; without a
history it only warns, until `RequireSchemaVersion` is set in the section.

## Known limitations

- **One instance's cache.** A change (a role taken away, a suspension) takes effect at once on the instance that made it,
  and on the others within `CacheDuration`. With several replicas that is the window; replace `IPermissionCache` with a
  distributed one if it is too long.
- **Personal access tokens** can be created without an expiry date. A token is worth what its owner holds right now, and
  an administrator can switch anybody's off at once; set an expiry for integrations that should not outlive a project.
- **No retrying execution strategy.** The administration opens its own transactions (a change and its audit entry, the
  administrators' lock), which EF Core refuses under a retrying strategy: do not configure `EnableRetryOnFailure` on the
  store's `DbContext`. A transient failure fails that one change, and the administrator retries it.
- **The import's audit copy** resumes from the highest id already in the target. While trying the application against
  the target schema between two imports, entries it writes to the target's audit log can hide legacy entries written
  meanwhile from the next import: try it read-only, or import again before writing.

## Build and test

```bash
dotnet build kdyf.Authorization.slnx
dotnet test kdyf.Authorization.slnx
```

Requires the .NET 10 SDK. Dependency versions are in `Directory.Packages.props`. The tests need no Entra ID (an
in-memory Microsoft Graph) and mostly no database (in-memory SQLite). The schema tests run against a real SQL Server:
LocalDB, or the server in `KDYF_AUTHZ_TEST_SQLSERVER` (a connection string without a database); without one they are
inconclusive.

To try the packages in another solution before they are published, `pack-local.ps1` builds, tests and packs them into
a local feed (`C:\Nuget` by default) with a unique version suffix per run.

## Branches

`develop` is where work lands, through pull requests; `master` is what has been released. A release is a tag on
`master`, `v<version>` (for example `v1.0.0`, or `v1.1.0-preview.1` for a preview); every package of a release carries
that version, and each depends on the others with that exact version. What changed is in
[CHANGELOG.md](https://github.com/kreadyf/kdyf.Authorization/blob/master/CHANGELOG.md).

After a stable release: set `PackageValidationBaselineVersion` in `Directory.Build.props` to it (a 1.x that breaks the
public API then fails the build), and raise `VersionPrefix` on `develop` to the next version.

## Security

See [SECURITY.md](https://github.com/kreadyf/kdyf.Authorization/blob/master/SECURITY.md) to report a vulnerability.

## License

[MIT](https://github.com/kreadyf/kdyf.Authorization/blob/master/LICENSE)
