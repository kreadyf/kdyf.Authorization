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
| `kdyf.Authorization.Migrations` | Temporary: moving the access gate from a group to app assignments |

Every package targets .NET 8 and .NET 10. Namespaces did not change when the former `*.Endpoints`,
`Administration.EntraId` and `Administration.AspNetCore` packages were merged, nor when `EntraId.Migration` became
`Migrations`: a host only changes its package references.

The endpoints expose nothing unless the host calls their `Map…()`. A host that prefers its own endpoints
uses the administration services directly, and a host that keeps its own response envelope registers an
`IKdyfAuthorizationResultWriter`.

## Getting started

```csharp
// Permissions and policies are classes (PermissionDefinition, Policy), discovered in the assemblies you declare.
// A permission's namespace is its area: a class in namespace 'global' declaring "Reports" is 'global.Reports'.

builder.Services.AddKdyfAuthorization(builder.Configuration, "Authorization", auth => auth
    .Declarations(typeof(Program).Assembly)
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

## Configuration

One section, named by the host, validated at startup: with a missing or inconsistent value the host does not start,
and the message names the key.

```jsonc
"Authorization": {
  "ConnectionStringName": "Authorization",    // ConnectionStrings:{name}; the host may also name it in code
  "Schema": "auth",
  "EntraId": { "TenantId": "…", "ClientId": "…", "Audience": "" },
  "Directory": {
    "Gate": "Group",                          // Group | Migrating | AppAssignment
    "GroupId": "…",                           // Group, Migrating
    "ServicePrincipalId": "…",                // Migrating, AppAssignment
    "AccessAppRoleId": "…",                   // Migrating, AppAssignment
    "ClientSecret": "…"                       // SECRET: user secrets, environment variables or a vault
  },
  "Authorization": { "CacheDuration": "00:02:00", "EmptyResultCacheDuration": "00:00:30" },
  "Simulation": { "HeaderName": "X-Simulate-User", "SessionIdleTimeout": "00:30:00" }
}
```

Secrets never belong in `appsettings.json`. The Microsoft Graph application permissions depend on the gate:
`User.Read.All`, plus `GroupMember.Read.All` (`GroupMember.ReadWrite.All` to administer) for a group, and
`AppRoleAssignment.ReadWrite.All` for app assignments. That last one is powerful — it can assign any app role in the
tenant — so give it to a separate app registration used only for Graph, with a certificate kept in a vault.

## Build and test

```bash
dotnet build kdyf.Authorization.slnx
dotnet test kdyf.Authorization.slnx
```

Requires the .NET 10 SDK. Dependency versions are in `Directory.Packages.props`. The tests need neither a database
nor Entra ID: in-memory SQLite and an in-memory Microsoft Graph.

To try the packages in another solution before they are published, `pack-local.ps1` builds, tests and packs them into
a local feed (`C:\Nuget` by default) with a unique version suffix per run.

## Branches

`develop` is where work lands, through pull requests; `master` is what has been released. A release is a tag on
`master`, `v<version>` (for example `v1.0.0-preview.2`); every package of a release carries that version.

## Security

See [SECURITY.md](SECURITY.md) to report a vulnerability.

## License

[MIT](LICENSE)
