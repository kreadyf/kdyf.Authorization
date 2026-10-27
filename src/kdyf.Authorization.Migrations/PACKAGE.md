# kdyf.Authorization.Migrations

[![NuGet](https://img.shields.io/nuget/v/kdyf.Authorization.Migrations?logo=nuget&label=NuGet)](https://www.nuget.org/packages/kdyf.Authorization.Migrations)

The versioned schema of kdyf.Authorization on SQL Server, run from inside the host: detect, plan, script, apply,
adopt and verify. It also imports the legacy `kdyf.auth.*` schema, and, temporarily, moves the access gate from an
Entra security group to Enterprise application assignments. To run the schema commands without a host, use
[kdyf.Authorization.Tool](https://www.nuget.org/packages/kdyf.Authorization.Tool).

```bash
dotnet add package kdyf.Authorization.Migrations
```

## Usage

```csharp
var app = builder.Build();
if (await app.RunKdyfAuthCommandAsync(args)) return;   // dotnet run -- kdyf-auth plan | apply | verify | ...
```

| Command | What it does |
|---|---|
| `kdyf-auth plan` | the dry run: what would be applied, and what stands in the way |
| `kdyf-auth apply` | applies the missing steps, each in its own transaction, verified and recorded |
| `kdyf-auth script <file>` | writes the SQL for a DBA; run `verify` after it |
| `kdyf-auth verify` | checks that the schema equals its version's manifest |
| `kdyf-auth migrate [--finalize]` | the legacy import, stage by stage (needs `AddKdyfAuthorizationLegacyImport`) |

A database whose tables hold rows is changed only with a recent backup in `msdb` or `--backup-confirmed`. Inside the
host the commands follow the host's own section (`Schema`, `UserProfiles`).

`Gate: "Migrating"` in a host that administers access also needs
`builder.Services.AddKdyfAuthorizationGateMigration()`, after the administration; the host refuses to start without it.

## The kdyf.Authorization packages

Every package ships with the same version and depends on its siblings with that exact version.

| Package | What for |
|---|---|
| [kdyf.Authorization](https://www.nuget.org/packages/kdyf.Authorization) | Core: permissions, policies, the permission tree, cache, personal access tokens, simulation |
| [kdyf.Authorization.AspNetCore](https://www.nuget.org/packages/kdyf.Authorization.AspNetCore) | Composition for a host: `AddKdyfAuthorization`, `UseKdyfAuthorization`, `auth/me`, `auth/policies` |
| [kdyf.Authorization.EntityFrameworkCore](https://www.nuget.org/packages/kdyf.Authorization.EntityFrameworkCore) | The `auth.*` tables: roles, grants, holders, tokens, the permission catalog |
| [kdyf.Authorization.EntraId](https://www.nuget.org/packages/kdyf.Authorization.EntraId) | Entra ID sign-in and the access gate, through Microsoft Graph |
| [kdyf.Authorization.Administration](https://www.nuget.org/packages/kdyf.Authorization.Administration) | Administration of people, roles, tokens, audit log and simulation, with optional endpoints |
| [kdyf.Authorization.Migrations](https://www.nuget.org/packages/kdyf.Authorization.Migrations) | The versioned SQL Server schema, run from the host (`<host> kdyf-auth ...`) |
| [kdyf.Authorization.Tool](https://www.nuget.org/packages/kdyf.Authorization.Tool) | The `kdyf-auth` dotnet tool: the schema commands without a host |

[Full guide](https://github.com/kreadyf/kdyf.Authorization#readme) ·
[Changelog](https://github.com/kreadyf/kdyf.Authorization/blob/master/CHANGELOG.md) ·
[Security](https://github.com/kreadyf/kdyf.Authorization/blob/master/SECURITY.md) ·
[MIT license](https://github.com/kreadyf/kdyf.Authorization/blob/master/LICENSE)
