# kdyf.Authorization.Administration

[![NuGet](https://img.shields.io/nuget/v/kdyf.Authorization.Administration?logo=nuget&label=NuGet)](https://www.nuget.org/packages/kdyf.Authorization.Administration)

The administration of access for a kdyf.Authorization host. It covers people and their access (an Entra group or
Enterprise application assignments), roles, personal access tokens, the directory, suspension, invitations, the
audit log and user simulation, together with the ASP.NET Core composition and optional minimal API endpoints.

```bash
dotnet add package kdyf.Authorization.Administration
```

## Usage

```csharp
builder.Services.AddKdyfAuthorizationAdministration(admin => admin
    .AdministeredBy(new AdministrationPolicy())     // your policy; it must demand exactly one permission
    .TokensManagedBy(new PersonalTokensPolicy()));

var app = builder.Build();
app.UseKdyfAuthorization();
app.MapKdyfAuthorizationAdministration();          // optional: auth/users, auth/roles, auth/pat, auth/audit, ...
app.MapKdyfAuthorizationSimulation();              // optional: auth/simulation/start, end, candidates
```

The permission that `AdministeredBy`'s policy demands is the administration permission. Somebody has to hold it
before anybody can give roles. The [full guide](https://github.com/kreadyf/kdyf.Authorization#the-first-administrator)
shows the one-time SQL for the first administrator.

Every change goes through the same rules:

- four eyes: nobody changes their own access, nor what a role they hold grants;
- an administrator gives nothing beyond what they hold;
- the last administrator is never removed.

Each change is written in one transaction with its audit entry. The endpoints expose nothing unless the host calls
their `Map…()`. A host that prefers its own endpoints uses the administration services directly, and
`IKdyfAuthorizationResultWriter` keeps a host's own response envelope.

During a simulation every write is refused. A POST that only reads, such as a search, needs `[ReadOnlyOperation]`
(or `.WithMetadata(new ReadOnlyOperationAttribute())`).

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
