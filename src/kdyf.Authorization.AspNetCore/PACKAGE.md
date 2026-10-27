# kdyf.Authorization.AspNetCore

[![NuGet](https://img.shields.io/nuget/v/kdyf.Authorization.AspNetCore?logo=nuget&label=NuGet)](https://www.nuget.org/packages/kdyf.Authorization.AspNetCore)

The entry point for an ASP.NET Core host. It composes kdyf.Authorization from one configuration section, validated
at startup, with `AddKdyfAuthorization` and `UseKdyfAuthorization`. It also offers user simulation and the optional
session endpoints `GET auth/me` and `GET auth/policies`.

```bash
dotnet add package kdyf.Authorization.AspNetCore
dotnet add package kdyf.Authorization.EntityFrameworkCore
dotnet add package kdyf.Authorization.EntraId
```

## Usage

```csharp
builder.Services.AddKdyfAuthorization(builder.Configuration, "Authorization", auth => auth
    .Declarations(typeof(Program).Assembly)          // your PermissionDefinition and Policy classes
    .UseEntityFrameworkStore((db, connectionString) => db.UseSqlServer(connectionString))
    .UseEntraId());

var app = builder.Build();
app.UseKdyfAuthorization();                          // after UseRouting(), before the endpoints
app.MapKdyfAuthorizationSession();                   // optional: auth/me, auth/policies
```

```json
{
  "ConnectionStrings": { "Authorization": "..." },
  "Authorization": {
    "ConnectionStringName": "Authorization",
    "EntraId": { "TenantId": "...", "ClientId": "..." },
    "Directory": { "Gate": "Group", "GroupId": "..." }
  }
}
```

The Microsoft Graph client secret goes in `Authorization:Directory:ClientSecret`, from user secrets, environment
variables or a vault, never `appsettings.json`. With a missing or inconsistent value the host does not start, and
the message names the key.

Every endpoint without its own authorization, and every bare `RequireAuthorization()`, demands the access gate: a
person must hold at least one permission. `KdyfAuthorizationPolicies.SignedIn` asks for a session only.

The tables are created beforehand with `kdyf-auth apply`
([kdyf.Authorization.Tool](https://www.nuget.org/packages/kdyf.Authorization.Tool)). The
[full guide](https://github.com/kreadyf/kdyf.Authorization#readme) covers the first administrator, every
configuration key and the schema versions.

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
