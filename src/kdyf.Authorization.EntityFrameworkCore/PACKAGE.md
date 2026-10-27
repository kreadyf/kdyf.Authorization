# kdyf.Authorization.EntityFrameworkCore

[![NuGet](https://img.shields.io/nuget/v/kdyf.Authorization.EntityFrameworkCore?logo=nuget&label=NuGet)](https://www.nuget.org/packages/kdyf.Authorization.EntityFrameworkCore)

The EF Core store of kdyf.Authorization: roles, what they grant, who holds them, personal access tokens and the
permission catalog, in the `auth.*` tables (the schema is configurable), on the database provider the host
chooses.

```bash
dotnet add package kdyf.Authorization.EntityFrameworkCore
```

## Usage

```csharp
builder.Services.AddKdyfAuthorization(builder.Configuration, "Authorization", auth => auth
    .Declarations(typeof(Program).Assembly)
    .UseEntityFrameworkStore((db, connectionString) => db.UseSqlServer(connectionString))
    .UseEntraId());
```

The connection string is `ConnectionStrings:{Authorization:ConnectionStringName}`, and the schema is
`Authorization:Schema` (`auth` by default). At startup the store writes the permission catalog from the declared
permissions and every node of the permission tree.

- **The host does not create the tables.** Create and upgrade them with `kdyf-auth apply`
  ([kdyf.Authorization.Tool](https://www.nuget.org/packages/kdyf.Authorization.Tool), or
  [kdyf.Authorization.Migrations](https://www.nuget.org/packages/kdyf.Authorization.Migrations) inside the host). The
  host does not start below the schema version it requires.
- **No retrying execution strategy.** The administration opens its own transactions, which EF Core refuses under
  `EnableRetryOnFailure`. Do not configure it on this store's `DbContext`.
- `"UserProfiles": true` keeps the `UserProfile` table (suspension, last access) and needs schema version 4.

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
