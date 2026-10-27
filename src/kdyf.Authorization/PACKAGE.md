# kdyf.Authorization

[![NuGet](https://img.shields.io/nuget/v/kdyf.Authorization?logo=nuget&label=NuGet)](https://www.nuget.org/packages/kdyf.Authorization)

The core of kdyf.Authorization, permission-based authorization for ASP.NET Core. It holds permissions and policies
declared as classes, the permission tree, the cached permission store, the personal access token scheme
(`Authorization: PAT <token>`) and read-only user simulation.

A host normally does not reference it alone: it comes with
[kdyf.Authorization.AspNetCore](https://www.nuget.org/packages/kdyf.Authorization.AspNetCore), which composes it
with the database store and Entra ID. Reference it directly in a library that only declares permissions and
policies.

```bash
dotnet add package kdyf.Authorization
```

## Declaring permissions and policies

```csharp
using kdyf.Authorization.Abstractions;
using kdyf.Authorization.Authorization;

namespace fabrikam;   // the namespace is the area: the code below is fabrikam.Invoices

public sealed class Invoices : PermissionDefinition
{
    public Invoices() : base("Invoices", "Invoices", "Read and issue invoices") { }
}

public sealed class InvoicingPolicy : Policy
{
    public InvoicingPolicy() : base("Invoicing") => RequireAny(new Invoices());
}

// At the door: app.MapGet("/invoices", ...).RequireAuthorization(new InvoicingPolicy());
```

`RequireAny(a, b)` is one rule that any of its permissions satisfies; several `RequireAny` calls must all hold.

## The permission tree

Codes are paths. A granted code covers itself and every code below it: a role granting `fabrikam` holds
`fabrikam.Invoices` and any `fabrikam.` code declared later, but not `fabrikamArchive.X`. The empty code `""` is
the root and covers everything. Every ancestor of a declared code exists in the catalog without a class.
Wildcards (`*`, `area.*`) were replaced by the tree in 1.2.0.

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
