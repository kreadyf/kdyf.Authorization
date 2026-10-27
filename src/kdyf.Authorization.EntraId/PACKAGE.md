# kdyf.Authorization.EntraId

[![NuGet](https://img.shields.io/nuget/v/kdyf.Authorization.EntraId?logo=nuget&label=NuGet)](https://www.nuget.org/packages/kdyf.Authorization.EntraId)

Microsoft Entra ID for kdyf.Authorization. People sign in with the Entra token, and who may use the application at
all is decided on the server, through Microsoft Graph, on every request (cached). It is either membership of a
security group or an assignment to the application's Enterprise application. The token's own `roles` and `groups`
claims never authorize a person.

```bash
dotnet add package kdyf.Authorization.EntraId
```

## Usage

```csharp
builder.Services.AddKdyfAuthorization(builder.Configuration, "Authorization", auth => auth
    .Declarations(typeof(Program).Assembly)
    .UseEntityFrameworkStore((db, connectionString) => db.UseSqlServer(connectionString))
    .UseEntraId());
```

```json
"Authorization": {
  "EntraId": { "TenantId": "...", "ClientId": "...", "Audience": "" },
  "Directory": {
    "Gate": "Group",
    "GroupId": "...",
    "ServicePrincipalId": "...",
    "AccessAppRoleId": "..."
  }
}
```

| `Gate` | Who gets in | Keys |
|---|---|---|
| `Group` | members of the security group | `GroupId` |
| `AppAssignment` | people assigned to the Enterprise application | `ServicePrincipalId`, `AccessAppRoleId` |
| `Migrating` | the group decides while the assignments are kept in line with it | all three |

The Graph application permissions depend on the gate:

- every gate: `User.Read.All`;
- a group: `GroupMember.Read.All` (`GroupMember.ReadWrite.All` to administer);
- app assignments: `AppRoleAssignment.ReadWrite.All`;
- `Migrating`: both;
- inviting guests: `User.Invite.All`.

`AppRoleAssignment.ReadWrite.All` can assign any app role in the tenant. Give it to a separate app registration
used only for Graph (`Directory:ClientId`, and `Directory:TenantId` for another tenant). Keep
`Directory:ClientSecret` in a vault and rotate it.

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
