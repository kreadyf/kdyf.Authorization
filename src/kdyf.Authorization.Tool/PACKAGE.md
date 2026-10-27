# kdyf.Authorization.Tool

[![NuGet](https://img.shields.io/nuget/v/kdyf.Authorization.Tool?logo=nuget&label=NuGet)](https://www.nuget.org/packages/kdyf.Authorization.Tool)

The `kdyf-auth` dotnet tool. It detects, plans, scripts, applies and verifies the versioned schema of kdyf.Authorization
on SQL Server, without a host. It needs the ASP.NET Core runtime.

```bash
dotnet tool install --global kdyf.Authorization.Tool
```

## Usage

The connection string goes in `KDYF_AUTH_CONNECTION_STRING` or `--connection-string`. The environment variable is
preferred, because an argument is visible in the process list. The identity needs DDL rights on the database.

```bash
kdyf-auth detect                     # what the schema is
kdyf-auth plan                       # the dry run: what would be applied, and what stands in the way
kdyf-auth apply --backup-confirmed --app-user my_app_user
kdyf-auth script schema.sql          # the SQL for a DBA; run verify after it
kdyf-auth verify                     # the schema equals its version's manifest
```

- `--app-user` adds the application's database user to the role `kdyf_{schema}_runtime`. That role may read the
  version but not write the history, and may insert into the audit log but not change it. This only holds if that
  user is neither `db_owner` nor `db_datawriter`.
- **Without a host the tool does not know the host's `UserProfiles` setting.** It works on the six tables of
  version 3 unless you pass `--user-profiles`. On a version-4 database, pass it, or `verify` reports the schema as
  ahead.
- A database whose tables hold rows is changed only with a recent backup in `msdb` or `--backup-confirmed`.

Migrating the legacy `kdyf.auth.*` schema runs inside the host, with
[kdyf.Authorization.Migrations](https://www.nuget.org/packages/kdyf.Authorization.Migrations).

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
