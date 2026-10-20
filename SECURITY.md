# Security

kdyf.Authorization decides who may do what in the applications that use it, so a flaw in it can expose their data.

## Reporting a vulnerability

Please **do not open a public issue**. Report it privately through GitHub: the repository's **Security** tab →
**Report a vulnerability**. Include what is affected, how to reproduce it and the impact you expect.

We acknowledge a report within a few working days, keep you informed while it is fixed, and credit you in the
release notes unless you prefer otherwise.

## Supported versions

| Version | Security fixes |
|---|---|
| 1.x, latest minor | yes |
| 1.x, older minors | no: update to the latest 1.x (minors do not break the public API) |
| previews | no |

A fix is released as a patch of the latest minor. Every package of the family carries the same version and depends on
the others with that exact version, so updating one updates them all.

## What this library assumes

- Secrets (the Microsoft Graph client secret, connection strings) come from user secrets, environment variables or a
  vault — never from `appsettings.json` or source control.
- The Graph application registration holds only the permissions its access gate needs; with app assignments,
  `AppRoleAssignment.ReadWrite.All` belongs to a registration used for nothing else.
- Hosts keep `UseKdyfAuthorization()` before their endpoints, and the fallback policy (a session for every endpoint)
  in place.
- The application's database user is a member of `kdyf_{schema}_runtime` and neither `db_owner` nor `db_datawriter`:
  otherwise the audit log can be changed and the history rewritten.
- People are told apart by their Entra object id (`oid`), never by e-mail; a token's `groups` and `roles` claims never
  authorize a person — their permissions come from the access gate, their roles and the suspension.
