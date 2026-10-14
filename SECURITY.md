# Security

kdyf.Authorization decides who may do what in the applications that use it, so a flaw in it can expose their data.

## Reporting a vulnerability

Please **do not open a public issue**. Report it privately through GitHub: the repository's **Security** tab →
**Report a vulnerability**. Include what is affected, how to reproduce it and the impact you expect.

We acknowledge a report within a few working days, keep you informed while it is fixed, and credit you in the
release notes unless you prefer otherwise.

## Supported versions

Fixes go to the latest published version. While the packages are in preview, there is no back-porting to earlier
previews.

## What this library assumes

- Secrets (the Microsoft Graph client secret, connection strings) come from user secrets, environment variables or a
  vault — never from `appsettings.json` or source control.
- The Graph application registration holds only the permissions its access gate needs; with app assignments,
  `AppRoleAssignment.ReadWrite.All` belongs to a registration used for nothing else.
- Hosts keep `UseKdyfAuthorization()` before their endpoints, and the fallback policy (a session for every endpoint)
  in place.
