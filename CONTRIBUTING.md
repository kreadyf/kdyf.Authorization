# Contributing

Thank you for helping. kdyf.Authorization decides who may do what in the applications that use it, so changes are
reviewed with that in mind: small, tested and explained.

**A security problem is not reported here.** Do not open an issue or a pull request for it: follow
[SECURITY.md](https://github.com/kreadyf/kdyf.Authorization/blob/master/SECURITY.md).

## Before you start

- For a bug, open an issue with what you did, what you expected and what happened, and the package version.
- For anything bigger than a small fix, open an issue first and describe the change. A change to the public API or to
  the behaviour of the access gate, the permission tree or the schema needs agreement before the code.

## Branches

- `develop` is where work lands. **Every pull request targets `develop`.**
- `master` is what has been released. Only `develop` (a release) and `hotfix/*` branches of this repository (a fix of
  what was released) are merged into it, and a check refuses anything else.
- Nobody pushes to `develop` or `master` directly: both take pull requests only, with the CI green.

So: fork the repository, create a branch from `develop` (`feature/<topic>` or `fix/<topic>`), and open the pull request
against `develop`.

## Building and testing

```bash
dotnet build kdyf.Authorization.slnx -c Release -warnaserror
dotnet test kdyf.Authorization.slnx -c Release --no-build
```

You need the .NET 10 SDK; the packages target .NET 8 and .NET 10 and the tests run on both. The tests need no Entra ID
and mostly no database. The schema tests run against SQL Server: LocalDB, or the server in `KDYF_AUTHZ_TEST_SQLSERVER`
(a connection string without a database); without one they are inconclusive locally, and the CI runs them.

## What a pull request needs

- **A test.** A fix comes with a test that fails without it. A feature comes with tests of what it allows and what it
  refuses.
- **No warnings.** The build treats them as errors, including a public type or member without XML documentation.
- **The public API kept.** Package validation compares it with the last release; a 1.x does not break it. If a change
  needs to, say so in the issue first.
- **The documentation.** The README, or the package's `PACKAGE.md` (what nuget.org shows), when the change is visible
  to a host. The maintainers write the CHANGELOG entry; describe the change in the pull request so it can be written.
- **Commits in English**, one per logical change, with a message that says why.

The CI (build, tests on both frameworks against SQL Server, pack) runs on every pull request. On a first contribution
a maintainer approves the run before it starts.

## License

By contributing you agree that your contribution is licensed under the
[MIT license](https://github.com/kreadyf/kdyf.Authorization/blob/master/LICENSE) of the project.
