using System.Data.Common;
using kdyf.Authorization.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace kdyf.Authorization.Migrations.Schema
{
    /// <summary>
    /// The <c>kdyf-auth</c> commands, the same in a host (<c>&lt;host&gt; kdyf-auth apply</c>, with the host's own
    /// configuration) and in the dotnet tool (with <c>--connection-string</c>).
    /// </summary>
    /// <remarks>
    /// <code>
    /// kdyf-auth detect                     what the schema is
    /// kdyf-auth plan                       the dry run: what would be applied, and what stands in the way
    /// kdyf-auth script &lt;file&gt;            the SQL for a DBA; run verify after it
    /// kdyf-auth apply                      apply, each step verified before it is recorded
    /// kdyf-auth adopt                      apply, only on a database that is adopted (the reference schema today)
    /// kdyf-auth verify                     the schema equals its version's manifest
    /// kdyf-auth cutover                    mark CutoverCompleted (closes the legacy import)
    /// kdyf-auth migrate [--finalize]       the commands of a migration in their order (see <see cref="MigrateCommand"/>)
    ///
    /// --schema &lt;name&gt;  --app-user &lt;user&gt;  --approve &lt;what&gt; (repeatable)  --backup-confirmed  --host-version &lt;v&gt;
    /// </code>
    /// Exit codes: 0 done, 1 refused / failed / not verified, 2 wrong arguments.
    /// </remarks>
    public static class SchemaCommandLine
    {
        /// <summary>The first argument that tells a host to run a command instead of starting.</summary>
        public const string Verb = "kdyf-auth";

        /// <summary>Exit code: done.</summary>
        public const int Ok = 0;

        /// <summary>Exit code: refused, failed or not verified.</summary>
        public const int NotDone = 1;

        /// <summary>Exit code: wrong arguments.</summary>
        public const int Usage = 2;

        /// <summary>The usage text: the commands and options.</summary>
        public static string Help => """
            kdyf-auth <command> [options]

            Commands:
              detect             What state the schema is in. Read-only.
              plan               The dry run: what would be applied and what stands in the way. Read-only.
              script <file>      Write the SQL for a DBA. Run 'verify' after it, always.
              apply              Apply the missing steps, each verified before it is recorded.
              adopt              Like apply, only on a database in the shape of version 1 without a history.
              verify             The schema is at the required version and equals its manifest. Read-only.
              cutover            Record CutoverCompleted: from then on the legacy import refuses to run.
              migrate [--approve unresolved-users]
                                 Everything that can be repeated, in order, stopping where one refuses: apply, then (when
                                 a legacy schema is there) resolve and import apply, then verify. In the host for a legacy schema.
              migrate --finalize --approver <name> --confirm [--rollback-window 48h]
                                 What cannot be repeated: the cutover, then (after the window) the contraction and the
                                 promotion of the new schema to the legacy name. Run it again after the window.
              legacy-report      What a legacy kdyf.auth.* schema holds and what its import would decide. Read-only.
              resolve            (host) Resolve the legacy users in Entra and snapshot both gates. --incremental keeps the unchanged.
              identities export <file> | import <file> --approver <name>
                                 (host) The review of the identities: approvals, and object ids given by hand.
              import plan | apply [--approve unresolved-users]
                                 (host) Copy the legacy schema into this one, reconciled and verified; plan is a dry run.
                                 Nobody may gain: every gain is refused unless approved in the exceptions.
              import reductions-accept --approver <name>
                                 (host) Accept what each person loses, as listed now.
              import cutover --approver <name> [--rollback-window 48h]
                                 (host) The automatic go/no-go, then CutoverCompleted and the rollback window.
              rollback-sync plan | apply
                                 Take the revocations made since the cutover back to the legacy schema. Never grants.
              contract rename | drop | promote | cleanup --confirm
                                 After the window: the legacy schema renamed to <schema>_legacy_<date>, later dropped;
                                 then promote: the new schema takes the legacy name (authz -> auth), role included;
                                 cleanup: the import's working tables (they hold e-mails) are dropped, what was approved
                                 stays in the run log.
              exceptions import <file> --approver <name>
                                 (host) The approved exceptions to the invariant (JSON); the file replaces the previous set.

            Options:
              --schema <name>        The schema (default: the host's configuration, or 'auth').
              --app-user <user>      The application's database user, made a member of the runtime role.
              --approve <what>       collation-repair | privileged-app-user. Repeatable.
              --backup-confirmed     A backup of the database was taken for this run.
              --host-version <v>     Recorded in the run log.
              --legacy-schema <name> The legacy schema to read (default 'auth').
              --user-profiles        Keep a profile per person (UserProfile, version 4). The host's UserProfiles
                                     setting is the default; the legacy import needs it.
              --connection-string <cs>
                                     The dotnet tool only. Otherwise the connection string is read from
                                     KDYF_AUTH_CONNECTION_STRING (first), or the host's configuration.
            """;

        /// <summary>Runs one command. <paramref name="args"/> start after <c>kdyf-auth</c>.</summary>
        public static async Task<int> RunAsync(
            IReadOnlyList<string> args, string connectionString, string defaultSchema, TextWriter output, CancellationToken cancellationToken = default) =>
            await RunAsync(args, connectionString, defaultSchema, output, services: null, cancellationToken);

        /// <summary>
        /// Runs one command, with the host's services for the commands that need them (the legacy identities: the
        /// directory and the access gates).
        /// </summary>
        public static async Task<int> RunAsync(
            IReadOnlyList<string> args, string connectionString, string defaultSchema, TextWriter output, IServiceProvider? services,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(args);
            ArgumentNullException.ThrowIfNull(output);

            if (args.Count == 0 || args[0] is "-h" or "--help" or "help")
            {
                await output.WriteLineAsync(Help);
                return args.Count == 0 ? Usage : Ok;
            }

            var command = args[0].ToLowerInvariant();
            var userProfiles = services?.GetService<IOptions<AuthorizationStoreOptions>>()?.Value.UserProfiles ?? false;
            if (args.Skip(1).Any(a => a == "--user-profiles"))
                userProfiles = true;
            if (command == "migrate")
                return await MigrateCommand.RunAsync(args, connectionString, defaultSchema, services, userProfiles, output, cancellationToken);
            if (Legacy.LegacyCommands.Handles(command))
            {
                // The import fills UserProfile (the legacy ids, who is suspended) and reads it back: no profiles, no import.
                if (!userProfiles && command != "contract")
                {
                    await output.WriteLineAsync($"'{command}' needs the profiles (UserProfile, schema version 4): set UserProfiles=true in the host's configuration, or pass --user-profiles.");
                    return Usage;
                }
                return await Legacy.LegacyCommands.RunAsync(args.Where(a => a != "--user-profiles").ToList(), connectionString, defaultSchema, services, output, cancellationToken);
            }
            var options = new SchemaMigrationOptions { Schema = defaultSchema, UserProfiles = userProfiles };
            string? file = null;
            var legacySchema = "auth";

            for (var i = 1; i < args.Count; i++)
            {
                string Value() => i + 1 < args.Count ? args[++i] : throw new ArgumentException($"{args[i]} needs a value.");
                try
                {
                    switch (args[i])
                    {
                        case "--schema": options.Schema = Value(); break;
                        case "--app-user": options.AppUser = Value(); break;
                        case "--approve": options.Approvals.Add(Value()); break;
                        case "--backup-confirmed": options.BackupConfirmed = true; break;
                        case "--host-version": options.HostVersion = Value(); break;
                        case "--legacy-schema": legacySchema = Value(); break;
                        case "--user-profiles": break;
                        default:
                            if (command == "script" && file is null && !args[i].StartsWith("--", StringComparison.Ordinal))
                                file = args[i];
                            else
                                throw new ArgumentException($"Unknown argument '{args[i]}'.");
                            break;
                    }
                }
                catch (ArgumentException ex)
                {
                    await output.WriteLineAsync(ex.Message);
                    await output.WriteLineAsync(Help);
                    return Usage;
                }
            }

            foreach (var approval in options.Approvals)
                if (approval is not (SchemaApprovals.CollationRepair or SchemaApprovals.PrivilegedAppUser))
                {
                    await output.WriteLineAsync($"Unknown approval '{approval}': {SchemaApprovals.CollationRepair} or {SchemaApprovals.PrivilegedAppUser}.");
                    return Usage;
                }

            if (command == "legacy-report")
            {
                try
                {
                    var (shape, report) = await Legacy.LegacyInspector.InspectAsync(connectionString, legacySchema, cancellationToken: cancellationToken);
                    if (report is null)
                    {
                        await output.WriteLineAsync($"Legacy shape {shape.Label}: {shape.Description}");
                        return NotDone;
                    }
                    await output.WriteAsync(report.ToText(shape));
                    return report.HasBlockers ? NotDone : Ok;
                }
                catch (Exception ex) when (ex is DbException or InvalidOperationException)
                {
                    await output.WriteLineAsync($"legacy-report failed: {ex.Message}");
                    return NotDone;
                }
            }

            SchemaMigrator migrator;
            try
            {
                migrator = new SchemaMigrator(connectionString, options);
            }
            catch (ArgumentException ex)
            {
                await output.WriteLineAsync(ex.Message);
                return Usage;
            }

            try
            {
                return await RunAsync(command, args[0], file, migrator, output, cancellationToken);
            }
            catch (Exception ex) when (ex is DbException or ArgumentException or InvalidOperationException or TimeoutException)
            {
                // The database, not the arguments: unreachable, a malformed connection string, no permission, the lock.
                await output.WriteLineAsync($"{command} failed: {ex.Message}");
                return NotDone;
            }
        }

        private static async Task<int> RunAsync(
            string command, string verb, string? file, SchemaMigrator migrator, TextWriter output, CancellationToken cancellationToken)
        {
            switch (command)
            {
                case "detect":
                {
                    var detection = await migrator.DetectAsync(cancellationToken);
                    await WriteAsync(output, detection);
                    return Ok;
                }

                case "plan":
                {
                    var plan = await migrator.PlanAsync(cancellationToken);
                    await WriteAsync(output, plan);
                    return plan.HasBlockers ? NotDone : Ok;
                }

                case "script":
                {
                    if (file is null)
                    {
                        await output.WriteLineAsync("script needs the file to write: kdyf-auth script <file>.");
                        return Usage;
                    }
                    try
                    {
                        await File.WriteAllTextAsync(file, await migrator.ScriptAsync(cancellationToken), cancellationToken);
                    }
                    catch (InvalidOperationException ex)
                    {
                        await output.WriteLineAsync(ex.Message);
                        return NotDone;
                    }
                    await output.WriteLineAsync($"Written to {file}. Take a backup, run it, then run 'kdyf-auth verify'.");
                    return Ok;
                }

                case "apply":
                case "adopt":
                {
                    if (command == "adopt")
                    {
                        var plan = await migrator.PlanAsync(cancellationToken);
                        if (!plan.Actions.Any(a => a.Kind == PlannedActionKind.Adopt))
                        {
                            await output.WriteLineAsync($"Nothing to adopt: {plan.Detection.Summary} Use 'plan' to see what 'apply' would do.");
                            return NotDone;
                        }
                    }
                    var report = await migrator.ApplyAsync(cancellationToken);
                    await WriteAsync(output, report.Plan);
                    foreach (var done in report.Done)
                        await output.WriteLineAsync($"done   {done}");
                    await output.WriteLineAsync($"{report.Result}: version {report.Version?.ToString() ?? "(none)"} of {report.Plan.TargetVersion}.{(report.Error is null ? "" : " " + report.Error)}");
                    return report.Succeeded ? Ok : NotDone;
                }

                case "verify":
                {
                    var verification = await migrator.VerifyAsync(cancellationToken);
                    await output.WriteLineAsync(verification.Detection.Summary);
                    foreach (var issue in verification.Issues)
                        await output.WriteLineAsync(issue.ToString());
                    await output.WriteLineAsync(verification.Succeeded ? "Verified." : "NOT verified.");
                    return verification.Succeeded ? Ok : NotDone;
                }

                case "cutover":
                    try
                    {
                        await migrator.MarkCutoverAsync(cancellationToken);
                    }
                    catch (InvalidOperationException ex)
                    {
                        await output.WriteLineAsync(ex.Message);
                        return NotDone;
                    }
                    await output.WriteLineAsync("CutoverCompleted recorded.");
                    return Ok;

                default:
                    await output.WriteLineAsync($"Unknown command '{verb}'.");
                    await output.WriteLineAsync(Help);
                    return Usage;
            }
        }

        private static async Task WriteAsync(TextWriter output, SchemaDetection detection)
        {
            await output.WriteLineAsync($"{detection.State}: {detection.Summary}");
            if (detection.CutoverCompleted)
                await output.WriteLineAsync("CutoverCompleted.");
            foreach (var difference in detection.Differences)
                await output.WriteLineAsync($"  {difference}");
        }

        private static async Task WriteAsync(TextWriter output, SchemaMigrationPlan plan)
        {
            await WriteAsync(output, plan.Detection);
            foreach (var action in plan.Actions)
                await output.WriteLineAsync($"plan   {action}");
            foreach (var issue in plan.Issues)
                await output.WriteLineAsync(issue.ToString());
            if (plan.UpToDate && !plan.HasBlockers)
                await output.WriteLineAsync($"Up to date (version {plan.Detection.Version}).");
        }
    }
}
