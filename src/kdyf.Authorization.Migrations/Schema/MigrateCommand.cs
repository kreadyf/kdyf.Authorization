using System.Data.Common;
using kdyf.Authorization.Migrations.Legacy;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace kdyf.Authorization.Migrations.Schema
{
    /// <summary>
    /// <c>kdyf-auth migrate</c>: the commands of a migration, in their order, stopping at the first one that refuses.
    /// It runs the other commands (so each keeps its own checks) and decides nothing for a person.
    /// </summary>
    /// <remarks>
    /// <code>
    /// kdyf-auth migrate                            apply → (legacy schema: resolve → import apply) → verify. Repeatable.
    /// kdyf-auth migrate --finalize --approver &lt;name&gt; --confirm [--rollback-window 48h]
    ///                                              import cutover → contract rename → contract promote
    /// </code>
    /// The first form changes nothing that cannot be repeated. The second one closes the import and gives the new
    /// schema the legacy name; the rollback window (default 48 h) has to pass before the contraction, so with a window
    /// it is run twice: the cutover now, the contraction after the window.
    /// </remarks>
    internal static class MigrateCommand
    {
        public static async Task<int> RunAsync(
            IReadOnlyList<string> args, string connectionString, string targetSchema, IServiceProvider? services, bool userProfiles,
            TextWriter output, CancellationToken cancellationToken)
        {
            var legacySchema = services?.GetService<IOptions<LegacyImportOptions>>()?.Value.LegacySchema ?? "auth";
            var finalize = false;
            var confirmed = false;
            var backupConfirmed = false;
            string? approver = null, appUser = null, hostVersion = null, window = null;
            var applyApprovals = new List<string>();
            var importApprovals = new List<string>();

            for (var i = 1; i < args.Count; i++)
            {
                string Value() => i + 1 < args.Count ? args[++i] : throw new ArgumentException($"{args[i]} needs a value.");
                try
                {
                    switch (args[i])
                    {
                        case "--finalize": finalize = true; break;
                        case "--confirm": confirmed = true; break;
                        case "--backup-confirmed": backupConfirmed = true; break;
                        case "--approver": approver = Value(); break;
                        case "--app-user": appUser = Value(); break;
                        case "--host-version": hostVersion = Value(); break;
                        case "--rollback-window": window = Value(); break;
                        case "--schema": targetSchema = Value(); break;
                        case "--legacy-schema": legacySchema = Value(); break;
                        case "--user-profiles": break;
                        case "--approve":
                        {
                            var what = Value();
                            (what == LegacyImportApprovals.UnresolvedUsers ? importApprovals : applyApprovals).Add(what);
                            break;
                        }
                        default: throw new ArgumentException($"Unknown argument '{args[i]}'.");
                    }
                }
                catch (ArgumentException ex)
                {
                    await output.WriteLineAsync(ex.Message);
                    await output.WriteLineAsync(SchemaCommandLine.Help);
                    return SchemaCommandLine.Usage;
                }
            }

            var profileFlag = userProfiles ? new[] { "--user-profiles" } : Array.Empty<string>();
            var legacyFlag = new[] { "--legacy-schema", legacySchema };
            var importApprovalFlags = importApprovals.SelectMany(a => new[] { "--approve", a }).ToArray();

            async Task<(int Code, string Text)> StepAsync(string title, IEnumerable<string> stepArgs)
            {
                await output.WriteLineAsync($"== {title}");
                var captured = new StringWriter();
                var code = await SchemaCommandLine.RunAsync(stepArgs.Concat(profileFlag).ToList(), connectionString, targetSchema, captured, services, cancellationToken);
                var text = captured.ToString();
                await output.WriteAsync(text);
                return (code, text);
            }

            try
            {
                await using var connection = new SqlConnection(connectionString);
                await connection.OpenAsync(cancellationToken);

                // A legacy schema is one with another name than the target: the target of a host that already is on the new
                // model (the legacy name and the target name are the same) has nothing to copy.
                var legacyExists = !string.Equals(legacySchema, targetSchema, StringComparison.OrdinalIgnoreCase)
                                   && await SchemaExistsAsync(connection, legacySchema, cancellationToken);

                return finalize
                    ? await FinalizeAsync()
                    : await MigrateAsync();

                async Task<int> MigrateAsync()
                {
                    var apply = new List<string> { "apply" };
                    if (appUser is not null) apply.AddRange(new[] { "--app-user", appUser });
                    if (hostVersion is not null) apply.AddRange(new[] { "--host-version", hostVersion });
                    if (backupConfirmed) apply.Add("--backup-confirmed");
                    foreach (var approval in applyApprovals) apply.AddRange(new[] { "--approve", approval });
                    var applied = await StepAsync($"apply [{targetSchema}]", apply);
                    if (applied.Code != SchemaCommandLine.Ok)
                        return applied.Code;

                    var imported = false;
                    if (legacyExists)
                    {
                        if (services?.GetService<ILegacyDirectory>() is null)
                        {
                            await output.WriteLineAsync($"The legacy schema [{legacySchema}] holds data, and importing it runs in the host ('<host> kdyf-auth migrate'), "
                                                        + "with AddKdyfAuthorizationLegacyImport and the host's Entra ID.");
                            return SchemaCommandLine.Usage;
                        }
                        if (await CutOverAsync(connection, targetSchema, cancellationToken) is not null)
                        {
                            await output.WriteLineAsync($"== import\nThe import of [{legacySchema}] into [{targetSchema}] was cut over: it does not run again. Next: 'migrate --finalize'.");
                        }
                        else
                        {
                            var resolved = await StepAsync($"resolve the users of [{legacySchema}]", new[] { "resolve", "--incremental" }.Concat(legacyFlag));
                            if (resolved.Code != SchemaCommandLine.Ok)
                            {
                                // 'resolve' refuses for two reasons: the directory failed (nothing resolved), or some users are left to a person.
                                // With their loss approved the import goes on, and its own report lists who loses what.
                                var pending = resolved.Text.Contains("Resolved ", StringComparison.Ordinal) && importApprovals.Count > 0;
                                if (!pending)
                                {
                                    if (resolved.Text.Contains("Resolved ", StringComparison.Ordinal))
                                        await output.WriteLineAsync("Some users are left to a person: 'identities export <file>' and 'identities import <file> --approver <name>' "
                                                                    + "decide them, or '--approve unresolved-users' accepts that they lose their roles. Then run migrate again.");
                                    return SchemaCommandLine.NotDone;
                                }
                            }

                            var copy = await StepAsync($"import [{legacySchema}] into [{targetSchema}]", new[] { "import", "apply" }.Concat(legacyFlag).Concat(importApprovalFlags));
                            if (copy.Code != SchemaCommandLine.Ok)
                            {
                                await output.WriteLineAsync("Nothing was copied. What stands in the way is listed above; fix it and run migrate again (it is repeatable).");
                                return copy.Code;
                            }
                            imported = true;
                        }
                    }

                    var verified = await StepAsync($"verify [{targetSchema}]", new[] { "verify" });
                    if (verified.Code != SchemaCommandLine.Ok)
                        return verified.Code;

                    await output.WriteLineAsync(imported
                        ? $"Migrated into [{targetSchema}]; [{legacySchema}] is untouched. Try the application against [{targetSchema}]. To close it: "
                          + "migrate --finalize --approver <name> --confirm [--rollback-window 0h]."
                        : "Done.");
                    return SchemaCommandLine.Ok;
                }

                async Task<int> FinalizeAsync()
                {
                    if (!confirmed || string.IsNullOrWhiteSpace(approver))
                    {
                        await output.WriteLineAsync("The finalization closes the import and renames schemas: name who approves with --approver <name> and confirm it with --confirm.");
                        return SchemaCommandLine.Usage;
                    }
                    if (!await SchemaExistsAsync(connection, targetSchema, cancellationToken))
                    {
                        await output.WriteLineAsync($"[{targetSchema}] does not exist: there is nothing to finalize (it was promoted already, or nothing was migrated).");
                        return SchemaCommandLine.Ok;
                    }

                    var cutOver = await CutOverAsync(connection, targetSchema, cancellationToken);
                    if (cutOver is null)
                    {
                        if (!legacyExists)
                        {
                            await output.WriteLineAsync($"There is no legacy schema [{legacySchema}] to finalize.");
                            return SchemaCommandLine.Ok;
                        }
                        var cut = new List<string> { "import", "cutover", "--approver", approver };
                        if (window is not null) cut.AddRange(new[] { "--rollback-window", window });
                        var cutDone = await StepAsync("cutover", cut.Concat(legacyFlag).Concat(importApprovalFlags));
                        if (cutDone.Code != SchemaCommandLine.Ok)
                        {
                            // What each person loses is for a person to accept, never for this command.
                            await output.WriteLineAsync("If the go/no-go asks for it: 'import reductions-accept --approver <name>' accepts what each person loses, as listed now; "
                                                    + "the users left to a person need the same '--approve unresolved-users' that migrate had. Then run this again.");
                            return cutDone.Code;
                        }
                        cutOver = await CutOverAsync(connection, targetSchema, cancellationToken);
                    }

                    if (cutOver is { } cut2 && DateTime.UtcNow < cut2)
                    {
                        await output.WriteLineAsync($"The rollback window closes at {cut2:u}: the legacy schema is needed until then. Run 'migrate --finalize' again after it "
                                                    + "(or use --rollback-window 0h at the cutover when there is nothing to go back to).");
                        return SchemaCommandLine.Ok;
                    }

                    if (legacyExists)
                    {
                        var renamed = await StepAsync($"rename [{legacySchema}] away", new[] { "contract", "rename", "--confirm" }.Concat(legacyFlag));
                        if (renamed.Code != SchemaCommandLine.Ok)
                            return renamed.Code;
                    }
                    var promoted = await StepAsync($"promote [{targetSchema}] to [{legacySchema}]", new[] { "contract", "promote", "--confirm" }.Concat(legacyFlag));
                    if (promoted.Code != SchemaCommandLine.Ok)
                        return promoted.Code;

                    await output.WriteLineAsync($"Done: the model lives in [{legacySchema}]. Deploy the application without the Schema override ([{targetSchema}]) before it starts again.");
                    return SchemaCommandLine.Ok;
                }
            }
            catch (Exception ex) when (ex is DbException or ArgumentException or InvalidOperationException or TimeoutException)
            {
                await output.WriteLineAsync($"migrate failed: {ex.Message}");
                return SchemaCommandLine.NotDone;
            }
        }

        private static async Task<bool> SchemaExistsAsync(SqlConnection connection, string schema, CancellationToken cancellationToken)
        {
            await using var command = connection.CreateCommand();
            command.CommandText = "SELECT SCHEMA_ID(@schema)";
            command.Parameters.AddWithValue("@schema", schema);
            return await command.ExecuteScalarAsync(cancellationToken) is not (null or DBNull);
        }

        /// <summary>When the rollback window of the cutover closes, or null when the target was not cut over (or has no history yet).</summary>
        private static async Task<DateTime?> CutOverAsync(SqlConnection connection, string target, CancellationToken cancellationToken)
        {
            try
            {
                return (await LegacyCutover.WindowAsync(connection, target, cancellationToken))?.WindowEnds;
            }
            catch (DbException)
            {
                return null;
            }
        }
    }
}
