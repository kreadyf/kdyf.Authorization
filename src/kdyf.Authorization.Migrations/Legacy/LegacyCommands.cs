using System.Data.Common;
using kdyf.Authorization.Abstractions;
using kdyf.Authorization.Migrations.Schema;
using kdyf.Authorization.Roles;
using kdyf.Authorization;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace kdyf.Authorization.Migrations.Legacy
{
    public static class LegacyImportServiceCollectionExtensions
    {
        /// <summary>
        /// What the legacy import needs from the host: the legacy schema and gate, and the directory over the host's Graph
        /// registration (<c>UseEntraId</c>). The new gate is the host's own (<see cref="IMembershipSource"/>).
        /// </summary>
        public static IServiceCollection AddKdyfAuthorizationLegacyImport(this IServiceCollection services, Action<LegacyImportOptions> configure)
        {
            services.AddOptions<LegacyImportOptions>().Configure(configure);
            // TryAdd: a host (or a test) that brings its own directory keeps it.
            services.TryAddSingleton<ILegacyDirectory, GraphLegacyDirectory>();
            return services;
        }
    }

    /// <summary>
    /// The commands of the legacy import that need the host (its Graph registration and its access gate):
    /// <c>resolve</c> and <c>identities export|import</c>. They write only the import's working tables in the target schema.
    /// </summary>
    internal static class LegacyCommands
    {
        public static bool Handles(string command) => command is "resolve" or "identities" or "import" or "exceptions" or "rollback-sync" or "contract";

        public static async Task<int> RunAsync(
            IReadOnlyList<string> args, string connectionString, string targetSchema, IServiceProvider? services, TextWriter output, CancellationToken cancellationToken)
        {
            var command = args[0].ToLowerInvariant();
            if (command is "rollback-sync" or "contract")
                return await DatabaseOnlyAsync(command, args, connectionString, targetSchema, services, output, cancellationToken);

            var options = services?.GetService<IOptions<LegacyImportOptions>>()?.Value;
            var directory = services?.GetService<ILegacyDirectory>();
            var newGate = services?.GetService<IMembershipSource>();
            if (options is null || directory is null || newGate is null)
            {
                await output.WriteLineAsync($"'{command}' runs in the host ('<host> kdyf-auth {command}'), with AddKdyfAuthorizationLegacyImport and the host's Entra ID: "
                                            + "it asks the directory and both access gates.");
                return SchemaCommandLine.Usage;
            }

            string? subcommand = null, file = null, approver = null;
            var approvals = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var window = TimeSpan.FromHours(48);
            var incremental = false;
            var legacySchema = options.LegacySchema;
            for (var i = 1; i < args.Count; i++)
            {
                switch (args[i])
                {
                    case "--incremental": incremental = true; break;
                    case "--approver" when i + 1 < args.Count: approver = args[++i]; break;
                    case "--approve" when i + 1 < args.Count: approvals.Add(args[++i]); break;
                    case "--rollback-window" when i + 1 < args.Count && int.TryParse(args[i + 1].TrimEnd('h'), out var hours): window = TimeSpan.FromHours(hours); i++; break;
                    case "--legacy-schema" when i + 1 < args.Count: legacySchema = args[++i]; break;
                    case "--schema" when i + 1 < args.Count: targetSchema = args[++i]; break;
                    default:
                        if (command is "identities" or "import" or "exceptions" && subcommand is null) subcommand = args[i].ToLowerInvariant();
                        else if (command is "identities" or "exceptions" && file is null) file = args[i];
                        else
                        {
                            await output.WriteLineAsync($"Unknown argument '{args[i]}'.");
                            return SchemaCommandLine.Usage;
                        }
                        break;
                }
            }

            try
            {
                await using var connection = new SqlConnection(connectionString);
                await connection.OpenAsync(cancellationToken);

                switch (command)
                {
                    case "resolve":
                        return await ResolveAsync(connection, connectionString, legacySchema, targetSchema, incremental, options, directory, newGate, output, cancellationToken);

                    case "import" when subcommand is "plan" or "apply" or "reductions-accept" or "cutover":
                    {
                        var declared = services!.GetService<DeclaredPermissions>();
                        if (declared is null)
                        {
                            await output.WriteLineAsync("The host declares no permissions (AddAssignedRoles): the import copies only what the host declares.");
                            return SchemaCommandLine.Usage;
                        }
                        var unknown = approvals.Where(a => a != LegacyImportApprovals.UnresolvedUsers).ToList();
                        if (unknown.Count > 0)
                        {
                            await output.WriteLineAsync($"Unknown approval {string.Join(", ", unknown)}: {LegacyImportApprovals.UnresolvedUsers}.");
                            return SchemaCommandLine.Usage;
                        }
                        var authorization = services!.GetService<PermissionAuthorizationOptions>();
                        var report = await LegacyImporter.RunAsync(connectionString, new LegacyImportRequest
                        {
                            Invariant = new InvariantSettings
                            {
                                MemberGrants = authorization?.MemberPermissionCodes.ToList() ?? new List<string>(),
                                AdministrationCode = authorization?.AdministrationPermissionCode,
                                ExactCodes = options.ExactCodes.Concat(authorization?.AdministrationPermissionCode is { } admin ? new[] { admin } : Array.Empty<string>()).Distinct().ToList(),
                                MinAdministrators = options.MinAdministrators,
                                TokensExemptFromGate = options.Gate == LegacyGate.Group,
                            },
                            LegacySchema = legacySchema,
                            TargetSchema = targetSchema,
                            Declared = declared.Permissions,
                            HostSteps = services!.GetServices<ILegacyImportHostStep>().ToList(),
                            MaxSnapshotAge = options.MaxSnapshotAge,
                            Apply = subcommand == "apply",
                            Settings = new LegacyImportSettings
                            {
                                AutoProvisionedRole = options.AutoProvisionedRole,
                                BootstrapTokenHash = options.BootstrapTokenHash,
                                RoleValueOverrides = options.RoleValueOverrides,
                                Approvals = approvals,
                            },
                        }, cancellationToken);
                        if (subcommand is "plan" or "apply")
                        {
                            await output.WriteAsync(LegacyImporter.ToText(report));
                            return report.HasBlockers ? SchemaCommandLine.NotDone : SchemaCommandLine.Ok;
                        }

                        if (string.IsNullOrWhiteSpace(approver))
                        {
                            await output.WriteLineAsync("Name who approves: --approver <name>.");
                            return SchemaCommandLine.Usage;
                        }

                        if (subcommand == "reductions-accept")
                        {
                            if (report.HasBlockers || report.Invariant is null)
                            {
                                await output.WriteAsync(LegacyImporter.ToText(report));
                                await output.WriteLineAsync("Blockers stand: there is nothing to accept yet.");
                                return SchemaCommandLine.NotDone;
                            }
                            foreach (var (user, codes) in report.Invariant.Reductions)
                                await output.WriteLineAsync($"  user {user} loses: {string.Join(", ", codes)}");
                            var fingerprint = await LegacyCutover.AcceptReductionsAsync(connectionString, targetSchema, report.Invariant, approver, cancellationToken);
                            await output.WriteLineAsync($"Accepted by {approver}: {report.Invariant.Reductions.Count} user(s), list {fingerprint}. A different list needs a new acceptance.");
                            return SchemaCommandLine.Ok;
                        }

                        // The cutover: the automatic go/no-go, then the marker and the rollback window.
                        var checks = await LegacyCutover.CheckAsync(connectionString, targetSchema, report, cancellationToken);
                        foreach (var check in checks)
                            await output.WriteLineAsync(check.ToString());
                        if (checks.Any(c => !c.Passed))
                        {
                            await output.WriteLineAsync("No go: nothing was changed.");
                            return SchemaCommandLine.NotDone;
                        }
                        await LegacyCutover.CutoverAsync(connectionString, targetSchema, approver, window, cancellationToken);
                        await output.WriteLineAsync($"Cut over by {approver}. Rollback window: {window.TotalHours:0} h; keep the administration frozen except revocations, "
                                                    + "and run 'rollback-sync apply' before going back.");
                        return SchemaCommandLine.Ok;
                    }

                    case "exceptions" when subcommand == "import" && file is not null:
                    {
                        if (string.IsNullOrWhiteSpace(approver))
                        {
                            await output.WriteLineAsync("Name who approves: --approver <name>.");
                            return SchemaCommandLine.Usage;
                        }
                        var json = await File.ReadAllTextAsync(file, cancellationToken);
                        var exceptions = InvariantExceptions.Parse(json, approver);
                        await using (var bootstrap = connection.CreateCommand())
                        {
                            bootstrap.CommandText = MigrationStore.BootstrapSql(targetSchema);
                            await bootstrap.ExecuteNonQueryAsync(cancellationToken);
                        }
                        var checksum = InvariantExceptions.Checksum(json);
                        await InvariantExceptions.ReplaceAsync(connection, targetSchema, exceptions, checksum, cancellationToken);
                        await output.WriteLineAsync($"{exceptions.Count} exception(s) approved by {approver}, file {checksum[..12]}…; they replace the previous set.");
                        return SchemaCommandLine.Ok;
                    }

                    case "identities" when subcommand == "export" && file is not null:
                    {
                        var identities = await MigrationStore.LoadAsync(connection, targetSchema, cancellationToken);
                        if (identities.Count == 0)
                        {
                            await output.WriteLineAsync("Nothing resolved yet: run 'kdyf-auth resolve'.");
                            return SchemaCommandLine.NotDone;
                        }
                        await File.WriteAllTextAsync(file, IdentityReview.ToCsv(identities), cancellationToken);
                        await output.WriteLineAsync($"{identities.Count} identities written to {file}. It holds e-mails: keep it out of source control, and delete it after the review.");
                        return SchemaCommandLine.Ok;
                    }

                    case "identities" when subcommand == "import" && file is not null:
                    {
                        if (string.IsNullOrWhiteSpace(approver))
                        {
                            await output.WriteLineAsync("Name who approves: --approver <name>.");
                            return SchemaCommandLine.Usage;
                        }
                        var identities = await MigrationStore.LoadAsync(connection, targetSchema, cancellationToken);
                        var decisions = IdentityReview.ReadDecisions(await File.ReadAllTextAsync(file, cancellationToken));
                        var (updated, problems) = await IdentityReview.ApplyAsync(identities, decisions, approver, directory, newGate, DateTime.UtcNow, cancellationToken);
                        if (problems.Count > 0)
                        {
                            foreach (var problem in problems)
                                await output.WriteLineAsync(problem);
                            await output.WriteLineAsync("Nothing was saved.");
                            return SchemaCommandLine.NotDone;
                        }
                        await MigrationStore.SaveAsync(connection, targetSchema, updated, cancellationToken);
                        await WriteSummaryAsync(output, updated);
                        return SchemaCommandLine.Ok;
                    }

                    default:
                        await output.WriteLineAsync("identities export <file> | identities import <file> --approver <name>");
                        return SchemaCommandLine.Usage;
                }
            }
            catch (Exception ex) when (ex is DbException or InvalidOperationException or FormatException or IOException or EntraId.GraphException)
            {
                await output.WriteLineAsync($"{command} failed: {ex.Message}");
                return SchemaCommandLine.NotDone;
            }
        }

        /// <summary>The commands that only need the database: rollback-sync and the contraction.</summary>
        private static async Task<int> DatabaseOnlyAsync(
            string command, IReadOnlyList<string> args, string connectionString, string targetSchema, IServiceProvider? services, TextWriter output,
            CancellationToken cancellationToken)
        {
            var legacySchema = services?.GetService<IOptions<LegacyImportOptions>>()?.Value.LegacySchema ?? "auth";
            string? subcommand = null;
            var confirmed = false;
            for (var i = 1; i < args.Count; i++)
            {
                switch (args[i])
                {
                    case "--legacy-schema" when i + 1 < args.Count: legacySchema = args[++i]; break;
                    case "--schema" when i + 1 < args.Count: targetSchema = args[++i]; break;
                    case "--confirm": confirmed = true; break;
                    default:
                        if (subcommand is null) subcommand = args[i].ToLowerInvariant();
                        else
                        {
                            await output.WriteLineAsync($"Unknown argument '{args[i]}'.");
                            return SchemaCommandLine.Usage;
                        }
                        break;
                }
            }

            try
            {
                if (command == "rollback-sync" && subcommand is "plan" or "apply")
                {
                    var changes = await LegacyCutover.RollbackSyncAsync(connectionString, legacySchema, targetSchema, subcommand == "apply", cancellationToken);
                    foreach (var change in changes)
                        await output.WriteLineAsync($"  {change.Table,-20} {change.Count,5}  {change.What}");
                    await output.WriteLineAsync(subcommand == "apply" ? $"Taken back to [{legacySchema}]." : "Dry run: nothing was changed.");
                    return SchemaCommandLine.Ok;
                }

                if (command == "contract" && subcommand is "promote")
                {
                    if (!confirmed)
                    {
                        await output.WriteLineAsync($"The promotion renames the schema [{targetSchema}] to [{legacySchema}] (and the runtime role with it): confirm it with --confirm.");
                        return SchemaCommandLine.Usage;
                    }
                    await output.WriteLineAsync(await LegacyCutover.PromoteAsync(connectionString, targetSchema, legacySchema, DateTime.UtcNow, cancellationToken));
                    return SchemaCommandLine.Ok;
                }

                if (command == "contract" && subcommand is "cleanup")
                {
                    if (!confirmed)
                    {
                        await output.WriteLineAsync($"The cleanup drops the import's working tables of [{targetSchema}] (identities with e-mails, gate snapshot, issues, approved exceptions): confirm it with --confirm.");
                        return SchemaCommandLine.Usage;
                    }
                    await output.WriteLineAsync(await LegacyCutover.CleanupAsync(connectionString, targetSchema, DateTime.UtcNow, cancellationToken));
                    return SchemaCommandLine.Ok;
                }

                if (command == "contract" && subcommand is "rename" or "drop")
                {
                    if (!confirmed)
                    {
                        await output.WriteLineAsync($"The contraction {(subcommand == "drop" ? "drops" : "renames")} [{legacySchema}]: confirm it with --confirm.");
                        return SchemaCommandLine.Usage;
                    }
                    await output.WriteLineAsync(await LegacyCutover.ContractAsync(connectionString, legacySchema, targetSchema, subcommand == "drop", DateTime.UtcNow, cancellationToken));
                    return SchemaCommandLine.Ok;
                }

                await output.WriteLineAsync("rollback-sync plan|apply | contract rename|drop|promote|cleanup --confirm");
                return SchemaCommandLine.Usage;
            }
            catch (Exception ex) when (ex is DbException or InvalidOperationException)
            {
                await output.WriteLineAsync($"{command} failed: {ex.Message}");
                return SchemaCommandLine.NotDone;
            }
        }

        private static async Task<int> ResolveAsync(
            DbConnection connection, string connectionString, string legacySchema, string targetSchema, bool incremental, LegacyImportOptions options,
            ILegacyDirectory directory, IMembershipSource newGate, TextWriter output, CancellationToken cancellationToken)
        {
            var (shape, report) = await LegacyInspector.InspectAsync(connectionString, legacySchema, cancellationToken: cancellationToken);
            if (report is null)
            {
                await output.WriteLineAsync($"Legacy shape {shape.Label}: {shape.Description}");
                return SchemaCommandLine.NotDone;
            }

            IReadOnlyDictionary<int, ResolvedIdentity>? previous = null;
            if (incremental)
                previous = (await MigrationStore.LoadAsync(connection, targetSchema, cancellationToken)).ToDictionary(i => i.LegacyUserId);

            var resolver = new IdentityResolver(directory, newGate, options);
            var identities = await resolver.ResolveAsync(report.Data.Users, previous, cancellationToken);
            await MigrationStore.SaveAsync(connection, targetSchema, identities, cancellationToken);

            await output.WriteLineAsync($"Resolved {identities.Count} legacy users of [{legacySchema}] into [{targetSchema}].{(incremental ? $" {identities.Count(i => previous!.ContainsKey(i.LegacyUserId) && previous[i.LegacyUserId] == i)} kept from before." : "")}");
            await WriteSummaryAsync(output, identities);
            return identities.All(i => i.Importable || !i.PassedLegacyGate) ? SchemaCommandLine.Ok : SchemaCommandLine.NotDone;
        }

        /// <summary>Counts and the users to decide on, by legacy id: no e-mails on screen.</summary>
        private static async Task WriteSummaryAsync(TextWriter output, IReadOnlyList<ResolvedIdentity> identities)
        {
            foreach (var group in identities.GroupBy(i => i.Status).OrderBy(g => g.Key))
                await output.WriteLineAsync($"  {group.Key,-10} {group.Count(),4}  approved {group.Count(i => i.Approved)}");
            await output.WriteLineAsync($"  legacy gate passed {identities.Count(i => i.PassedLegacyGate)}, new gate passes {identities.Count(i => i.PassesNewGate == true)}");

            var lost = identities.Where(i => !i.PassesNewGate.GetValueOrDefault() && i.PassedLegacyGate && i.Importable).Select(i => i.LegacyUserId).ToList();
            if (lost.Count > 0)
                await output.WriteLineAsync($"  In the legacy gate but not in the new one (they would lose access): {string.Join(", ", lost)}");
            var pending = identities.Where(i => !i.Importable).Select(i => $"{i.LegacyUserId} ({i.Status})").ToList();
            if (pending.Count > 0)
                await output.WriteLineAsync($"  To decide (export, review, import): {string.Join(", ", pending)}");
        }
    }
}
