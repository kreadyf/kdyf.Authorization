using System.Reflection;
using kdyf.Authorization.Abstractions;
using kdyf.Authorization.Roles;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Declaration = kdyf.Authorization.Abstractions.PermissionDefinition;
using PermissionRow = kdyf.Authorization.EntityFrameworkCore.Entities.Permission;

namespace kdyf.Authorization.EntityFrameworkCore
{
    /// <summary>How the catalog synchronisation behaves.</summary>
    public sealed class PermissionCatalogSyncOptions
    {
        /// <summary>Where the declarations live: every concrete <see cref="Declaration"/> in them.</summary>
        public List<Assembly> Assemblies { get; } = new();

        /// <summary>
        /// The declarations themselves, when they are not simply "everything in an assembly".
        /// </summary>
        /// <remarks>
        /// Takes the place of <see cref="Assemblies"/> when it has anything in it. For a consumer
        /// that composes its catalog from more than one place, and for exercising this service
        /// against one set of declarations at a time — scanning cannot do that, because every
        /// declaration in a test assembly belongs to every test in it.
        /// </remarks>
        public List<Declaration> Declarations { get; } = new();

        /// <summary>
        /// Read the declarations from the <see cref="DeclaredPermissions"/> registered by <c>AddAssignedRoles</c> —
        /// the catalog authorization itself reads — instead of scanning <see cref="Assemblies"/>.
        /// </summary>
        /// <remarks>
        /// What <c>UseEntityFrameworkStore</c> sets: the rows are then written from the very list the roles are checked
        /// against, area wildcards included, so the two cannot drift. <see cref="Declarations"/>, when it has anything in
        /// it, still takes the place of both. Without a registered <see cref="DeclaredPermissions"/> it falls back to
        /// <see cref="Assemblies"/> and says so.
        /// </remarks>
        public bool FromDeclaredPermissions { get; set; }

        /// <summary>
        /// Log what WOULD change and write nothing.
        /// </summary>
        /// <remarks>
        /// For an environment where data changes go through a reviewed script. Note what it costs: a
        /// declared code with no row denies every endpoint behind it, in silence — so leaving this on
        /// means somebody has to act on the log.
        /// </remarks>
        public bool ReportOnly { get; set; }
    }

    /// <summary>
    /// Brings <c>auth.Permission</c> in line with the permissions declared in code: inserts the ones
    /// that are missing and updates a name or description that has changed.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is what makes a declaration self-sufficient — add the class, and the permission exists.
    /// Until now the code and the row were two halves of one fact maintained by hand, and forgetting
    /// the second is the quietest failure this system has: the policy denies, always, and nothing
    /// anywhere says why.
    /// </para>
    /// <para>
    /// <b>It never deletes.</b> A row that no longer has a class may still be granted to roles, and
    /// the foreign key from <c>auth.RolePermission</c> has no cascade — the delete would fail rather
    /// than quietly strip people's access. That is the better of the two outcomes, but neither is
    /// this service's decision to make. Undeclared rows are reported and left alone.
    /// </para>
    /// <para>
    /// <b>It never rewrites a code.</b> The code is the primary key and the target of that foreign
    /// key; changing it is a migration, not a sync. So a declaration differing from an existing row
    /// only in capitalisation is an ERROR rather than an update: the default collation would match
    /// the two, an insert would violate the key, and an update would break the grants.
    /// </para>
    /// </remarks>
    public sealed class PermissionCatalogSynchronizer<TContext> : IHostedService
        where TContext : DbContext
    {
        private readonly IServiceProvider _services;
        private readonly PermissionCatalogSyncOptions _options;
        private readonly IHostEnvironment _environment;
        private readonly ILogger<PermissionCatalogSynchronizer<TContext>> _logger;

        /// <summary>For the container.</summary>
        public PermissionCatalogSynchronizer(
            IServiceProvider services,
            PermissionCatalogSyncOptions options,
            IHostEnvironment environment,
            ILogger<PermissionCatalogSynchronizer<TContext>> logger)
        {
            _services = services;
            _options = options;
            _environment = environment;
            _logger = logger;
        }

        /// <summary>
        /// Runs the synchronisation once, at startup: inserts the missing rows and updates changed names and descriptions,
        /// or only logs them under <see cref="PermissionCatalogSyncOptions.ReportOnly"/>.
        /// </summary>
        /// <remarks>
        /// An invalid, duplicated or miscased declaration, or a write that was refused, throws
        /// <see cref="InvalidOperationException"/> outside Production and is logged as critical in Production. A catalog
        /// that cannot be read is logged and the synchronisation is skipped: the host still starts.
        /// </remarks>
        public async Task StartAsync(CancellationToken cancellationToken)
        {
            var declared = _options.Declarations.Count > 0
                ? _options.Declarations.ToList()
                : FromCatalog() ?? _options.Assemblies.SelectMany(Declaration.DiscoverIn).ToList();

            if (declared.Count == 0)
            {
                _logger.LogWarning(
                    "Permission catalog sync: no permission is declared in {Assemblies}. Nothing to do.",
                    string.Join(", ", _options.Assemblies.Select(a => a.GetName().Name)));
                return;
            }

            var invalid = Validate(declared);
            if (invalid.Count > 0)
                Report(string.Join(" ", invalid.Values));

            // DiscoverIn checks one assembly; two sources can still declare one code. Adding the
            // same key twice would throw from EF before any of the handling below.
            var duplicated = declared
                .GroupBy(p => p.Code, StringComparer.OrdinalIgnoreCase)
                .Where(g => g.Count() > 1)
                .Select(g => g.Key)
                .ToList();
            if (duplicated.Count > 0)
                Report("these permission codes are declared more than once: " + string.Join(", ", duplicated) + ".");

            var usable = declared
                .Where(p => !invalid.ContainsKey(p))
                .DistinctBy(p => p.Code, StringComparer.OrdinalIgnoreCase)
                .ToList();

            using var scope = _services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<TContext>();

            List<PermissionRow> rows;
            try
            {
                rows = await db.Set<PermissionRow>().ToListAsync(cancellationToken);
            }
            catch (Exception ex)
            {
                // A database that is not up yet is not a wiring mistake. Say so and let the host
                // start: refusing to boot over a diagnostic is worse than booting without it.
                _logger.LogError(ex, "Permission catalog unreadable — the synchronisation is skipped this time.");
                return;
            }

            // Matched the way the DATABASE matches, not the way C# does: the key is case-insensitive
            // under the default collation, so an ordinal lookup would call an existing row missing
            // and then fail trying to insert it.
            // Tolerant of two rows differing only in case (a case-sensitive collation allows it):
            // the first wins here, the other is reported as undeclared below.
            var byCode = new Dictionary<string, PermissionRow>(StringComparer.OrdinalIgnoreCase);
            foreach (var row in rows)
                byCode.TryAdd(row.PermissionCode, row);

            var added = new List<Declaration>();
            var updated = new List<Declaration>();
            var miscased = new List<string>();

            foreach (var permission in usable)
            {
                if (!byCode.TryGetValue(permission.Code, out var row))
                {
                    added.Add(permission);
                    continue;
                }

                if (!string.Equals(row.PermissionCode, permission.Code, StringComparison.Ordinal))
                {
                    miscased.Add($"'{permission.Code}' is declared but its row reads '{row.PermissionCode}'");
                    continue;
                }

                if (string.Equals(row.Name, permission.Name, StringComparison.Ordinal)
                    && string.Equals(row.Description, permission.Description, StringComparison.Ordinal))
                    continue;

                updated.Add(permission);

                if (!_options.ReportOnly)
                {
                    row.Name = permission.Name;
                    row.Description = permission.Description;
                }
            }

            if (miscased.Count > 0)
                Report("these permissions differ from their row only in capitalisation, which this service "
                       + "cannot fix — the code is the primary key and the grants point at it: "
                       + string.Join("; ", miscased) + ".");

            var undeclared = rows
                .Where(r => !usable.Any(p => string.Equals(p.Code, r.PermissionCode, StringComparison.OrdinalIgnoreCase)))
                .Select(r => r.PermissionCode)
                .OrderBy(c => c, StringComparer.Ordinal)
                .ToList();

            if (undeclared.Count > 0)
                _logger.LogWarning(
                    "Permission catalog sync: {Count} row(s) of auth.Permission are declared by no class and were left "
                    + "untouched — a role may still be granting them: {Codes}.",
                    undeclared.Count, string.Join(", ", undeclared));

            if (added.Count == 0 && updated.Count == 0)
            {
                _logger.LogInformation(
                    "Permission catalog sync: {Count} declared permissions, all present and up to date.", usable.Count);
                return;
            }

            if (_options.ReportOnly)
            {
                _logger.LogWarning(
                    "Permission catalog sync (report only): {Added} to add ({AddedCodes}), {Updated} to update "
                    + "({UpdatedCodes}). Nothing was written.",
                    added.Count, Codes(added), updated.Count, Codes(updated));
                return;
            }

            foreach (var permission in added)
                db.Set<PermissionRow>().Add(new PermissionRow
                {
                    PermissionCode = permission.Code,
                    Name = permission.Name,
                    Description = permission.Description,
                });

            Exception? refused = null;
            try
            {
                await db.SaveChangesAsync(cancellationToken);
            }
            catch (Exception ex)
            {
                // Every exception, not just DbUpdateException. A write that cannot happen AT ALL —
                // a read-only database, an application user with no INSERT on auth.Permission —
                // surfaces as the provider's own exception, sometimes from opening the transaction
                // rather than from the write. Letting that escape would stop the host from booting,
                // which is the opposite of what this service promises.
                //
                // And nothing is swallowed: what this was gets decided below, by asking the table.
                // The same DbUpdateException covers another replica writing the same rows a moment
                // earlier — benign — and a refusal, which is anything but.
                refused = ex;
            }

            await VerifyOrReportAsync(db, usable, added.Count, refused, cancellationToken);

            _logger.LogInformation(
                "Permission catalog sync: added {Added} ({AddedCodes}), updated {Updated} ({UpdatedCodes}).",
                added.Count, Codes(added), updated.Count, Codes(updated));

            // A new row changes what a wildcard stands for, and an expanded set is cached. At a cold
            // start there is nothing to drop; this covers an instance that is already serving.
            if (added.Count > 0)
                scope.ServiceProvider.GetService<IPermissionCache>()?.InvalidateAll();
        }

        /// <summary>
        /// After writing, asks the table whether the declarations are actually there.
        /// </summary>
        /// <remarks>
        /// <para>
        /// This is what used to be a second hosted service, and it belongs here: it asks the same
        /// question this one already answered, one step later. As a separate service it also had to
        /// be registered AFTER — an invisible dependency between two adjacent lines, breakable by
        /// tidying them.
        /// </para>
        /// <para>
        /// And it is the only honest way to read a failed write. A row that is present now means
        /// somebody else wrote it: nothing was lost. A row still missing means the write was
        /// REFUSED, and then every endpoint behind that code denies in silence — the failure this
        /// whole service exists to prevent, arrived through the back door.
        /// </para>
        /// </remarks>
        private async Task VerifyOrReportAsync(
            TContext db, List<Declaration> declared, int addedCount, Exception? refused, CancellationToken ct)
        {
            db.ChangeTracker.Clear();

            var present = (await db.Set<PermissionRow>()
                    .AsNoTracking()
                    .Select(r => r.PermissionCode)
                    .ToListAsync(ct))
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            var missing = declared
                .Where(p => !present.Contains(p.Code))
                .Select(p => p.Code)
                .OrderBy(code => code, StringComparer.Ordinal)
                .ToList();

            if (missing.Count == 0)
            {
                if (refused is null)
                    return;

                // Nothing missing after a failed write means somebody else inserted it — but only
                // if there was something to insert. A refused UPDATE leaves every row in place and
                // would otherwise pass here as a benign race.
                if (addedCount > 0)
                {
                    _logger.LogInformation(
                        "Permission catalog sync: another instance wrote the same rows first.");
                    return;
                }

                _logger.LogError(refused, "Permission catalog sync: the write was refused.");
                Report("the name/description update was refused. Check that the application user may UPDATE auth.Permission.");
                return;
            }

            if (refused is not null)
                _logger.LogError(refused, "Permission catalog sync: the write was refused.");

            var why = refused is null
                ? "the write reported success but the rows are not there"
                : "the write was refused — check that the application user may INSERT into auth.Permission";

            Report($"these declared permissions are still missing after writing ({why}): "
                   + $"{string.Join(", ", missing)}. Every endpoint behind them denies in silence.");
        }

        /// <summary>The registered catalog's declarations under <see cref="PermissionCatalogSyncOptions.FromDeclaredPermissions"/>;
        /// null to scan the assemblies instead.</summary>
        private List<Declaration>? FromCatalog()
        {
            if (!_options.FromDeclaredPermissions)
                return null;

            var catalog = _services.GetService<DeclaredPermissions>();
            if (catalog is null)
            {
                _logger.LogWarning(
                    "Permission catalog sync: FromDeclaredPermissions is on but no DeclaredPermissions is registered (AddAssignedRoles); "
                    + "scanning {Assemblies} instead.",
                    string.Join(", ", _options.Assemblies.Select(a => a.GetName().Name)));
                return null;
            }

            return catalog.Permissions.ToList();
        }

        /// <summary>Declarations that cannot be stored as they are, with the reason.</summary>
        /// <remarks>
        /// Checked here rather than left to the insert: a truncation or a duplicate key surfaces as a
        /// provider error naming a column, and the reader has to work backwards to the class that
        /// caused it.
        /// </remarks>
        private static Dictionary<Declaration, string> Validate(IEnumerable<Declaration> declared)
        {
            var invalid = new Dictionary<Declaration, string>();

            foreach (var permission in declared)
            {
                if (permission.Code.Length > 50)
                    invalid[permission] = $"'{permission.Code}' is longer than the 50 characters of PermissionCode.";
                else if (permission.Code.Any(c => c > 127))
                    invalid[permission] = $"'{permission.Code}' has non-ASCII characters and PermissionCode is VARCHAR.";
                else if (permission.Name.Length > 100)
                    invalid[permission] = $"the name of '{permission.Code}' is longer than 100 characters.";
                else if (permission.Description?.Length > 200)
                    invalid[permission] = $"the description of '{permission.Code}' is longer than 200 characters.";
            }

            return invalid;
        }

        /// <summary>
        /// Outside Production this throws, which is what makes it a net: the mistake surfaces on the
        /// machine of whoever made it. In Production it is logged instead — a deployment must not be
        /// stopped by a diagnostic, and the rows that CAN be written still are.
        /// </summary>
        private void Report(string message)
        {
            if (_environment.IsProduction())
            {
                _logger.LogCritical("Permission catalog sync: {Message}", message);
                return;
            }

            throw new InvalidOperationException($"Permission catalog sync: {message}");
        }

        private static string Codes(IEnumerable<Declaration> permissions) =>
            string.Join(", ", permissions.Select(p => p.Code));

        /// <summary>Nothing to stop.</summary>
        public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
