using System.Data;
using System.Data.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace kdyf.Authorization.EntityFrameworkCore
{
    /// <summary>The version of the schema these packages are built for.</summary>
    public static class AuthorizationSchema
    {
        /// <summary>
        /// The schema version with the profiles (<see cref="AuthorizationStoreOptions.UserProfiles"/>): the last step of
        /// kdyf.Authorization.Migrations, which ships with the same version.
        /// </summary>
        public const int RequiredVersion = 4;

        /// <summary>The version without the profiles: the six tables the reference databases already have, indexed and granted.</summary>
        public const int RequiredVersionWithoutProfiles = 3;

        /// <summary>
        /// The schema version the host expects. A schema at this version or newer works (steps widen, they do not break).
        /// </summary>
        public static int RequiredVersionFor(bool userProfiles) => userProfiles ? RequiredVersion : RequiredVersionWithoutProfiles;
    }

    /// <summary>
    /// When the host starts, checks the version of the schema in <c>{Schema}.SchemaVersion</c>, written by the schema
    /// migration (kdyf.Authorization.Migrations). Never changes anything.
    /// </summary>
    /// <remarks>
    /// <list type="bullet">
    /// <item>No history: a warning (the schema predates versioning: adopt it), or a failure with
    /// <see cref="AuthorizationStoreOptions.RequireSchemaVersion"/>.</item>
    /// <item>A version below <see cref="AuthorizationSchema.RequiredVersion"/>, or a step recorded as failed: the host does
    /// not start, and the message says what is missing and how to apply it.</item>
    /// <item>The database unreachable: logged and the host starts, as the catalog sync does, unless the version is
    /// required.</item>
    /// <item>Not SQL Server: nothing (the versioning is SQL Server's).</item>
    /// </list>
    /// </remarks>
    internal sealed class SchemaVersionCheck<TContext> : IHostedService
        where TContext : DbContext
    {
        private readonly IServiceProvider _services;
        private readonly IOptions<AuthorizationStoreOptions> _options;
        private readonly ILogger<SchemaVersionCheck<TContext>> _logger;

        public SchemaVersionCheck(IServiceProvider services, IOptions<AuthorizationStoreOptions> options, ILogger<SchemaVersionCheck<TContext>> logger)
        {
            _services = services;
            _options = options;
            _logger = logger;
        }

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            var options = _options.Value;
            using var scope = _services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<TContext>();
            if (db.Database.ProviderName != "Microsoft.EntityFrameworkCore.SqlServer")
                return;

            SchemaVersionState state;
            try
            {
                state = await ReadAsync(db.Database.GetDbConnection(), options.Schema, cancellationToken);
            }
            catch (DbException ex)
            {
                if (options.RequireSchemaVersion)
                    throw new InvalidOperationException($"The version of the schema '{options.Schema}' cannot be read, and RequireSchemaVersion is on.", ex);
                _logger.LogError(ex, "The version of the schema {Schema} cannot be read: the check is skipped this time.", options.Schema);
                return;
            }

            var error = Evaluate(state, options);
            if (error is not null)
                throw new InvalidOperationException(error);

            if (state.Version is null)
                _logger.LogWarning(
                    "The schema {Schema} has no version (no SchemaVersion table): it predates the versioning of kdyf.Authorization. "
                    + "Adopt it with 'kdyf-auth adopt' (it is stamped, not rebuilt), then turn RequireSchemaVersion on.",
                    options.Schema);
            else
                _logger.LogInformation("The schema {Schema} is at version {Version} (required {Required}).",
                    options.Schema, state.Version, AuthorizationSchema.RequiredVersionFor(options.UserProfiles));
        }

        public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        internal sealed record SchemaVersionState(int? Version, string? FailedStep, bool HasUserProfile = true);

        /// <summary>The reason the host must not start, or <c>null</c>.</summary>
        internal static string? Evaluate(SchemaVersionState state, AuthorizationStoreOptions options)
        {
            var schema = options.Schema;
            if (state.FailedStep is not null)
                return $"The migration of the schema '{schema}' failed at step {state.FailedStep} and was not resumed. "
                       + "Run 'kdyf-auth apply' again: it resumes the failed step.";
            if (state.Version is null)
            {
                if (options.RequireSchemaVersion)
                    return $"The schema '{schema}' has no version, and RequireSchemaVersion is on. Adopt or migrate it with 'kdyf-auth adopt' or 'kdyf-auth apply'.";
                // Without a version the host only warns, unless the tables these packages need are not there: every
                // request would fail on them, so it is said now.
                if (options.UserProfiles && !state.HasUserProfile)
                    return $"The schema '{schema}' has no version and no UserProfile table, which UserProfiles needs (schema version 4). "
                           + "Run 'kdyf-auth adopt' (or 'apply'): it stamps the existing tables and adds the missing ones.";
                return null;
            }
            var required = AuthorizationSchema.RequiredVersionFor(options.UserProfiles);
            if (state.Version < required)
                return $"The schema '{schema}' is at version {state.Version}; this configuration requires {required}"
                       + (options.UserProfiles ? " (UserProfiles is on). " : ". ")
                       + "Run 'kdyf-auth apply' before deploying this version.";
            return null;
        }

        private static async Task<SchemaVersionState> ReadAsync(DbConnection connection, string schema, CancellationToken cancellationToken)
        {
            var opened = connection.State != ConnectionState.Open;
            if (opened)
                await connection.OpenAsync(cancellationToken);
            try
            {
                await using var command = connection.CreateCommand();
                // The schema name is validated at startup (letters, digits and '_'): safe to bracket. The version is the
                // highest step applied with every step before it applied too.
                command.CommandText = $"""
                    IF OBJECT_ID(N'[{schema}].[SchemaVersion]') IS NULL
                        SELECT CAST(NULL AS INT), CAST(NULL AS VARCHAR(100)), CAST(CASE WHEN OBJECT_ID(N'[{schema}].[UserProfile]') IS NULL THEN 0 ELSE 1 END AS BIT);
                    ELSE
                        SELECT
                            (SELECT MAX(v.Version) FROM [{schema}].[SchemaVersion] v
                             WHERE v.Status = 'Applied'
                               AND (SELECT COUNT(*) FROM [{schema}].[SchemaVersion] p WHERE p.Status = 'Applied' AND p.Version <= v.Version) = v.Version + 1),
                            (SELECT TOP (1) StepId FROM [{schema}].[SchemaVersion] WHERE Status = 'Failed' ORDER BY Version),
                            CAST(CASE WHEN OBJECT_ID(N'[{schema}].[UserProfile]') IS NULL THEN 0 ELSE 1 END AS BIT);
                    """;
                await using var reader = await command.ExecuteReaderAsync(cancellationToken);
                await reader.ReadAsync(cancellationToken);
                return new SchemaVersionState(reader.IsDBNull(0) ? null : reader.GetInt32(0), reader.IsDBNull(1) ? null : reader.GetString(1), reader.GetBoolean(2));
            }
            finally
            {
                if (opened)
                    await connection.CloseAsync();
            }
        }
    }
}
