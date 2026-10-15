using kdyf.Authorization.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace kdyf.Authorization.Migrations.Schema
{
    public static class SchemaCommandHostExtensions
    {
        /// <summary>The environment variable with the connection string of the migration, when it is not the host's.</summary>
        public const string ConnectionStringVariable = "KDYF_AUTH_CONNECTION_STRING";

        /// <summary>
        /// Runs a <c>kdyf-auth</c> command with the host's own composition (its connection string and schema) when the
        /// first argument is <c>kdyf-auth</c>, sets the exit code and returns <c>true</c>; otherwise returns <c>false</c>
        /// and the host runs as usual. Call it after <c>Build()</c> and before <c>Run()</c>:
        /// <code>
        /// var app = builder.Build();
        /// if (await app.RunKdyfAuthCommandAsync(args)) return;
        /// </code>
        /// </summary>
        /// <remarks>
        /// The host is not started: no hosted service runs, no request is served. The migration needs DDL, which the
        /// application's user should not have: put the connection string of an identity that has it in
        /// <c>KDYF_AUTH_CONNECTION_STRING</c> (an environment variable, not an argument, so it is not in the process list).
        /// </remarks>
        public static async Task<bool> RunKdyfAuthCommandAsync(this IHost host, string[] args, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(host);
            ArgumentNullException.ThrowIfNull(args);
            if (args.Length == 0 || !string.Equals(args[0], SchemaCommandLine.Verb, StringComparison.OrdinalIgnoreCase))
                return false;

            var store = host.Services.GetRequiredService<IOptions<AuthorizationStoreOptions>>().Value;
            var connectionString = Environment.GetEnvironmentVariable(ConnectionStringVariable) ?? store.ConnectionString;
            if (string.IsNullOrWhiteSpace(connectionString))
            {
                await Console.Error.WriteLineAsync($"No connection string: set {ConnectionStringVariable}, or the host's ConnectionStrings:{store.ConnectionStringName}.");
                Environment.ExitCode = SchemaCommandLine.Usage;
                return true;
            }

            Environment.ExitCode = await SchemaCommandLine.RunAsync(args.Skip(1).ToList(), connectionString, store.Schema, Console.Out, host.Services, cancellationToken);
            return true;
        }
    }
}
