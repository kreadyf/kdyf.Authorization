using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;

namespace kdyf.Authorization.EntityFrameworkCore
{
    /// <summary>
    /// Where the <c>auth.*</c> tables are: the connection string, by name, and the schema. Bound from the root of the
    /// library's section by <c>UseEntityFrameworkStore</c>.
    /// </summary>
    public sealed class AuthorizationStoreOptions
    {
        /// <summary>The default name under <c>ConnectionStrings</c>.</summary>
        public const string DefaultConnectionStringName = "Authorization";

        /// <summary>
        /// The name, under <c>ConnectionStrings</c>, of the database holding the <c>auth.*</c> tables. A host that keeps
        /// them in its own database names that connection string here.
        /// </summary>
        public string ConnectionStringName { get; set; } = DefaultConnectionStringName;

        /// <summary>
        /// The connection string, as read from <c>ConnectionStrings:{ConnectionStringName}</c>. SECRET.
        /// </summary>
        /// <remarks>
        /// Not bindable on purpose: the setter is not public, so a <c>ConnectionString</c> key inside the section is never
        /// read — the database has one place, the application's connection strings, and a stale copy cannot win.
        /// </remarks>
        public string? ConnectionString { get; internal set; }

        /// <summary>SQL schema of the tables.</summary>
        public string Schema { get; set; } = ModelBuilderExtensions.DefaultSchema;

        /// <summary>
        /// Refuse to start on a schema without a version (no <c>SchemaVersion</c> table), instead of only warning. Turn it
        /// on once every environment has been migrated or adopted (<c>kdyf-auth adopt</c>): a schema whose version is below
        /// the one the packages require stops the host either way.
        /// </summary>
        public bool RequireSchemaVersion { get; set; }
    }

    /// <summary>
    /// Validates <see cref="AuthorizationStoreOptions"/> when the host starts: without its database the host does not
    /// start, and the message names the key and where to set it.
    /// </summary>
    internal sealed partial class AuthorizationStoreOptionsValidator : IValidateOptions<AuthorizationStoreOptions>
    {
        private readonly string _section;

        public AuthorizationStoreOptionsValidator(string section) => _section = section;

        [GeneratedRegex("^[A-Za-z_][A-Za-z0-9_]*$")]
        private static partial Regex SqlIdentifier();

        public ValidateOptionsResult Validate(string? name, AuthorizationStoreOptions options)
        {
            var errors = new List<string>();

            if (string.IsNullOrWhiteSpace(options.ConnectionStringName))
                errors.Add($"{_section}:ConnectionStringName is empty. Leave it out to use '{AuthorizationStoreOptions.DefaultConnectionStringName}'.");
            else if (string.IsNullOrWhiteSpace(options.ConnectionString))
            {
                var key = options.ConnectionStringName;
                errors.Add($"ConnectionStrings:{key} is missing: the database of the auth.* tables. "
                           + $"Locally: dotnet user-secrets set \"ConnectionStrings:{key}\" \"<connection-string>\" --project <host project>. "
                           + $"Deployed: the ConnectionStrings__{key} environment variable, or a connection string named {key} in the App Service. "
                           + $"Another name: {_section}:ConnectionStringName.");
            }

            if (string.IsNullOrWhiteSpace(options.Schema) || !SqlIdentifier().IsMatch(options.Schema))
                errors.Add($"{_section}:Schema '{options.Schema}' is not a valid SQL schema name (letters, digits and '_', not starting with a digit).");

            return errors.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(errors);
        }
    }
}
