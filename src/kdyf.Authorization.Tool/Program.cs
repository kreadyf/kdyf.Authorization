using kdyf.Authorization.Migrations.Schema;

// kdyf-auth <command> [options] --connection-string <cs>, or the connection string in KDYF_AUTH_CONNECTION_STRING
// (preferred: an argument is visible in the process list).
var rest = new List<string>();
string? connectionString = Environment.GetEnvironmentVariable(SchemaCommandHostExtensions.ConnectionStringVariable);
for (var i = 0; i < args.Length; i++)
{
    if (args[i] == "--connection-string" && i + 1 < args.Length)
        connectionString = args[++i];
    else
        rest.Add(args[i]);
}

if (rest.Count > 0 && rest[0] is not ("-h" or "--help" or "help") && string.IsNullOrWhiteSpace(connectionString))
{
    Console.Error.WriteLine($"No connection string: set {SchemaCommandHostExtensions.ConnectionStringVariable}, or pass --connection-string.");
    return SchemaCommandLine.Usage;
}

using var cancel = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cancel.Cancel(); };
return await SchemaCommandLine.RunAsync(rest, connectionString ?? "", "auth", Console.Out, cancel.Token);
