using System.Text.RegularExpressions;
using Microsoft.Data.SqlClient;

namespace kdyf.Authorization.Migrations.Test;

/// <summary>
/// A database of its own for one test, on LocalDB or the server in <c>KDYF_AUTHZ_TEST_SQLSERVER</c>, dropped at the end.
/// Without a server the test is inconclusive.
/// </summary>
internal sealed partial class TestDatabase : IAsyncDisposable
{
    private const string Variable = "KDYF_AUTHZ_TEST_SQLSERVER";
    private readonly string _server;

    private TestDatabase(string server, string name)
    {
        _server = server;
        Name = name;
        ConnectionString = new SqlConnectionStringBuilder(server) { InitialCatalog = name, Pooling = false }.ConnectionString;
    }

    public string Name { get; }

    public string ConnectionString { get; }

    public static async Task<TestDatabase> CreateAsync()
    {
        var server = Environment.GetEnvironmentVariable(Variable)
                     ?? @"Server=(localdb)\MSSQLLocalDB;Integrated Security=true;TrustServerCertificate=true;Connect Timeout=60";
        var name = "kdyf_authz_test_" + Guid.NewGuid().ToString("N")[..12];
        try
        {
            await using var connection = new SqlConnection(server);
            await connection.OpenAsync();
            await using var command = new SqlCommand($"CREATE DATABASE [{name}]", connection) { CommandTimeout = 120 };
            await command.ExecuteNonQueryAsync();
        }
        catch (SqlException ex)
        {
            Assert.Inconclusive($"No SQL Server for the integration tests ({ex.Message}). Start LocalDB or set {Variable}.");
        }
        return new TestDatabase(server, name);
    }

    /// <summary>Runs a script with <c>GO</c> separators, as sqlcmd would.</summary>
    public async Task ExecuteAsync(string script)
    {
        await using var connection = new SqlConnection(ConnectionString);
        await connection.OpenAsync();
        foreach (var batch in Go().Split(script).Where(b => !string.IsNullOrWhiteSpace(b)))
        {
            await using var command = new SqlCommand(batch, connection) { CommandTimeout = 120 };
            await command.ExecuteNonQueryAsync();
        }
    }

    public async Task<T?> ScalarAsync<T>(string sql)
    {
        await using var connection = new SqlConnection(ConnectionString);
        await connection.OpenAsync();
        await using var command = new SqlCommand(sql, connection);
        var value = await command.ExecuteScalarAsync();
        return value is null or DBNull ? default : (T)value;
    }

    public async ValueTask DisposeAsync()
    {
        SqlConnection.ClearAllPools();
        await using var connection = new SqlConnection(_server);
        await connection.OpenAsync();
        await using var command = new SqlCommand(
            $"IF DB_ID(N'{Name}') IS NOT NULL BEGIN ALTER DATABASE [{Name}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [{Name}]; END",
            connection) { CommandTimeout = 120 };
        await command.ExecuteNonQueryAsync();
    }

    [GeneratedRegex(@"^\s*GO\s*$", RegexOptions.Multiline | RegexOptions.IgnoreCase)]
    private static partial Regex Go();
}
