using kdyf.Authorization.Migrations.Schema;
using Microsoft.Data.SqlClient;

namespace kdyf.Authorization.Migrations.Legacy
{
    /// <summary>Reads a legacy schema and reports on it. Read-only: safe against any database, production included.</summary>
    internal static class LegacyInspector
    {
        public static async Task<(LegacyShape Shape, LegacyReport? Report)> InspectAsync(
            string connectionString, string legacySchema, IReadOnlyDictionary<int, string>? overrides = null, CancellationToken cancellationToken = default)
        {
            await using var connection = new SqlConnection(connectionString);
            await connection.OpenAsync(cancellationToken);

            // The schema's own spelling (Auth or auth): the catalog is compared ignoring case, the queries use it as stored.
            await using (var command = connection.CreateCommand())
            {
                command.CommandText = "SELECT name FROM sys.schemas WHERE name = @schema";
                command.Parameters.AddWithValue("@schema", legacySchema);
                legacySchema = await command.ExecuteScalarAsync(cancellationToken) as string
                               ?? throw new InvalidOperationException($"There is no schema '{legacySchema}'.");
            }

            var snapshot = await SchemaSnapshot.ReadAsync(connection, null, legacySchema, "-", cancellationToken);
            var shape = LegacyShapes.Classify(snapshot);
            if (!shape.Supported)
                return (shape, null);

            var data = await LegacyData.ReadAsync(connection, snapshot, cancellationToken);
            return (shape, LegacyReport.Build(data, overrides));
        }
    }
}
