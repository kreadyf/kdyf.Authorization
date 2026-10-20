using System.Data.Common;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace kdyf.Authorization.Migrations.Legacy
{
    /// <summary>
    /// The approved exceptions to the invariant, in <c>MigrationException</c> of the target schema: imported from a JSON file
    /// that a person reviewed, as a whole (the file replaces the previous set), each row with who approved it and the SHA-256
    /// of the file it came from.
    /// </summary>
    /// <remarks>
    /// <code>
    /// { "exceptions": [
    ///   { "kind": "member-base-access", "reason": "Members of the new gate get the base access (finding 9)" },
    ///   { "kind": "gain", "objectId": "…", "code": "Orders.Read", "reason": "…" },
    ///   { "kind": "token-count", "value": -2, "reason": "Tokens of people outside the group stop working" } ] }
    /// </code>
    /// </remarks>
    internal static class InvariantExceptions
    {
        public const string Table = "MigrationException";

        internal static string BootstrapSql(string schema) => $"""

            IF OBJECT_ID(N'[{schema}].[{Table}]') IS NULL
            CREATE TABLE [{schema}].[{Table}] (
                ExceptionId  INT IDENTITY(1,1) NOT NULL CONSTRAINT PK_{Table} PRIMARY KEY,
                Kind         VARCHAR(30)    NOT NULL,
                ObjectId     VARCHAR(50)    NULL,
                Code         VARCHAR(50)    NULL,
                Value        INT            NULL,
                Reason       NVARCHAR(1000) NOT NULL,
                ApprovedBy   NVARCHAR(128)  NOT NULL,
                ApprovedAt   DATETIME2      NOT NULL,
                FileChecksum CHAR(64)       NOT NULL
            );
            """;

        /// <summary>Reads the file; throws with every problem when an entry is unknown or incomplete.</summary>
        public static IReadOnlyList<InvariantException> Parse(string json, string approver)
        {
            using var document = JsonDocument.Parse(json);
            if (!document.RootElement.TryGetProperty("exceptions", out var list) || list.ValueKind != JsonValueKind.Array)
                throw new FormatException("The file needs an 'exceptions' array.");

            var problems = new List<string>();
            var result = new List<InvariantException>();
            var index = 0;
            foreach (var entry in list.EnumerateArray())
            {
                index++;
                string? Text(string name) => entry.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
                int? Number(string name) => entry.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Number ? value.GetInt32() : null;

                var kind = Text("kind");
                var reason = Text("reason");
                var objectId = Text("objectId");
                var code = Text("code");
                var value = Number("value");

                if (kind is null || !InvariantKinds.All.Contains(kind))
                    problems.Add($"#{index}: kind '{kind}' is not one of {string.Join(", ", InvariantKinds.All)}.");
                if (string.IsNullOrWhiteSpace(reason))
                    problems.Add($"#{index}: every exception needs a reason.");
                if (objectId is not null && !Guid.TryParse(objectId, out _))
                    problems.Add($"#{index}: '{objectId}' is not an object id.");
                if (kind is InvariantKinds.Gain or InvariantKinds.Exact && (objectId is null || code is null))
                    problems.Add($"#{index}: a {kind} exception names the person (objectId) and the code.");
                if (kind is InvariantKinds.TokenCount or InvariantKinds.MinAdministrators && value is null)
                    problems.Add($"#{index}: a {kind} exception gives the value.");

                result.Add(new InvariantException(kind ?? "", objectId is null ? null : Guid.Parse(objectId).ToString(), code, value, reason ?? "", approver));
            }

            if (problems.Count > 0)
                throw new FormatException("The exceptions file is not valid: " + string.Join(" ", problems));
            return result;
        }

        public static string Checksum(string json) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(json))).ToLowerInvariant();

        internal static async Task ReplaceAsync(DbConnection connection, string schema, IReadOnlyList<InvariantException> exceptions, string checksum, CancellationToken cancellationToken)
        {
            await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
            await using (var delete = connection.CreateCommand())
            {
                delete.Transaction = transaction;
                delete.CommandText = $"DELETE FROM [{schema}].[{Table}]";
                await delete.ExecuteNonQueryAsync(cancellationToken);
            }
            foreach (var e in exceptions)
            {
                await using var insert = connection.CreateCommand();
                insert.Transaction = transaction;
                insert.CommandText = $"INSERT INTO [{schema}].[{Table}] (Kind, ObjectId, Code, Value, Reason, ApprovedBy, ApprovedAt, FileChecksum) VALUES (@k, @o, @c, @v, @r, @a, SYSUTCDATETIME(), @f)";
                foreach (var (name, value) in new (string, object?)[] { ("@k", e.Kind), ("@o", e.ObjectId), ("@c", e.Code), ("@v", e.Value), ("@r", e.Reason), ("@a", e.ApprovedBy), ("@f", checksum) })
                {
                    var parameter = insert.CreateParameter();
                    parameter.ParameterName = name;
                    parameter.Value = value ?? DBNull.Value;
                    insert.Parameters.Add(parameter);
                }
                await insert.ExecuteNonQueryAsync(cancellationToken);
            }
            await transaction.CommitAsync(cancellationToken);
        }

        internal static async Task<IReadOnlyList<InvariantException>> LoadAsync(DbConnection connection, string schema, CancellationToken cancellationToken)
        {
            await using var command = connection.CreateCommand();
            command.CommandText = $"IF OBJECT_ID(N'[{schema}].[{Table}]') IS NOT NULL SELECT Kind, ObjectId, Code, Value, Reason, ApprovedBy FROM [{schema}].[{Table}]";
            var list = new List<InvariantException>();
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
                list.Add(new InvariantException(reader.GetString(0), reader.IsDBNull(1) ? null : reader.GetString(1), reader.IsDBNull(2) ? null : reader.GetString(2),
                    reader.IsDBNull(3) ? null : reader.GetInt32(3), reader.GetString(4), reader.GetString(5)));
            return list;
        }
    }
}
