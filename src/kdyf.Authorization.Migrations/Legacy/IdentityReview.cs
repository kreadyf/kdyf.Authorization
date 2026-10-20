using System.Globalization;
using System.Text;
using kdyf.Authorization.Abstractions;

namespace kdyf.Authorization.Migrations.Legacy
{
    /// <summary>A person's decision about one legacy user, read from the review file.</summary>
    /// <param name="LegacyUserId">The legacy user decided on.</param>
    /// <param name="ObjectId">The object id to use instead of the resolved one (an ambiguous or not found user). Optional.</param>
    /// <param name="Approve">Yes, no, or (null) leave as it is.</param>
    internal sealed record ReviewDecision(int LegacyUserId, string? ObjectId, bool? Approve);

    /// <summary>
    /// The human review of the identities: a CSV a person reads, decides on (<c>Approved</c> yes/no, an <c>ObjectId</c>
    /// for the users the directory could not resolve) and hands back. It holds e-mails: never commit it.
    /// </summary>
    internal static class IdentityReview
    {
        private static readonly string[] Columns =
        {
            "LegacyUserId", "Email", "LegacyObjectId", "ObjectId", "Method", "Matches", "UserType", "AccountEnabled", "Status",
            "PassedLegacyGate", "PassesNewGate", "Importable", "Approved", "ApprovedBy",
        };

        public static string ToCsv(IEnumerable<ResolvedIdentity> identities)
        {
            var csv = new StringBuilder();
            csv.AppendLine(string.Join(",", Columns));
            foreach (var i in identities.OrderBy(i => i.LegacyUserId))
                csv.AppendLine(string.Join(",", new object?[]
                {
                    i.LegacyUserId, i.Email, i.LegacyObjectId, i.ObjectId, i.Method, i.Matches, i.UserType, i.AccountEnabled, i.Status,
                    i.PassedLegacyGate, i.PassesNewGate, i.Importable, i.Approved ? "yes" : "", i.ApprovedBy,
                }.Select(Field)));
            return csv.ToString();
        }

        /// <summary>The decisions in a review file: by its header, so columns may be reordered or removed.</summary>
        public static IReadOnlyList<ReviewDecision> ReadDecisions(string csv)
        {
            var lines = Parse(csv).ToList();
            if (lines.Count == 0)
                return Array.Empty<ReviewDecision>();
            var header = lines[0].Select((name, index) => (name, index)).ToDictionary(c => c.name.Trim(), c => c.index, StringComparer.OrdinalIgnoreCase);
            if (!header.TryGetValue("LegacyUserId", out var idColumn))
                throw new FormatException("The review file has no LegacyUserId column.");

            string? Cell(IReadOnlyList<string> row, string column) =>
                header.TryGetValue(column, out var index) && index < row.Count && !string.IsNullOrWhiteSpace(row[index]) ? row[index].Trim() : null;

            var decisions = new List<ReviewDecision>();
            foreach (var row in lines.Skip(1).Where(r => r.Any(c => !string.IsNullOrWhiteSpace(c))))
            {
                var rawId = idColumn < row.Count ? row[idColumn] : "";
                if (!int.TryParse(rawId, NumberStyles.Integer, CultureInfo.InvariantCulture, out var id))
                    throw new FormatException($"'{rawId}' is not a legacy user id (a row shorter than the header?).");
                var approved = Cell(row, "Approved")?.ToLowerInvariant();
                decisions.Add(new ReviewDecision(id, Cell(row, "ObjectId"), approved switch
                {
                    null => (bool?)null,
                    "yes" or "y" or "true" or "1" or "si" or "sí" => true,
                    "no" or "n" or "false" or "0" => false,
                    _ => throw new FormatException($"User {id}: Approved is '{approved}', expected yes or no."),
                }));
            }
            return decisions;
        }

        /// <summary>
        /// Applies the decisions to the identities. An object id given by hand is checked in the directory and its gate
        /// read again; an approval is recorded with <paramref name="approver"/> and the time. Returns the identities and
        /// the problems; with any problem nothing should be saved.
        /// </summary>
        public static async Task<(IReadOnlyList<ResolvedIdentity> Identities, IReadOnlyList<string> Problems)> ApplyAsync(
            IReadOnlyList<ResolvedIdentity> identities, IReadOnlyList<ReviewDecision> decisions, string approver,
            ILegacyDirectory directory, IMembershipSource newGate, DateTime now, CancellationToken cancellationToken = default)
        {
            var problems = new List<string>();
            var byId = identities.ToDictionary(i => i.LegacyUserId);

            foreach (var decision in decisions)
            {
                if (!byId.TryGetValue(decision.LegacyUserId, out var identity))
                {
                    problems.Add($"User {decision.LegacyUserId} is not among the resolved identities.");
                    continue;
                }

                if (decision.Approve is false)
                {
                    byId[identity.LegacyUserId] = identity with { ApprovedBy = null, ApprovedAt = null };
                    continue;
                }
                if (decision.Approve is null)
                    continue;

                var given = decision.ObjectId is null ? (Guid?)null : Guid.TryParse(decision.ObjectId, out var g) ? g : null;
                if (decision.ObjectId is not null && given is null)
                {
                    problems.Add($"User {identity.LegacyUserId}: '{decision.ObjectId}' is not an object id.");
                    continue;
                }

                if (given is { } objectId && objectId.ToString() != identity.ObjectId)
                {
                    var person = await directory.GetAsync(objectId.ToString(), cancellationToken);
                    if (person is null)
                    {
                        problems.Add($"User {identity.LegacyUserId}: the directory has nobody with object id {objectId}.");
                        continue;
                    }
                    byId[identity.LegacyUserId] = identity with
                    {
                        ObjectId = objectId.ToString(), Method = "manual", Matches = 1, UserType = person.UserType,
                        AccountEnabled = person.AccountEnabled, Status = IdentityStatus.Manual,
                        PassesNewGate = (await newGate.GetMembershipAsync(objectId.ToString(), cancellationToken))?.HasAccess ?? false,
                        ApprovedBy = approver, ApprovedAt = now,
                    };
                    continue;
                }

                if (identity.Status is IdentityStatus.Ambiguous or IdentityStatus.NotFound)
                    problems.Add($"User {identity.LegacyUserId} is {identity.Status}: give the ObjectId to approve.");
                else if (identity.Status != IdentityStatus.Ok)
                    byId[identity.LegacyUserId] = identity with { ApprovedBy = approver, ApprovedAt = now };
            }

            return (byId.Values.OrderBy(i => i.LegacyUserId).ToList(), problems);
        }

        private static string Field(object? value)
        {
            var text = value switch
            {
                null => "",
                bool b => b ? "true" : "false",
                IFormattable f => f.ToString(null, CultureInfo.InvariantCulture),
                _ => value.ToString() ?? "",
            };
            // A leading =, +, - or @ (or a tab or carriage return before one) would be a formula in a spreadsheet: quoted
            // with an apostrophe it stays text.
            if (text.Length > 0 && text[0] is '=' or '+' or '-' or '@' or '\t' or '\r')
                text = "'" + text;
            return text.IndexOfAny(new[] { ',', '"', '\n', '\r' }) >= 0 ? "\"" + text.Replace("\"", "\"\"") + "\"" : text;
        }

        private static IEnumerable<List<string>> Parse(string csv)
        {
            var row = new List<string>();
            var field = new StringBuilder();
            var quoted = false;
            for (var i = 0; i < csv.Length; i++)
            {
                var c = csv[i];
                if (quoted)
                {
                    if (c == '"' && i + 1 < csv.Length && csv[i + 1] == '"') { field.Append('"'); i++; }
                    else if (c == '"') quoted = false;
                    else field.Append(c);
                }
                else if (c == '"') quoted = true;
                else if (c == ',') { row.Add(Unformula(field.ToString())); field.Clear(); }
                else if (c == '\n')
                {
                    row.Add(Unformula(field.ToString().TrimEnd('\r'))); field.Clear();
                    yield return row;
                    row = new List<string>();
                }
                else field.Append(c);
            }
            if (field.Length > 0 || row.Count > 0)
            {
                row.Add(Unformula(field.ToString()));
                yield return row;
            }
        }

        private static string Unformula(string value) => value.Length > 1 && value[0] == '\'' && value[1] is '=' or '+' or '-' or '@' ? value[1..] : value;
    }
}
