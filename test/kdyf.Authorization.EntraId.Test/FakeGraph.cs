using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Azure.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using kdyf.Authorization.EntraId;

namespace kdyf.Authorization.EntraId.Test;

/// <summary>
/// Microsoft Graph in memory, as far as the gate goes: people with an enabled flag, the access group, and the
/// assignments of app roles on service principals — answering the URLs the library sends, and recording them.
/// </summary>
internal sealed class FakeGraph : HttpMessageHandler
{
    public const string ServicePrincipal = "66666666-6666-6666-6666-666666666666";
    public const string AccessRole = "77777777-7777-7777-7777-777777777777";
    public const string OtherRole = "88888888-8888-8888-8888-888888888888";
    public const string OtherApplication = "99999999-9999-9999-9999-999999999999";
    public const string Group = "55555555-5555-5555-5555-555555555555";

    private int _nextAssignment;

    /// <summary>People by object id: enabled or not.</summary>
    public Dictionary<string, bool> People { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>The direct members of <see cref="Group"/>.</summary>
    public HashSet<string> Members { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Every assignment in the tenant: id, principal, principal type, resource and role.</summary>
    public List<(string Id, string Principal, string Type, string Resource, string Role)> Assignments { get; } = [];

    /// <summary>Addresses: object id → the e-mail and UPN a $filter by e-mail matches.</summary>
    public Dictionary<string, string> Emails { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Every request, as "METHOD path?query".</summary>
    public List<string> Requests { get; } = [];

    /// <summary>When set, every assignment call answers 500.</summary>
    public bool AssignmentsDown { get; set; }

    public FakeGraph Person(string objectId, bool enabled = true, bool member = false)
    {
        People[objectId] = enabled;
        if (member)
            Members.Add(objectId);
        return this;
    }

    public FakeGraph Assign(string principal, string role = AccessRole, string resource = ServicePrincipal, string type = "User")
    {
        Assignments.Add(($"a{++_nextAssignment}", principal, type, resource, role));
        return this;
    }

    public bool IsAssigned(string principal) =>
        Assignments.Any(a => a.Principal == principal && a.Role == AccessRole && a.Resource == ServicePrincipal);

    /// <summary>The library's Graph plumbing over this fake, with the gate's configuration.</summary>
    public ServiceProvider Services(AccessGate gate = AccessGate.Group, Action<IServiceCollection>? more = null)
    {
        var services = new ServiceCollection().AddLogging();
        services.AddEntraGroupMembership();
        services.Configure<EntraGraphOptions>(o =>
        {
            o.TenantId = "11111111-1111-1111-1111-111111111111";
            o.ClientId = "22222222-2222-2222-2222-222222222222";
            o.ClientSecret = "secret";
            o.GroupId = Group;
            o.Gate = gate;
            o.ServicePrincipalId = ServicePrincipal;
            o.AccessAppRoleId = AccessRole;
        });
        services.AddSingleton(new GraphTokenProvider(new StaticCredential()));
        services.AddSingleton<IHttpClientFactory>(new Factory(this));
        more?.Invoke(services);
        return services.BuildServiceProvider();
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var path = request.RequestUri!.AbsolutePath.Replace("/v1.0/", "");
        var query = Uri.UnescapeDataString(request.RequestUri.Query);
        Requests.Add($"{request.Method} {path}{query}");
        var body = request.Content is null ? null : JsonNode.Parse(await request.Content.ReadAsStringAsync(cancellationToken));
        var segments = path.Trim('/').Split('/');

        // users/{id}?$select=id,accountEnabled
        if (request.Method == HttpMethod.Get && segments is ["users", var user] )
            return People.TryGetValue(user, out var enabled)
                ? Json(new { id = user, accountEnabled = enabled })
                : Status(HttpStatusCode.NotFound);

        // users?$filter=mail eq '…' or … userPrincipalName eq '…': what arrived of the query is all Graph sees. A '#' sent
        // unencoded never arrives (it starts the fragment), and a '+' arrives as a space: then nothing matches.
        if (request.Method == HttpMethod.Get && segments is ["users"] && query.Contains("$filter=", StringComparison.Ordinal))
        {
            // As a server reads it: '+' in a query string is a space.
            var received = Uri.UnescapeDataString(request.RequestUri.Query.Replace('+', ' '));
            var wanted = Literals(received).ToHashSet(StringComparer.OrdinalIgnoreCase);
            return Json(new { value = Emails.Where(e => wanted.Contains(e.Value)).Select(e => new { id = e.Key, mail = e.Value, userPrincipalName = e.Value, displayName = e.Value }) });
        }

        // users/{id}/checkMemberGroups
        if (request.Method == HttpMethod.Post && segments is ["users", var member, "checkMemberGroups"])
            return People.ContainsKey(member)
                ? Json(new { value = Members.Contains(member) ? new[] { Group } : Array.Empty<string>() })
                : Status(HttpStatusCode.NotFound);

        // groups/{group}/transitiveMembers/microsoft.graph.user
        if (request.Method == HttpMethod.Get && segments is ["groups", Group, "transitiveMembers", "microsoft.graph.user"])
            return Json(new { value = Members.Select(id => new { id, accountEnabled = People.GetValueOrDefault(id, true), mail = $"{id[..4]}@test" }) });

        // groups/{group}/members/$ref (add) and groups/{group}/members/{id}/$ref (remove)
        if (request.Method == HttpMethod.Post && segments is ["groups", Group, "members", "$ref"])
        {
            var added = body!["@odata.id"]!.GetValue<string>().Split('/')[^1];
            return Members.Add(added) ? Status(HttpStatusCode.NoContent) : Status(HttpStatusCode.BadRequest, "One or more added object references already exist");
        }

        if (request.Method == HttpMethod.Delete && segments is ["groups", Group, "members", var removed, "$ref"])
            return Members.Remove(removed) ? Status(HttpStatusCode.NoContent) : Status(HttpStatusCode.NotFound);

        if (segments.Contains("appRoleAssignments") || segments.Contains("appRoleAssignedTo"))
        {
            if (AssignmentsDown)
                return Status(HttpStatusCode.InternalServerError, "down");

            // users/{id}/appRoleAssignments: every assignment of the user, on any application.
            if (request.Method == HttpMethod.Get && segments is ["users", var holder, "appRoleAssignments"])
                return People.ContainsKey(holder)
                    ? Json(new { value = Assignments.Where(a => a.Principal == holder).Select(Shape) })
                    : Status(HttpStatusCode.NotFound);

            // servicePrincipals/{sp}/appRoleAssignedTo: every assignment on the application.
            if (request.Method == HttpMethod.Get && segments is ["servicePrincipals", var resource, "appRoleAssignedTo"])
                return Json(new { value = Assignments.Where(a => a.Resource == resource).Select(Shape) });

            if (request.Method == HttpMethod.Post && segments is ["servicePrincipals", var on, "appRoleAssignedTo"])
            {
                var principal = body!["principalId"]!.GetValue<string>();
                var role = body["appRoleId"]!.GetValue<string>();
                var target = body["resourceId"]!.GetValue<string>();
                if (Assignments.Any(a => a.Principal == principal && a.Role == role && a.Resource == target))
                    return Status(HttpStatusCode.BadRequest, "Permission being assigned already exists on the object");
                Assign(principal, role, target);
                return Json(new { id = Assignments[^1].Id }, HttpStatusCode.Created);
            }

            if (request.Method == HttpMethod.Delete && segments is ["servicePrincipals", var from, "appRoleAssignedTo", var id])
                return Assignments.RemoveAll(a => a.Id == id && a.Resource == from) > 0 ? Status(HttpStatusCode.NoContent) : Status(HttpStatusCode.NotFound);
        }

        return Status(HttpStatusCode.NotImplemented, $"FakeGraph does not answer {request.Method} {path}");
    }

    private static object Shape((string Id, string Principal, string Type, string Resource, string Role) a) =>
        new { id = a.Id, principalId = a.Principal, principalType = a.Type, resourceId = a.Resource, appRoleId = a.Role };

    /// <summary>The string literals of an OData filter: between single quotes, a doubled quote being one quote.</summary>
    private static IEnumerable<string> Literals(string filter)
    {
        var literal = new StringBuilder();
        var inside = false;
        for (var i = 0; i < filter.Length; i++)
        {
            if (filter[i] != '\'')
            {
                if (inside)
                    literal.Append(filter[i]);
                continue;
            }
            if (inside && i + 1 < filter.Length && filter[i + 1] == '\'')
            {
                literal.Append('\'');
                i++;
                continue;
            }
            if (inside)
            {
                yield return literal.ToString();
                literal.Clear();
            }
            inside = !inside;
        }
    }

    private static HttpResponseMessage Json(object value, HttpStatusCode status = HttpStatusCode.OK) =>
        new(status) { Content = new StringContent(JsonSerializer.Serialize(value), Encoding.UTF8, "application/json") };

    private static HttpResponseMessage Status(HttpStatusCode status, string? message = null) =>
        message is null
            ? new(status)
            : Json(new { error = new { code = "x", message } }, status);

    private sealed class Factory(FakeGraph graph) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(graph, disposeHandler: false);
    }

    private sealed class StaticCredential : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            new("token", DateTimeOffset.UtcNow.AddHours(1));

        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            new(GetToken(requestContext, cancellationToken));
    }
}

/// <summary>Log lines, kept to be read.</summary>
internal sealed class ListLogger<T> : ILogger<T>
{
    public List<(LogLevel Level, string Message)> Lines { get; } = [];

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
        Lines.Add((logLevel, formatter(state, exception)));
}
