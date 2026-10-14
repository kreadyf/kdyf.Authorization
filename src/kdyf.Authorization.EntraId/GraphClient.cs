using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace kdyf.Authorization.EntraId
{
    /// <summary>Graph refused a call, or could not be reached. The message is fit for an administrator.</summary>
    public sealed class GraphException : Exception
    {
        public GraphException(string message, HttpStatusCode? statusCode = null, Exception? inner = null)
            : base(message, inner)
        {
            StatusCode = statusCode;
        }

        /// <summary>Graph's status, when it answered at all.</summary>
        public HttpStatusCode? StatusCode { get; }
    }

    /// <summary>A page of a Graph collection.</summary>
    public sealed class GraphPage<T>
    {
        public List<T>? Value { get; set; }

        [JsonPropertyName("@odata.nextLink")]
        public string? NextLink { get; set; }
    }

    /// <summary>
    /// The few Graph calls kdyf.Authorization needs, over one authenticated <see cref="HttpClient"/>: JSON in and
    /// out, Graph's error envelope turned into a <see cref="GraphException"/>.
    /// </summary>
    /// <remarks>
    /// Every caller builds URLs from ids it has checked to be GUIDs (see <see cref="IsObjectId"/>): an
    /// id is pasted into a path or a <c>$filter</c>, and a crafted one could otherwise reshape the query.
    /// </remarks>
    public sealed class GraphClient
    {
        public const string HttpClientName = "kdyf.Authorization.Graph";

        private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
        {
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        private readonly IHttpClientFactory _httpClientFactory;
        private readonly GraphTokenProvider _tokens;
        private readonly IOptions<EntraGraphOptions> _options;
        private readonly ILogger<GraphClient> _logger;

        public GraphClient(
            IHttpClientFactory httpClientFactory,
            GraphTokenProvider tokens,
            IOptions<EntraGraphOptions> options,
            ILogger<GraphClient> logger)
        {
            _httpClientFactory = httpClientFactory;
            _tokens = tokens;
            _options = options;
            _logger = logger;
        }

        /// <summary>Entra object ids are GUIDs; anything else is refused before it reaches a URL.</summary>
        public static bool IsObjectId(string? value) => Guid.TryParse(value, out _);

        /// <summary>GET that must succeed.</summary>
        public async Task<T> GetAsync<T>(string url, string action, CancellationToken ct, bool eventualConsistency = false)
        {
            using var response = await SendAsync(HttpMethod.Get, url, null, ct, eventualConsistency);
            await EnsureSuccessAsync(response, action, ct);
            return (await response.Content.ReadFromJsonAsync<T>(Json, ct))!;
        }

        /// <summary>GET where a 404 means "no such object" and answers null.</summary>
        public async Task<T?> GetOrNullAsync<T>(string url, string action, CancellationToken ct) where T : class
        {
            using var response = await SendAsync(HttpMethod.Get, url, null, ct);
            if (response.StatusCode == HttpStatusCode.NotFound)
                return null;

            await EnsureSuccessAsync(response, action, ct);
            return await response.Content.ReadFromJsonAsync<T>(Json, ct);
        }

        /// <summary>Every item of a collection, following nextLink up to <paramref name="maxPages"/> pages.</summary>
        public async Task<List<T>> GetAllAsync<T>(string url, string action, CancellationToken ct, int maxPages = 20, bool eventualConsistency = false)
        {
            var items = new List<T>();
            string? next = url;

            for (var page = 0; page < maxPages && next is not null; page++)
            {
                var body = await GetAsync<GraphPage<T>>(next, action, ct, eventualConsistency);
                if (body.Value is not null)
                    items.AddRange(body.Value);
                next = body.NextLink;
            }

            if (next is not null)
                _logger.LogWarning("Graph: {Action} returned more than {MaxPages} pages; the list is truncated.", action, maxPages);

            return items;
        }

        /// <summary>POST with a JSON body; returns Graph's response and leaves the status to the caller.</summary>
        public Task<HttpResponseMessage> PostAsync(string url, object body, CancellationToken ct) =>
            SendAsync(HttpMethod.Post, url, body, ct);

        /// <summary>DELETE; returns Graph's response and leaves the status to the caller.</summary>
        public Task<HttpResponseMessage> DeleteAsync(string url, CancellationToken ct) =>
            SendAsync(HttpMethod.Delete, url, null, ct);

        /// <summary>
        /// Whether the user is a member of the group, directly or through nested groups
        /// (<c>checkMemberGroups</c>). False when Graph no longer knows the user.
        /// </summary>
        public async Task<bool> IsMemberOfAsync(string objectId, string groupId, CancellationToken ct)
        {
            if (!IsObjectId(objectId) || !IsObjectId(groupId))
                return false;

            using var response = await PostAsync($"users/{objectId}/checkMemberGroups", new { groupIds = new[] { groupId } }, ct);
            if (response.StatusCode == HttpStatusCode.NotFound)
                return false;

            await EnsureSuccessAsync(response, "checking the user's group membership", ct);
            var body = await ReadAsync<GraphPage<string>>(response, ct);
            return body.Value?.Any(id => string.Equals(id, groupId, StringComparison.OrdinalIgnoreCase)) == true;
        }

        /// <summary>Reads a JSON response body.</summary>
        public static async Task<T> ReadAsync<T>(HttpResponseMessage response, CancellationToken ct) =>
            (await response.Content.ReadFromJsonAsync<T>(Json, ct))!;

        /// <summary>Throws a <see cref="GraphException"/> naming the action unless the response succeeded.</summary>
        public async Task EnsureSuccessAsync(HttpResponseMessage response, string action, CancellationToken ct)
        {
            if (response.IsSuccessStatusCode)
                return;

            var error = await ReadErrorAsync(response, ct);
            _logger.LogError("Graph rejected {Action}: {Status} {Error}", action, (int)response.StatusCode, error);
            throw new GraphException($"The directory rejected {action}: {error}", response.StatusCode);
        }

        /// <summary>The message inside Graph's error envelope, or the raw body when it does not follow it.</summary>
        public static async Task<string> ReadErrorAsync(HttpResponseMessage response, CancellationToken ct)
        {
            var raw = await response.Content.ReadAsStringAsync(ct);

            try
            {
                var envelope = JsonSerializer.Deserialize<GraphErrorEnvelope>(raw, Json);
                if (!string.IsNullOrWhiteSpace(envelope?.Error?.Message))
                    return envelope!.Error!.Message!;
            }
            catch (JsonException)
            {
                // Not every failure is JSON (a proxy, a 502): the raw body is used.
            }

            return string.IsNullOrWhiteSpace(raw) ? $"HTTP {(int)response.StatusCode}" : raw;
        }

        private async Task<HttpResponseMessage> SendAsync(
            HttpMethod method, string url, object? body, CancellationToken ct, bool eventualConsistency = false)
        {
            var options = _options.Value;
            if (!options.IsConfigured)
                throw new GraphException("Microsoft Graph is not configured: tenant, client id, client secret and what the gate reads (the access group id, "
                                         + "or the Enterprise application and its Access app role) are needed.");

            var token = await _tokens.GetAccessTokenAsync(ct);

            var client = _httpClientFactory.CreateClient(HttpClientName);
            client.BaseAddress ??= new Uri(options.GraphBaseUrl);

            using var request = new HttpRequestMessage(method, url);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

            // $search and advanced $filter (otherMails/any, $count) need this header.
            if (eventualConsistency)
                request.Headers.Add("ConsistencyLevel", "eventual");

            if (body is not null)
                request.Content = JsonContent.Create(body, body.GetType(), options: Json);

            var started = System.Diagnostics.Stopwatch.GetTimestamp();
            try
            {
                var response = await client.SendAsync(request, ct);
                LogDuration(method, url, (int)response.StatusCode, System.Diagnostics.Stopwatch.GetElapsedTime(started));
                return response;
            }
            catch (HttpRequestException ex)
            {
                throw new GraphException("Microsoft Graph could not be reached.", null, ex);
            }
        }

        /// <summary>
        /// How long each Graph call took: a warning from one second, so a slow directory shows in the logs of any
        /// environment; debug otherwise. Only the path — the query can carry an e-mail address.
        /// </summary>
        private void LogDuration(HttpMethod method, string url, int status, TimeSpan elapsed)
        {
            var path = url.Split('?', 2)[0];
            if (elapsed >= SlowCall)
                _logger.LogWarning("Graph {Method} {Path} answered {Status} in {ElapsedMs} ms.", method, path, status, (long)elapsed.TotalMilliseconds);
            else
                _logger.LogDebug("Graph {Method} {Path} answered {Status} in {ElapsedMs} ms.", method, path, status, (long)elapsed.TotalMilliseconds);
        }

        private static readonly TimeSpan SlowCall = TimeSpan.FromSeconds(1);

        private sealed class GraphErrorEnvelope
        {
            public GraphError? Error { get; set; }

            internal sealed class GraphError
            {
                public string? Code { get; set; }
                public string? Message { get; set; }
            }
        }
    }
}
