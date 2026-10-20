using kdyf.Authorization.Simulation;
using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using kdyf.Authorization.Abstractions;
using kdyf.Authorization.Administration;

namespace kdyf.Authorization.Endpoints.Test;

/// <summary>
/// A host with the library's endpoints mapped over fake services: routing, authentication, the doors and the
/// filters are real; what the services answer is the test's.
/// </summary>
internal sealed class TestHost : IAsyncDisposable
{
    public const string AdminHeader = "X-Test-Admin";
    public const string UserHeader = "X-Test-User";

    public Mock<IAccessAdminService> Access { get; } = new(MockBehavior.Strict);
    public Mock<IPatAdminService> Tokens { get; } = new(MockBehavior.Strict);
    public Mock<IDirectoryAdminService> Directory { get; } = new(MockBehavior.Strict);
    public Mock<IAuditAdminService> Audit { get; } = new(MockBehavior.Strict);
    public Mock<ISimulationAdminService> Simulation { get; } = new(MockBehavior.Strict);

    /// <summary>The policy simulation was switched on with: the door of the simulation endpoints.</summary>
    public const string SimulationPolicy = "UserSimulation";
    public Mock<IUserContext> UserContext { get; } = new();

    /// <summary>The actor every request gets: the services must receive exactly this one.</summary>
    public AdminActor Actor { get; } = new(new UserIdentity("11111111-1111-1111-1111-111111111111", "admin@test"), new HashSet<string>(StringComparer.Ordinal));

    private WebApplication? _app;

    public HttpClient Client { get; private set; } = null!;

    /// <summary>Every route the host exposes, as routing sees it.</summary>
    public IReadOnlyList<Microsoft.AspNetCore.Routing.RouteEndpoint> Endpoints =>
        _app!.Services.GetServices<Microsoft.AspNetCore.Routing.EndpointDataSource>()
            .SelectMany(source => source.Endpoints)
            .OfType<Microsoft.AspNetCore.Routing.RouteEndpoint>()
            .ToList();

    public static async Task<TestHost> StartAsync(Action<IServiceCollection>? services = null, Action<WebApplication>? map = null)
    {
        var host = new TestHost();
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();

        builder.Services.AddAuthentication("Test").AddScheme<AuthenticationSchemeOptions, HeaderAuthenticationHandler>("Test", _ => { });
        builder.Services.AddAuthorization(options =>
        {
            options.AddPolicy(AccessPolicyNames.Administration, policy => policy.RequireClaim("admin", "true"));
            options.AddPolicy(AccessPolicyNames.PersonalAccessTokens, policy => policy.RequireAuthenticatedUser());
            options.AddPolicy(SimulationPolicy, policy => policy.RequireClaim("admin", "true"));
            options.AddPolicy(kdyf.Authorization.AspNetCore.KdyfAuthorizationPolicies.SignedIn, policy => policy.RequireAuthenticatedUser());
        });

        builder.Services.AddSingleton(host.Access.Object);
        builder.Services.AddSingleton(host.Tokens.Object);
        builder.Services.AddSingleton(host.Directory.Object);
        builder.Services.AddSingleton(host.Audit.Object);
        builder.Services.AddSingleton(host.Simulation.Object);
        builder.Services.AddSingleton(new UserSimulationOptions { RequiredPermission = "global.UserSimulation", PolicyName = SimulationPolicy });
        builder.Services.AddSingleton(host.UserContext.Object);
        builder.Services.AddSingleton<IAdminActorAccessor>(new FixedActor(host.Actor));
        services?.Invoke(builder.Services);

        var app = builder.Build();
        app.UseAuthentication();
        app.UseAuthorization();
        if (map is null)
        {
            app.MapKdyfAuthorizationAdministration();
            app.MapKdyfAuthorizationSession();
            app.MapKdyfAuthorizationSimulation();
        }
        else
        {
            map(app);
        }

        await app.StartAsync();
        host._app = app;
        host.Client = app.GetTestClient();
        return host;
    }

    /// <summary>A request as an administrator (passes both doors).</summary>
    public HttpRequestMessage AsAdmin(HttpMethod method, string url, HttpContent? body = null)
    {
        var request = new HttpRequestMessage(method, url) { Content = body };
        request.Headers.Add(UserHeader, "admin@test");
        request.Headers.Add(AdminHeader, "true");
        return request;
    }

    /// <summary>A request as a signed-in person who is not an administrator.</summary>
    public HttpRequestMessage AsUser(HttpMethod method, string url)
    {
        var request = new HttpRequestMessage(method, url);
        request.Headers.Add(UserHeader, "user@test");
        return request;
    }

    public async ValueTask DisposeAsync()
    {
        Client.Dispose();
        if (_app is not null)
            await _app.DisposeAsync();
    }

    private sealed class FixedActor(AdminActor actor) : IAdminActorAccessor
    {
        public Task<AdminActor> GetAsync(CancellationToken cancellationToken = default) => Task.FromResult(actor);
    }

    /// <summary>Signs in whoever the test header names; no header, no session.</summary>
    private sealed class HeaderAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder)
        : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
    {
        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.TryGetValue(UserHeader, out var user))
                return Task.FromResult(AuthenticateResult.NoResult());

            var claims = new List<Claim> { new("name", user.ToString()) };
            if (Request.Headers.TryGetValue(AdminHeader, out var admin))
                claims.Add(new Claim("admin", admin.ToString()));

            var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, Scheme.Name));
            return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(principal, Scheme.Name)));
        }
    }
}
