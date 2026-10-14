using System.Security.Claims;
using System.Text.Encodings.Web;
using kdyf.Authorization.Abstractions;
using kdyf.Authorization.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace kdyf.Authorization.Test;

/// <summary>
/// How a Personal Access Token comes to be a principal.
/// </summary>
/// <remarks>
/// <para>
/// The link between the store and authorization. What decides whether a token opens doors is not
/// what the store returns, but how it is turned into claims here: the permissions travel as ROLE
/// CLAIMS and the authorization handler checks them with <c>IsInRole</c>. If the claim type did not
/// match, the token would authenticate cleanly and be denied everywhere.
/// </para>
/// <para>
/// The other half is when it does NOT claim the request. A missing, foreign or invalid token returns
/// <c>NoResult</c> and not <c>Fail</c>: with two schemes mounted —Bearer and PAT—, failing would block
/// requests that carry a perfectly valid Bearer. A STORE failure, however, is
/// <c>Fail</c>, because there it is unknown whether the token was valid.
/// </para>
/// </remarks>
[TestClass]
public class PatAuthenticationHandlerTests
{
    private const string Good = "a-good-token";

    // =====================================================================
    // When it does not claim the request
    // =====================================================================

    [TestMethod]
    public async Task Without_an_authorization_header_it_claims_nothing()
    {
        var result = await Authenticate(header: null);

        Assert.IsTrue(result.None, "without a header it is none of its business");
    }

    [TestMethod]
    public async Task Another_schemes_header_is_left_alone()
    {
        var result = await Authenticate("Bearer eyJhbGciOi...");

        Assert.IsTrue(result.None, "a valid Bearer cannot fail because of the PAT scheme");
    }

    [TestMethod]
    public async Task An_empty_token_claims_nothing()
    {
        Assert.IsTrue((await Authenticate("PAT ")).None);
        Assert.IsTrue((await Authenticate("PAT    ")).None);
    }

    [TestMethod]
    public async Task An_unknown_token_claims_nothing_instead_of_failing()
    {
        var result = await Authenticate("PAT does-not-exist");

        Assert.IsTrue(result.None);
        Assert.IsFalse(result.Failure is not null, "Fail would block the other schemes");
    }

    /// <summary>The prefix is compared case-insensitively: whoever writes the header by hand does not
    /// have to get the case right.</summary>
    [TestMethod]
    public async Task The_prefix_is_case_insensitive()
    {
        Assert.IsTrue((await Authenticate("pat " + Good)).Succeeded);
        Assert.IsTrue((await Authenticate("PAT " + Good)).Succeeded);
    }

    // =====================================================================
    // A valid token
    // =====================================================================

    [TestMethod]
    public async Task A_valid_token_authenticates_under_its_own_name()
    {
        var result = await Authenticate("PAT " + Good);

        Assert.IsTrue(result.Succeeded);
        Assert.AreEqual("hours integration", result.Principal!.Identity!.Name);
        Assert.AreEqual(
            PatAuthenticationHandler.SchemeName,
            result.Principal.FindFirst(ClaimTypes.AuthenticationMethod)?.Value);
    }

    /// <summary>
    /// The test that ties this handler to authorization: the permission handler grants through
    /// <c>IsInRole</c>, so every code has to end up as a QUERYABLE role claim, not
    /// merely present with any claim type.
    /// </summary>
    [TestMethod]
    public async Task Every_permission_becomes_a_role_the_authorization_handler_can_read()
    {
        var result = await Authenticate("PAT " + Good);

        Assert.IsTrue(result.Principal!.IsInRole("my.Timesheet"));
        Assert.IsTrue(result.Principal.IsInRole("fabrikam.Controlling"));
        Assert.IsFalse(result.Principal.IsInRole("global.UserAdministration"), "what it does not grant");
    }

    /// <summary>
    /// It carries no email, and that is deliberate: it is what distinguishes a non-person client. The
    /// authorization handler uses that absence to allow it the role-claim shortcut, which it denies
    /// to a person — for a person the database is the only source.
    /// </summary>
    [TestMethod]
    public async Task A_token_is_not_a_person_so_it_carries_no_email()
    {
        var options = new PermissionAuthorizationOptions();
        var result = await Authenticate("PAT " + Good);

        var identity = new Authorization.ClaimsUserIdentityResolver(options).Resolve(result.Principal!);

        Assert.IsTrue(string.IsNullOrEmpty(identity?.Email), "no email: it is not a person");
    }

    // =====================================================================
    // When the store goes down
    // =====================================================================

    /// <summary>
    /// A store that blows up is not "there is no token": it is unknown whether it was valid. It fails, and whoever reads it
    /// will see the error in the log instead of an unexplained 401.
    /// </summary>
    [TestMethod]
    public async Task A_store_failure_fails_the_authentication()
    {
        var result = await Authenticate("PAT " + Good, store: new ThrowingStore());

        Assert.IsFalse(result.Succeeded);
        Assert.IsNotNull(result.Failure);
        Assert.IsFalse(result.None, "it is not the same as carrying no token");
    }

    // =====================================================================

    private static async Task<AuthenticateResult> Authenticate(string? header, IPatStore? store = null)
    {
        var context = new DefaultHttpContext
        {
            RequestServices = new ServiceCollection()
                .AddSingleton(store ?? new FakeStore())
                .BuildServiceProvider(),
        };

        if (header is not null)
            context.Request.Headers["Authorization"] = header;

        var handler = new PatAuthenticationHandler(
            new StubOptions<PatAuthenticationOptions>(),
            NullLoggerFactory.Instance,
            UrlEncoder.Default);

        await handler.InitializeAsync(
            new AuthenticationScheme(
                PatAuthenticationHandler.SchemeName, null, typeof(PatAuthenticationHandler)),
            context);

        return await handler.AuthenticateAsync();
    }
}

/// <summary>Knows a single token, and answers it with two permissions.</summary>
internal sealed class FakeStore : IPatStore
{
    public Task<PatPrincipal?> ResolveAsync(byte[] tokenHash, CancellationToken cancellationToken = default)
    {
        var expected = PatToken.Hash("a-good-token");
        var matches = tokenHash.Length == expected.Length && tokenHash.SequenceEqual(expected);

        return Task.FromResult(matches
            ? new PatPrincipal("hours integration",
                new HashSet<string>(StringComparer.Ordinal) { "my.Timesheet", "fabrikam.Controlling" })
            : null);
    }
}

internal sealed class ThrowingStore : IPatStore
{
    public Task<PatPrincipal?> ResolveAsync(byte[] tokenHash, CancellationToken cancellationToken = default) =>
        throw new InvalidOperationException("the database does not respond");
}

internal sealed class StubOptions<T> : IOptionsMonitor<T> where T : class, new()
{
    public T CurrentValue { get; } = new();

    public T Get(string? name) => CurrentValue;

    public IDisposable? OnChange(Action<T, string?> listener) => null;
}
