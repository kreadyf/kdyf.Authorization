using kdyf.Authorization.Abstractions;
using kdyf.Authorization.EntityFrameworkCore.Entities;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace kdyf.Authorization.EntityFrameworkCore.Test;

/// <summary>
/// What a Personal Access Token grants, and when it stops being valid.
/// </summary>
/// <remarks>
/// It is the only door in the system that opens with no person in front of it: a token travels in a
/// header and does not visibly expire the way a session does. What decides what it can do is not stored
/// with it —on purpose— but resolved on every request from what its OWNER holds, through the same
/// permission store as the owner's own requests. Taking the owner out of the group, removing their role or
/// disabling their account has to kill their tokens without anybody looking for them. These tests pin that down.
/// </remarks>
[TestClass]
public class EfPatStoreTests
{
    private static readonly byte[] Hash = new byte[] { 1, 2, 3, 4 };
    private const string Owner = "6a1a2ce1-0000-0000-0000-000000000001";

    [TestMethod]
    public async Task A_valid_token_carries_the_permissions_of_its_owner()
    {
        using var db = new PatFixture();
        db.Permissions.Grant(Owner, "Default", "portal.Read");
        db.SeedToken("timesheet integration");

        var principal = await db.Store().ResolveAsync(Hash);

        Assert.IsNotNull(principal);
        Assert.AreEqual("timesheet integration", principal!.Name, "the token's name, for the log");
        CollectionAssert.AreEquivalent(new[] { "Default", "portal.Read" }, principal.PermissionCodes.ToArray());
    }

    /// <summary>The owner is looked up by the immutable id alone: nothing about them is resolved by e-mail.</summary>
    [TestMethod]
    public async Task The_owner_is_resolved_by_object_id_only()
    {
        using var db = new PatFixture();
        db.Permissions.Grant(Owner, "Default");
        db.SeedToken();

        await db.Store().ResolveAsync(Hash);

        var asked = db.Permissions.Asked.Single();
        Assert.AreEqual(Owner, asked.SubjectId);
        Assert.IsNull(asked.Email, "the frozen label is display only");
    }

    [TestMethod]
    public async Task An_unknown_hash_is_nobody()
    {
        using var db = new PatFixture();
        db.Permissions.Grant(Owner, "Default");
        db.SeedToken();

        Assert.IsNull(await db.Store().ResolveAsync(new byte[] { 9, 9, 9, 9 }));
    }

    [TestMethod]
    public async Task A_deactivated_token_is_refused()
    {
        using var db = new PatFixture();
        db.Permissions.Grant(Owner, "Default");
        db.SeedToken(active: false);

        Assert.IsNull(await db.Store().ResolveAsync(Hash));
    }

    [TestMethod]
    public async Task An_expired_token_is_refused()
    {
        using var db = new PatFixture();
        db.Permissions.Grant(Owner, "Default");
        db.SeedToken(expiresAt: DateTime.UtcNow.AddMinutes(-1));

        Assert.IsNull(await db.Store().ResolveAsync(Hash));
    }

    [TestMethod]
    public async Task A_token_that_has_not_expired_yet_still_works()
    {
        using var db = new PatFixture();
        db.Permissions.Grant(Owner, "Default");
        db.SeedToken(expiresAt: DateTime.UtcNow.AddDays(1));

        Assert.IsNotNull(await db.Store().ResolveAsync(Hash));
    }

    /// <summary>
    /// The guarantee that makes revoking access in Entra enough: the owner's tokens stop working without
    /// anybody looking for them. If this fails, a person who leaves keeps access through a header.
    /// </summary>
    [TestMethod]
    public async Task Revoking_the_owner_in_Entra_invalidates_their_tokens()
    {
        using var db = new PatFixture();
        db.Permissions.Grant(Owner, "Default", "portal.Read");
        db.SeedToken();

        Assert.IsNotNull(await db.Store().ResolveAsync(Hash), "while the owner holds a role");

        db.Permissions.Revoke(Owner);

        Assert.IsNull(await db.Store().ResolveAsync(Hash), "and not once they hold none");
    }

    /// <summary>
    /// A directory failure is not "no permissions" and not "the old permissions": it propagates, and the
    /// authentication handler turns it into a failure — never a grant.
    /// </summary>
    [TestMethod]
    public async Task A_failure_resolving_the_owner_propagates_instead_of_granting()
    {
        using var db = new PatFixture();
        db.Permissions.Grant(Owner, "Default");
        db.Permissions.FailWith = new InvalidOperationException("Graph is down");
        db.SeedToken();

        await Assert.ThrowsExceptionAsync<InvalidOperationException>(() => db.Store().ResolveAsync(Hash));
    }

    [TestMethod]
    public async Task Using_a_token_records_when_it_was_last_used()
    {
        using var db = new PatFixture();
        db.Permissions.Grant(Owner, "Default");
        db.SeedToken();

        Assert.IsNull(db.Token().LastUsedAt, "freshly created, it has not been used");

        await db.Store().ResolveAsync(Hash);

        Assert.IsNotNull(db.Token().LastUsedAt);
    }

    /// <summary>The unique hash is in the mapping, not only in the SQL script, so the model enforces it too.</summary>
    [TestMethod]
    public void Two_tokens_cannot_share_a_hash()
    {
        using var db = new PatFixture();
        db.SeedToken("first");

        Assert.ThrowsException<DbUpdateException>(() => db.SeedToken("second"));
    }
}

/// <summary>One database per test, with the package's model applied, and a permission store to steer.</summary>
internal sealed class PatFixture : IDisposable
{
    private static readonly byte[] Hash = new byte[] { 1, 2, 3, 4 };
    private const string Owner = "6a1a2ce1-0000-0000-0000-000000000001";

    private readonly SqliteConnection _connection;
    private readonly TestAuthContext _context;

    internal PatFixture()
    {
        _connection = new SqliteConnection("DataSource=:memory:");
        _connection.Open();
        _context = new TestAuthContext(new DbContextOptionsBuilder<TestAuthContext>().UseSqlite(_connection).Options);
        _context.Database.EnsureCreated();
    }

    internal FakePermissionStore Permissions { get; } = new();

    internal void SeedToken(string name = "token", bool active = true, DateTime? expiresAt = null)
    {
        _context.Add(new PersonalAccessToken
        {
            Name = name,
            TokenHash = Hash,
            OwnerObjectId = Owner,
            OwnerLabel = "ana@test",
            IsActive = active,
            ExpiresAt = expiresAt,
            CreatedAt = DateTime.UtcNow,
        });
        _context.SaveChanges();
    }

    internal PersonalAccessToken Token()
    {
        _context.ChangeTracker.Clear();
        return _context.Set<PersonalAccessToken>().AsNoTracking().Single();
    }

    internal EfPatStore<TestAuthContext> Store() => new(_context, Permissions);

    public void Dispose()
    {
        _context.Dispose();
        _connection.Dispose();
    }
}

/// <summary>The permission store as the PAT store sees it: who holds what right now, by subject id.</summary>
internal sealed class FakePermissionStore : IPermissionStore
{
    private readonly Dictionary<string, HashSet<string>> _granted = new(StringComparer.OrdinalIgnoreCase);

    internal List<UserIdentity> Asked { get; } = new();

    internal Exception? FailWith { get; set; }

    internal void Grant(string subjectId, params string[] codes) =>
        _granted[subjectId] = codes.ToHashSet(StringComparer.Ordinal);

    internal void Revoke(string subjectId) => _granted.Remove(subjectId);

    public Task<IReadOnlySet<string>> GetPermissionsAsync(UserIdentity user, CancellationToken cancellationToken = default)
    {
        Asked.Add(user);

        if (FailWith is not null)
            throw FailWith;

        IReadOnlySet<string> codes = user.SubjectId is not null && _granted.TryGetValue(user.SubjectId, out var set)
            ? set
            : new HashSet<string>(StringComparer.Ordinal);
        return Task.FromResult(codes);
    }
}

/// <summary>A consumer's context, configured the way the package tells consumers to configure it.</summary>
internal sealed class TestAuthContext : DbContext
{
    public TestAuthContext(DbContextOptions<TestAuthContext> options) : base(options) { }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        modelBuilder.ApplyAuthorizationModel();
    }
}
