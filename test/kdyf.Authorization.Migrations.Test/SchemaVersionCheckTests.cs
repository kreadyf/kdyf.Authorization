using kdyf.Authorization.EntityFrameworkCore;
using kdyf.Authorization.Migrations.Schema;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace kdyf.Authorization.Migrations.Test;

/// <summary>
/// The check a host runs when it starts: a schema without a version only warns (until the host requires one), a schema
/// behind the packages or with a failed step stops the host.
/// </summary>
[TestClass]
public sealed class SchemaVersionCheckTests
{
    private static async Task StartAsync(TestDatabase db, bool require = false)
    {
        var services = new ServiceCollection();
        var options = new AuthorizationStoreOptions { RequireSchemaVersion = require };
        services.AddSingleton(Options.Create(options));
        services.AddDbContext<AuthorizationDbContext>(o => o.UseSqlServer(db.ConnectionString));
        await using var provider = services.BuildServiceProvider();

        var check = new SchemaVersionCheck<AuthorizationDbContext>(
            provider, provider.GetRequiredService<IOptions<AuthorizationStoreOptions>>(), NullLogger<SchemaVersionCheck<AuthorizationDbContext>>.Instance);
        await check.StartAsync(CancellationToken.None);
    }

    [TestMethod]
    public async Task A_schema_at_the_required_version_starts()
    {
        await using var db = await TestDatabase.CreateAsync();
        await new SchemaMigrator(db.ConnectionString).ApplyAsync();

        await StartAsync(db, require: true);
    }

    [TestMethod]
    public async Task A_schema_without_a_version_starts_unless_one_is_required()
    {
        await using var db = await TestDatabase.CreateAsync();
        await db.ExecuteAsync(Fixtures.HostScriptVersion1);
        await db.ExecuteAsync("CREATE TABLE auth.UserProfile (objectId VARCHAR(50) NOT NULL PRIMARY KEY, isActive BIT NOT NULL);");

        await StartAsync(db);
        var error = await Assert.ThrowsExceptionAsync<InvalidOperationException>(() => StartAsync(db, require: true));
        StringAssert.Contains(error.Message, "no version");
    }

    /// <summary>
    /// Without a version the host only warns, but without the profiles table every request would fail on it (the
    /// suspension is read on each resolution): that is said at startup, with what to run.
    /// </summary>
    [TestMethod]
    public async Task A_schema_without_a_version_and_without_the_profiles_does_not_start()
    {
        await using var db = await TestDatabase.CreateAsync();
        await db.ExecuteAsync(Fixtures.HostScriptVersion1);

        var error = await Assert.ThrowsExceptionAsync<InvalidOperationException>(() => StartAsync(db));

        StringAssert.Contains(error.Message, "kdyf-auth adopt");
    }

    [TestMethod]
    public async Task A_schema_behind_the_packages_does_not_start()
    {
        await using var db = await TestDatabase.CreateAsync();
        await new SchemaMigrator(db.ConnectionString, new SchemaMigrationOptions(), null,
            new MigrationStep[] { new RuntimeRoleStep(), new TablesStep() }).ApplyAsync();

        var error = await Assert.ThrowsExceptionAsync<InvalidOperationException>(() => StartAsync(db));

        StringAssert.Contains(error.Message, "at version 1");
    }

    [TestMethod]
    public async Task A_failed_step_does_not_start()
    {
        var state = new SchemaVersionCheck<AuthorizationDbContext>.SchemaVersionState(3, "0004-something");

        var error = SchemaVersionCheck<AuthorizationDbContext>.Evaluate(state, new AuthorizationStoreOptions());

        StringAssert.Contains(error, "0004-something");
    }

    [TestMethod]
    public void A_schema_ahead_of_the_packages_starts() =>
        Assert.IsNull(SchemaVersionCheck<AuthorizationDbContext>.Evaluate(
            new SchemaVersionCheck<AuthorizationDbContext>.SchemaVersionState(AuthorizationSchema.RequiredVersion + 1, null),
            new AuthorizationStoreOptions { RequireSchemaVersion = true }));
}
