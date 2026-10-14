using kdyf.Authorization.Abstractions;
using kdyf.Authorization.EntityFrameworkCore;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using PermissionRow = kdyf.Authorization.EntityFrameworkCore.Entities.Permission;

namespace kdyf.Authorization.EntityFrameworkCore.Test;

/// <summary>
/// One SQLite database per test, alive as long as the fixture.
/// </summary>
/// <remarks>
/// <c>DataSource=:memory:</c> lives as long as the CONNECTION, so the connection is opened here and
/// handed to every context: let EF open and close its own, and the schema would vanish between the
/// arrange and the act.
/// </remarks>
internal sealed class CatalogFixture : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly ServiceProvider _services;

    internal CatalogFixture(string environment = "Development")
    {
        _connection = new SqliteConnection("DataSource=:memory:");
        _connection.Open();

        Cache = new RecordingPermissionCache();

        var services = new ServiceCollection();
        services.AddDbContext<TestAuthContext>(o => o.UseSqlite(_connection));
        services.AddSingleton<IPermissionCache>(Cache);
        _services = services.BuildServiceProvider();

        Environment = new TestEnvironment { EnvironmentName = environment };

        using var scope = _services.CreateScope();
        scope.ServiceProvider.GetRequiredService<TestAuthContext>().Database.EnsureCreated();
    }

    internal RecordingPermissionCache Cache { get; }

    internal IHostEnvironment Environment { get; }

    /// <summary>Puts rows in the table before the service runs.</summary>
    internal CatalogFixture WithRows(params PermissionRow[] rows)
    {
        using var scope = _services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<TestAuthContext>();
        db.Set<PermissionRow>().AddRange(rows);
        db.SaveChanges();
        return this;
    }

    /// <summary>
    /// Makes the database read-only: reading works, writing blows up. It is as close as one can get
    /// to an application user with no INSERT on auth.Permission, which is the real case.
    /// </summary>
    internal void MakeReadOnly()
    {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = "PRAGMA query_only = ON;";
        cmd.ExecuteNonQuery();
    }

    /// <summary>Runs the synchronisation over exactly these declarations.</summary>
    internal Task SyncAsync(IEnumerable<PermissionDefinition> declarations, bool reportOnly = false)
    {
        var options = new PermissionCatalogSyncOptions { ReportOnly = reportOnly };
        options.Declarations.AddRange(declarations);

        return new PermissionCatalogSynchronizer<TestAuthContext>(
                _services, options, Environment,
                NullLogger<PermissionCatalogSynchronizer<TestAuthContext>>.Instance)
            .StartAsync(CancellationToken.None);
    }

    /// <summary>The table as it stands now, ordered by code.</summary>
    internal List<PermissionRow> Rows()
    {
        using var scope = _services.CreateScope();
        return scope.ServiceProvider.GetRequiredService<TestAuthContext>()
            .Set<PermissionRow>()
            .AsNoTracking()
            .OrderBy(r => r.PermissionCode)
            .ToList();
    }

    internal PermissionRow? Row(string code) =>
        Rows().SingleOrDefault(r => r.PermissionCode == code);

    public void Dispose()
    {
        _services.Dispose();
        _connection.Dispose();
    }

    internal static PermissionRow RowFor(string code, string? name, string? description) =>
        new() { PermissionCode = code, Name = name, Description = description };
}

/// <summary>Records whether the cache was dropped, which is a behaviour worth asserting: a new row
/// changes what a wildcard stands for, and expanded sets are cached.</summary>
internal sealed class RecordingPermissionCache : IPermissionCache
{
    internal int InvalidateAllCalls { get; private set; }

    public void Invalidate(UserIdentity user) { }

    public void InvalidateAll() => InvalidateAllCalls++;
}

internal sealed class TestEnvironment : IHostEnvironment
{
    public string EnvironmentName { get; set; } = "Development";
    public string ApplicationName { get; set; } = "tests";
    public string ContentRootPath { get; set; } = ".";
    public IFileProvider ContentRootFileProvider { get; set; } = null!;
}
