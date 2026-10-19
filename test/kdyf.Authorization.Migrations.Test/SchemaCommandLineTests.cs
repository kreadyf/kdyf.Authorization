using kdyf.Authorization.Abstractions;
using kdyf.Authorization.EntityFrameworkCore;
using kdyf.Authorization.Migrations.Schema;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace kdyf.Authorization.Migrations.Test;

/// <summary>The kdyf-auth commands: what they print, and the exit code a pipeline acts on.</summary>
[TestClass]
public sealed class SchemaCommandLineTests
{
    private static async Task<(int Code, string Output)> RunAsync(TestDatabase? db, params string[] args)
    {
        var output = new StringWriter();
        var code = await SchemaCommandLine.RunAsync(args, db?.ConnectionString ?? "Server=unused", "auth", output);
        return (code, output.ToString());
    }

    [TestMethod]
    public async Task Detect_plan_apply_verify_on_an_empty_database()
    {
        await using var db = await TestDatabase.CreateAsync();

        var detect = await RunAsync(db, "detect");
        Assert.AreEqual(SchemaCommandLine.Ok, detect.Code);
        StringAssert.StartsWith(detect.Output, "Empty:");

        var plan = await RunAsync(db, "plan");
        Assert.AreEqual(SchemaCommandLine.Ok, plan.Code, plan.Output);
        StringAssert.Contains(plan.Output, "plan   Apply 3: 0003-runtime-grants");

        Assert.AreEqual(SchemaCommandLine.NotDone, (await RunAsync(db, "verify")).Code);
        var apply = await RunAsync(db, "apply");
        Assert.AreEqual(SchemaCommandLine.Ok, apply.Code, apply.Output);
        var verify = await RunAsync(db, "verify");
        Assert.AreEqual(SchemaCommandLine.Ok, verify.Code, verify.Output);
        StringAssert.Contains(verify.Output, "Verified.");
    }

    [TestMethod]
    public async Task Adopt_refuses_a_database_that_is_not_adopted()
    {
        await using var db = await TestDatabase.CreateAsync();

        var adopt = await RunAsync(db, "adopt");

        Assert.AreEqual(SchemaCommandLine.NotDone, adopt.Code);
        StringAssert.Contains(adopt.Output, "Nothing to adopt");
        Assert.IsNull(await db.ScalarAsync<object>("SELECT OBJECT_ID(N'auth.SchemaVersion')"));
    }

    [TestMethod]
    public async Task Adopt_with_a_confirmed_backup_and_an_approval()
    {
        await using var db = await TestDatabase.CreateAsync();
        await db.ExecuteAsync(Fixtures.CaseInsensitiveVersion1);
        await db.ExecuteAsync(Fixtures.Data);

        var refused = await RunAsync(db, "adopt", "--backup-confirmed");
        Assert.AreEqual(SchemaCommandLine.NotDone, refused.Code);
        StringAssert.Contains(refused.Output, "collation-repair-approval");

        var adopt = await RunAsync(db, "adopt", "--backup-confirmed", "--approve", "collation-repair");
        Assert.AreEqual(SchemaCommandLine.Ok, adopt.Code, adopt.Output);
    }

    [TestMethod]
    public async Task Script_writes_a_file_that_verifies_once_run()
    {
        await using var db = await TestDatabase.CreateAsync();
        var file = Path.Combine(Path.GetTempPath(), $"kdyf-auth-{Guid.NewGuid():N}.sql");
        try
        {
            var script = await RunAsync(db, "script", file);
            Assert.AreEqual(SchemaCommandLine.Ok, script.Code, script.Output);

            await db.ExecuteAsync(await File.ReadAllTextAsync(file));

            Assert.AreEqual(SchemaCommandLine.Ok, (await RunAsync(db, "verify")).Code);
        }
        finally
        {
            File.Delete(file);
        }
    }

    [TestMethod]
    public async Task Wrong_arguments_are_a_usage_error_without_touching_the_database()
    {
        Assert.AreEqual(SchemaCommandLine.Usage, (await RunAsync(null)).Code);
        Assert.AreEqual(SchemaCommandLine.Usage, (await RunAsync(null, "frobnicate")).Code);
        Assert.AreEqual(SchemaCommandLine.Usage, (await RunAsync(null, "migrate", "--bogus")).Code);
        Assert.AreEqual(SchemaCommandLine.Usage, (await RunAsync(null, "migrate", "--approver")).Code);
        Assert.AreEqual(SchemaCommandLine.Usage, (await RunAsync(null, "apply", "--approve", "everything")).Code);
        Assert.AreEqual(SchemaCommandLine.Usage, (await RunAsync(null, "apply", "--schema")).Code);
        Assert.AreEqual(SchemaCommandLine.Usage, (await RunAsync(null, "apply", "--schema", "a b")).Code);
        Assert.AreEqual(SchemaCommandLine.Usage, (await RunAsync(null, "script")).Code);
        Assert.AreEqual(SchemaCommandLine.Ok, (await RunAsync(null, "--help")).Code);
    }

    /// <summary>A pipeline gets a message and exit code 1, not a stack trace.</summary>
    [TestMethod]
    public async Task A_database_that_cannot_be_reached_is_a_message_and_exit_code_1()
    {
        var output = new StringWriter();

        var malformed = await SchemaCommandLine.RunAsync(new[] { "detect" }, "this is not a connection string", "auth", output);
        var unreachable = await SchemaCommandLine.RunAsync(new[] { "plan" }, "Server=tcp:127.0.0.1,1;Connect Timeout=1;Encrypt=False", "auth", output);

        Assert.AreEqual(SchemaCommandLine.NotDone, malformed);
        Assert.AreEqual(SchemaCommandLine.NotDone, unreachable);
        StringAssert.Contains(output.ToString(), "detect failed:");
        StringAssert.Contains(output.ToString(), "plan failed:");
    }

    [TestMethod]
    public async Task A_host_runs_the_command_with_its_own_connection_string_and_schema()
    {
        await using var db = await TestDatabase.CreateAsync();
        using var host = Host.CreateDefaultBuilder()
            .ConfigureServices(services => services.AddSingleton(Options.Create(new AuthorizationStoreOptions { ConnectionString = db.ConnectionString, Schema = "authz", UserProfiles = true })))
            .Build();

        Assert.IsFalse(await host.RunKdyfAuthCommandAsync(Array.Empty<string>()));
        Assert.IsFalse(await host.RunKdyfAuthCommandAsync(new[] { "--urls", "http://localhost:5000" }));

        var exitCode = Environment.ExitCode;
        try
        {
            Assert.IsTrue(await host.RunKdyfAuthCommandAsync(new[] { "kdyf-auth", "apply" }));
            Assert.AreEqual(SchemaCommandLine.Ok, Environment.ExitCode);
        }
        finally
        {
            Environment.ExitCode = exitCode;
        }
        Assert.IsTrue((await new SchemaMigrator(db.ConnectionString, new SchemaMigrationOptions { Schema = "authz", UserProfiles = true }).VerifyAsync()).Succeeded);
    }

    private sealed class ScopedGate : IMembershipSource
    {
        public Task<Membership?> GetMembershipAsync(string subjectId, CancellationToken cancellationToken = default) => Task.FromResult<Membership?>(null);
        public Task<DirectoryIdentity?> FindByEmailAsync(string email, CancellationToken cancellationToken = default) => Task.FromResult<DirectoryIdentity?>(null);
    }

    /// <summary>
    /// The legacy commands resolve the host's scoped services (the access gate is scoped, as in UseEntraId). A host that
    /// validates scopes — any host in Development — refused them from the root provider: the command runs in a scope.
    /// </summary>
    [TestMethod]
    public async Task A_host_that_validates_scopes_runs_the_legacy_commands()
    {
        using var host = Host.CreateDefaultBuilder()
            .UseDefaultServiceProvider(options => { options.ValidateScopes = true; options.ValidateOnBuild = true; })
            .ConfigureServices(services => services
                .AddSingleton(Options.Create(new AuthorizationStoreOptions { ConnectionString = "Server=unused", Schema = "authz" }))
                .AddScoped<IMembershipSource, ScopedGate>())
            .Build();

        var exitCode = Environment.ExitCode;
        try
        {
            // Without the legacy import registered it answers with the usage; what matters is that it answers.
            Assert.IsTrue(await host.RunKdyfAuthCommandAsync(new[] { "kdyf-auth", "resolve" }));
            Assert.AreEqual(SchemaCommandLine.Usage, Environment.ExitCode);
        }
        finally
        {
            Environment.ExitCode = exitCode;
        }
    }
}
