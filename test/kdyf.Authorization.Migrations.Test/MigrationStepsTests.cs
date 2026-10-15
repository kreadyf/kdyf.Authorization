using kdyf.Authorization.Migrations.Schema;

namespace kdyf.Authorization.Migrations.Test;

/// <summary>The rules every step keeps. No database.</summary>
[TestClass]
public sealed class MigrationStepsTests
{
    /// <summary>
    /// A released step never changes: databases record its checksum, and <c>verify</c> fails on any that no longer
    /// matches. A change to the schema is a NEW step. Add the new step's checksum here; never edit one of these.
    /// </summary>
    [TestMethod]
    public void Released_steps_are_frozen()
    {
        var released = new Dictionary<string, string>
        {
            ["0000-runtime-role"] = "3b28791cd3e25ce851477cf2ebe0512f048ff11feb9d855e7b1db41ff6b4976b",
            ["0001-tables"] = "b1c11e32d176a5c3a2f427890b762a2904afbe7edb0ea105534d342902bc3aaa",
            ["0002-rolepermission-permissioncode-index"] = "3d88b45ade845c278a534aa8bcaf26bfad79a9a8addcc36796bb23e620ff7901",
            ["0003-runtime-grants"] = "72b27cdf0ecffd982ee70efecdd437f7fc13dec152071d1825064c9374e9a273",
        };

        foreach (var step in MigrationSteps.All)
        {
            Assert.IsTrue(released.TryGetValue(step.Id, out var checksum), $"{step.Id} is not in the list of released steps: add it with {step.Checksum}.");
            Assert.AreEqual(checksum, step.Checksum, $"{step.Id} changed after its release. Restore it, and make the change a new step.");
        }
    }

    [TestMethod]
    public void Versions_are_consecutive_from_zero_and_ids_are_unique()
    {
        CollectionAssert.AreEqual(Enumerable.Range(0, MigrationSteps.All.Count).ToArray(), MigrationSteps.All.Select(s => s.Version).ToArray());
        Assert.AreEqual(MigrationSteps.All.Count, MigrationSteps.All.Select(s => s.Id).Distinct().Count());
        foreach (var step in MigrationSteps.All)
            StringAssert.StartsWith(step.Id, step.Version.ToString("0000") + "-");
    }

    /// <summary>The same step has the same checksum in every database, whatever the schema is called.</summary>
    [TestMethod]
    public void The_checksum_does_not_depend_on_the_schema_or_the_line_endings()
    {
        var step = new TablesStep();
        Assert.AreNotEqual(step.Sql("auth", "kdyf_auth_runtime"), step.Sql("authz", "kdyf_authz_runtime"));
        Assert.AreEqual(64, step.Checksum.Length);
    }

    [TestMethod]
    public void The_steps_create_what_the_manifest_lists()
    {
        var sql = new TablesStep().Sql("auth", "r");
        foreach (var table in SchemaManifest.Tables(1))
        {
            StringAssert.Contains(sql, $"[auth].[{table.Name}]");
            StringAssert.Contains(sql, table.PrimaryKeyName);
            foreach (var foreignKey in table.ForeignKeys)
                StringAssert.Contains(sql, foreignKey.Name);
            foreach (var index in table.Indexes)
                StringAssert.Contains(sql, index.Name);
        }
    }

    [TestMethod]
    public void A_schema_name_that_is_not_an_identifier_is_refused()
    {
        Assert.ThrowsException<ArgumentException>(() => new SchemaMigrator("Server=unused", new SchemaMigrationOptions { Schema = "auth]; DROP TABLE x; --" }));
        Assert.ThrowsException<ArgumentException>(() => new SchemaMigrator("Server=unused", new SchemaMigrationOptions { AppUser = "x]; DROP USER y; --" }));
    }
}
