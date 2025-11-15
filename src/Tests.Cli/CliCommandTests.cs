namespace Tests.Cli;

using System.Globalization;
using System.Security.Principal;
using System.Text.Json;

using CsvHelper;
using CsvHelper.Configuration;

using Moq;

using UserRights.Application;
using UserRights.Cli;
using UserRights.Extensions.Security;

using static Tests.TestData;

/// <summary>
/// Represents CLI command tests.
/// </summary>
[TestClass]
public class CliCommandTests
{
    /// <summary>
    /// Gets or sets the unit test context.
    /// </summary>
    public required TestContext TestContext { get; set; }

    /// <summary>
    /// Verifies listing all user rights to a JSON formatted file works as expected.
    /// </summary>
    /// <returns>A task representing the asynchronous operation.</returns>
    [TestMethod]
    public async Task ListMode_WithJsonAndPath_ShouldWriteJsonToFile()
    {
        // Arrange.
        UserRightEntry[] expected =
        [
            new(Privilege1, PrincipalSid1.Value, PrincipalSid1.ToAccount().Value),
            new(Privilege1, PrincipalSid2.Value, PrincipalSid2.ToAccount().Value),
            new(Privilege2, PrincipalSid2.Value, PrincipalSid2.ToAccount().Value),
            new(Privilege2, PrincipalSid3.Value, PrincipalSid3.ToAccount().Value)
        ];

        var lsaUserRights = LsaUserRightsMockBuilder.CreateBuilder()
            .WithGrant(expected)
            .Build();

        using var fixture = new CliMockBuilder(lsaUserRights.Object);

        var rootCommand = fixture.CliBuilder.Build();

        var file = Path.GetTempFileName();
        var args = new[] { "list", "--json", "--path", file };

        // Act.
        int rc;
        UserRightEntry[] actual;
        try
        {
            rc = await rootCommand.Parse(args).ThrowIfInvalid().RunAsync(TestContext.CancellationToken).ConfigureAwait(false);

            var stream = File.OpenRead(file);
            await using (stream.ConfigureAwait(false))
            {
                var results = await JsonSerializer.DeserializeAsync<UserRightEntry[]>(stream, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
                actual = results?.ToArray() ?? [];
            }
        }
        finally
        {
            File.Delete(file);
        }

        // Assert.
        Assert.AreEqual(0, rc);
        CollectionAssert.AreEquivalent(expected, actual);

        lsaUserRights.Verify(x => x.Connect(), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaEnumerateAccountsWithUserRight(), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaEnumerateAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid1)), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaEnumerateAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid2)), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaEnumerateAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid3)), Times.Exactly(1));
        lsaUserRights.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies listing all user rights to a CSV formatted file works as expected.
    /// </summary>
    /// <returns>A task representing the asynchronous operation.</returns>
    [TestMethod]
    public async Task ListMode_WithPath_ShouldWriteCsvToFile()
    {
        // Arrange.
        UserRightEntry[] expected =
        [
            new(Privilege1, PrincipalSid1.Value, PrincipalSid1.ToAccount().Value),
            new(Privilege1, PrincipalSid2.Value, PrincipalSid2.ToAccount().Value),
            new(Privilege2, PrincipalSid2.Value, PrincipalSid2.ToAccount().Value),
            new(Privilege2, PrincipalSid3.Value, PrincipalSid3.ToAccount().Value)
        ];

        var lsaUserRights = LsaUserRightsMockBuilder.CreateBuilder()
            .WithGrant(expected)
            .Build();

        using var fixture = new CliMockBuilder(lsaUserRights.Object);

        var rootCommand = fixture.CliBuilder.Build();

        var file = Path.GetTempFileName();
        var args = new[] { "list", "--path", file };

        // Act.
        int rc;
        UserRightEntry[] actual;
        try
        {
            rc = await rootCommand.Parse(args).ThrowIfInvalid().RunAsync(TestContext.CancellationToken).ConfigureAwait(false);

            var csvConfiguration = new CsvConfiguration(CultureInfo.InvariantCulture)
            {
                PrepareHeaderForMatch = a => a.Header.ToUpperInvariant() ?? throw new InvalidOperationException()
            };

            using var streamReader = new StreamReader(file);
            using var csvReader = new CsvReader(streamReader, csvConfiguration);

            actual = await csvReader.GetRecordsAsync<UserRightEntry>(TestContext.CancellationToken)
                .ToArrayAsync(TestContext.CancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            File.Delete(file);
        }

        // Assert.
        Assert.AreEqual(0, rc);
        CollectionAssert.AreEquivalent(expected, actual);

        lsaUserRights.Verify(x => x.Connect(), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaEnumerateAccountsWithUserRight(), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaEnumerateAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid1)), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaEnumerateAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid2)), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaEnumerateAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid3)), Times.Exactly(1));
        lsaUserRights.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies a single grant is successful and does not modify other assignments.
    /// </summary>
    [TestMethod]
    public void PrincipalMode_WithGrant_ShouldWork()
    {
        // Arrange.
        var lsaUserRightsMockBuilder = LsaUserRightsMockBuilder.CreateBuilder();
        var lsaUserRights = lsaUserRightsMockBuilder
            .WithGrant(PrincipalSid1, Privilege1)
            .WithGrant(PrincipalSid2, Privilege1, Privilege2)
            .Build();

        using var fixture = new CliMockBuilder(lsaUserRights.Object);

        var rootCommand = fixture.CliBuilder.Build();

        var args = new[] { "principal", PrincipalName1, "--grant", Privilege2 };

        // Act.
        var rc = rootCommand.Parse(args).ThrowIfInvalid().Run();

        // Assert.
        Assert.AreEqual(0, rc);
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2 }, lsaUserRightsMockBuilder.Database.Keys.ToArray());
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid1]);
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid2]);

        lsaUserRights.Verify(x => x.Connect(), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaEnumerateAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid1)), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaAddAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid1), It.Is<string>(s => string.Equals(s, Privilege2, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies a single grant with a single revoke is successful and does not modify other assignments.
    /// </summary>
    [TestMethod]
    public void PrincipalMode_WithGrantAndRevoke_ShouldWork()
    {
        // Arrange.
        const string systemName = "host.example.com";

        var lsaUserRightsMockBuilder = LsaUserRightsMockBuilder.CreateBuilder();
        var lsaUserRights = lsaUserRightsMockBuilder
            .WithSystemName(systemName)
            .WithGrant(PrincipalSid1, Privilege1)
            .WithGrant(PrincipalSid2, Privilege1, Privilege2)
            .Build();

        using var fixture = new CliMockBuilder(lsaUserRights.Object);

        var rootCommand = fixture.CliBuilder.Build();

        var args = new[] { "principal", PrincipalName1, "--grant", Privilege2, "--revoke", Privilege1, "--system-name", systemName };

        // Act.
        var rc = rootCommand.Parse(args).ThrowIfInvalid().Run();

        // Assert.
        Assert.AreEqual(0, rc);
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2 }, lsaUserRightsMockBuilder.Database.Keys.ToArray());
        CollectionAssert.AreEqual(new[] { Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid1]);
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid2]);

        lsaUserRights.Verify(x => x.Connect(It.Is<string>(s => string.Equals(s, systemName, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaEnumerateAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid1)), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaRemoveAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid1), It.Is<string>(s => string.Equals(s, Privilege1, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaAddAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid1), It.Is<string>(s => string.Equals(s, Privilege2, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies granting a privilege to a principal and revoking their other privileges is successful and does not modify other assignments.
    /// </summary>
    [TestMethod]
    public void PrincipalMode_WithGrantAndRevokeOthers_ShouldWork()
    {
        // Arrange.
        var lsaUserRightsMockBuilder = LsaUserRightsMockBuilder.CreateBuilder();
        var lsaUserRights = lsaUserRightsMockBuilder
            .WithGrant(PrincipalSid1, Privilege1)
            .Build();

        using var fixture = new CliMockBuilder(lsaUserRights.Object);

        var rootCommand = fixture.CliBuilder.Build();

        var args = new[] { "principal", PrincipalName1, "--grant", Privilege2, "--revoke-others" };

        // Act.
        var rc = rootCommand.Parse(args).ThrowIfInvalid().Run();

        // Assert.
        Assert.AreEqual(0, rc);
        Assert.ContainsSingle(lsaUserRightsMockBuilder.Database);
        Assert.AreEqual(lsaUserRightsMockBuilder.Database.Keys.Single(), PrincipalSid1);
        CollectionAssert.AreEqual(new[] { Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid1]);

        lsaUserRights.Verify(x => x.Connect(), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaEnumerateAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid1)), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaRemoveAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid1), It.Is<string>(s => string.Equals(s, Privilege1, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaAddAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid1), It.Is<string>(s => string.Equals(s, Privilege2, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies a single revocation is successful and does not modify other assignments.
    /// </summary>
    [TestMethod]
    public void PrincipalMode_WithRevoke_ShouldWork()
    {
        // Arrange.
        var lsaUserRightsMockBuilder = LsaUserRightsMockBuilder.CreateBuilder();
        var lsaUserRights = lsaUserRightsMockBuilder
            .WithGrant(PrincipalSid1, Privilege1)
            .WithGrant(PrincipalSid2, Privilege1, Privilege2)
            .Build();

        using var fixture = new CliMockBuilder(lsaUserRights.Object);

        var rootCommand = fixture.CliBuilder.Build();

        var args = new[] { "principal", PrincipalName2, "--revoke", Privilege2 };

        // Act.
        var rc = rootCommand.Parse(args).ThrowIfInvalid().Run();

        // Assert.
        Assert.AreEqual(0, rc);
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2 }, lsaUserRightsMockBuilder.Database.Keys.ToArray());
        CollectionAssert.AreEqual(new[] { Privilege1 }, lsaUserRightsMockBuilder.Database[PrincipalSid1]);
        CollectionAssert.AreEqual(new[] { Privilege1 }, lsaUserRightsMockBuilder.Database[PrincipalSid2]);

        lsaUserRights.Verify(x => x.Connect(), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaEnumerateAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid2)), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaRemoveAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid2), It.Is<string>(s => string.Equals(s, Privilege2, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies a revoking all privileges for a principal is successful and does not modify other assignments.
    /// </summary>
    [TestMethod]
    public void PrincipalMode_WithRevokeAll_ShouldWork()
    {
        // Arrange.
        var lsaUserRightsMockBuilder = LsaUserRightsMockBuilder.CreateBuilder();
        var lsaUserRights = lsaUserRightsMockBuilder
            .WithGrant(PrincipalSid1, Privilege1)
            .WithGrant(PrincipalSid2, Privilege1, Privilege2)
            .Build();

        using var fixture = new CliMockBuilder(lsaUserRights.Object);

        var rootCommand = fixture.CliBuilder.Build();

        var args = new[] { "principal", PrincipalName1, "--revoke-all" };

        // Act.
        var rc = rootCommand.Parse(args).ThrowIfInvalid().Run();

        // Assert.
        Assert.AreEqual(0, rc);
        CollectionAssert.AreEqual(new[] { PrincipalSid2 }, lsaUserRightsMockBuilder.Database.Keys.ToArray());
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid2]);

        lsaUserRights.Verify(x => x.Connect(), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaEnumerateAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid1)), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaRemoveAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid1), It.Is<string>(s => string.Equals(s, Privilege1, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies a single grant is successful and does not modify other assignments.
    /// </summary>
    [TestMethod]
    public void PrivilegeMode_WithGrant_ShouldWork()
    {
        // Arrange.
        var lsaUserRightsMockBuilder = LsaUserRightsMockBuilder.CreateBuilder();
        var lsaUserRights = lsaUserRightsMockBuilder
            .WithGrant(PrincipalSid1, Privilege1)
            .WithGrant(PrincipalSid2, Privilege2)
            .Build();

        using var fixture = new CliMockBuilder(lsaUserRights.Object);

        var rootCommand = fixture.CliBuilder.Build();

        var args = new[] { "privilege", Privilege2, "--grant", PrincipalName1 };

        // Act.
        var rc = rootCommand.Parse(args).ThrowIfInvalid().Run();

        // Assert.
        Assert.AreEqual(0, rc);
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2 }, lsaUserRightsMockBuilder.Database.Keys.ToArray());
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid1]);
        CollectionAssert.AreEqual(new[] { Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid2]);

        lsaUserRights.Verify(x => x.Connect(), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaEnumerateAccountsWithUserRight(It.Is<string>(s => string.Equals(s, Privilege2, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaAddAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid1), It.Is<string>(s => string.Equals(s, Privilege2, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies a single grant with a single revoke is successful and does not modify other assignments.
    /// </summary>
    [TestMethod]
    public void PrivilegeMode_WithGrantAndRevoke_ShouldWork()
    {
        // Arrange.
        var lsaUserRightsMockBuilder = LsaUserRightsMockBuilder.CreateBuilder();
        var lsaUserRights = lsaUserRightsMockBuilder
            .WithGrant(PrincipalSid1, Privilege1)
            .WithGrant(PrincipalSid2, Privilege2)
            .Build();

        using var fixture = new CliMockBuilder(lsaUserRights.Object);

        var rootCommand = fixture.CliBuilder.Build();

        var args = new[] { "privilege", Privilege1, "--grant", PrincipalName2, "--revoke", PrincipalName1 };

        // Act.
        var rc = rootCommand.Parse(args).ThrowIfInvalid().Run();

        // Assert.
        Assert.AreEqual(0, rc);
        CollectionAssert.AreEqual(new[] { PrincipalSid2 }, lsaUserRightsMockBuilder.Database.Keys.ToArray());
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid2]);

        lsaUserRights.Verify(x => x.Connect(), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaEnumerateAccountsWithUserRight(It.Is<string>(s => string.Equals(s, Privilege1, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaAddAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid2), It.Is<string>(s => string.Equals(s, Privilege1, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaRemoveAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid1), It.Is<string>(s => string.Equals(s, Privilege1, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies granting a principal to a privilege and revoking its other principals is successful and does not modify other assignments.
    /// </summary>
    [TestMethod]
    public void PrivilegeMode_WithGrantAndRevokeOthers_ShouldWork()
    {
        // Arrange.
        var lsaUserRightsMockBuilder = LsaUserRightsMockBuilder.CreateBuilder();
        var lsaUserRights = lsaUserRightsMockBuilder
            .WithGrant(PrincipalSid1, Privilege1)
            .WithGrant(PrincipalSid2, Privilege1, Privilege2)
            .Build();

        using var fixture = new CliMockBuilder(lsaUserRights.Object);

        var rootCommand = fixture.CliBuilder.Build();

        var args = new[] { "privilege", Privilege2, "--grant", PrincipalName1, "--revoke-others" };

        // Act.
        var rc = rootCommand.Parse(args).ThrowIfInvalid().Run();

        // Assert.
        Assert.AreEqual(0, rc);
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2 }, lsaUserRightsMockBuilder.Database.Keys.ToArray());
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid1]);
        CollectionAssert.AreEqual(new[] { Privilege1 }, lsaUserRightsMockBuilder.Database[PrincipalSid2]);

        lsaUserRights.Verify(x => x.Connect(), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaEnumerateAccountsWithUserRight(It.Is<string>(s => string.Equals(s, Privilege2, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaAddAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid1), It.Is<string>(s => string.Equals(s, Privilege2, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaRemoveAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid2), It.Is<string>(s => string.Equals(s, Privilege2, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies granting a principal to a privilege and revoking all principals matching a pattern is successful and does not modify other assignments.
    /// </summary>
    [TestMethod]
    public void PrivilegeMode_WithGrantAndRevokePattern_ShouldWork()
    {
        // Arrange.
        var lsaUserRightsMockBuilder = LsaUserRightsMockBuilder.CreateBuilder();
        var lsaUserRights = lsaUserRightsMockBuilder
            .WithGrant(PrincipalSidCurrent, Privilege1)
            .WithGrant(PrincipalSid1, Privilege2)
            .WithGrant(PrincipalSid2, Privilege1, Privilege2)
            .WithGrant(PrincipalSid3, Privilege1, Privilege2)
            .Build();

        using var fixture = new CliMockBuilder(lsaUserRights.Object);

        var rootCommand = fixture.CliBuilder.Build();

        var args = new[] { "privilege", Privilege1, "--grant", PrincipalName1, "--revoke-pattern", "^S-1-5-21" };

        // Act.
        var rc = rootCommand.Parse(args).ThrowIfInvalid().Run();

        // Assert.
        Assert.AreEqual(0, rc);
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2, PrincipalSid3 }, lsaUserRightsMockBuilder.Database.Keys.ToArray());
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid1]);
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid2]);
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid3]);

        lsaUserRights.Verify(x => x.Connect(), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaEnumerateAccountsWithUserRight(It.Is<string>(s => string.Equals(s, Privilege1, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaAddAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid1), It.Is<string>(s => string.Equals(s, Privilege1, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaRemoveAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSidCurrent), It.Is<string>(s => string.Equals(s, Privilege1, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies a single revocation is successful and does not modify other assignments.
    /// </summary>
    [TestMethod]
    public void PrivilegeMode_WithRevoke_ShouldWork()
    {
        // Arrange.
        var lsaUserRightsMockBuilder = LsaUserRightsMockBuilder.CreateBuilder();
        var lsaUserRights = lsaUserRightsMockBuilder
            .WithGrant(PrincipalSid1, Privilege1)
            .WithGrant(PrincipalSid2, Privilege1, Privilege2)
            .Build();

        using var fixture = new CliMockBuilder(lsaUserRights.Object);

        var rootCommand = fixture.CliBuilder.Build();

        var args = new[] { "privilege", Privilege1, "--revoke", PrincipalName2 };

        // Act.
        var rc = rootCommand.Parse(args).ThrowIfInvalid().Run();

        // Assert.
        Assert.AreEqual(0, rc);
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2 }, lsaUserRightsMockBuilder.Database.Keys.ToArray());
        CollectionAssert.AreEqual(new[] { Privilege1 }, lsaUserRightsMockBuilder.Database[PrincipalSid1]);
        CollectionAssert.AreEqual(new[] { Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid2]);

        lsaUserRights.Verify(x => x.Connect(), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaEnumerateAccountsWithUserRight(It.Is<string>(s => string.Equals(s, Privilege1, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaRemoveAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid2), It.Is<string>(s => string.Equals(s, Privilege1, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies revoking all principals for a privilege is successful and does not modify other assignments.
    /// </summary>
    [TestMethod]
    public void PrivilegeMode_WithRevokeAll_ShouldWork()
    {
        // Arrange.
        var lsaUserRightsMockBuilder = LsaUserRightsMockBuilder.CreateBuilder();
        var lsaUserRights = lsaUserRightsMockBuilder
            .WithGrant(PrincipalSid1, Privilege1, Privilege2)
            .WithGrant(PrincipalSid2, Privilege1, Privilege2)
            .Build();

        using var fixture = new CliMockBuilder(lsaUserRights.Object);

        var rootCommand = fixture.CliBuilder.Build();

        var args = new[] { "privilege", Privilege1, "--revoke-all" };

        // Act.
        var rc = rootCommand.Parse(args).ThrowIfInvalid().Run();

        // Assert.
        Assert.AreEqual(0, rc);
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2 }, lsaUserRightsMockBuilder.Database.Keys.ToArray());
        CollectionAssert.AreEqual(new[] { Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid1]);
        CollectionAssert.AreEqual(new[] { Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid2]);

        lsaUserRights.Verify(x => x.Connect(), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaEnumerateAccountsWithUserRight(It.Is<string>(s => string.Equals(s, Privilege1, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaRemoveAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid1), It.Is<string>(s => string.Equals(s, Privilege1, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaRemoveAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid2), It.Is<string>(s => string.Equals(s, Privilege1, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies revoking all non-builtin and virtual principals from a privilege is successful.
    /// </summary>
    [TestMethod]
    public void PrivilegeMode_WithRevokePattern_ShouldWork()
    {
        // Arrange.
        var lsaUserRightsMockBuilder = LsaUserRightsMockBuilder.CreateBuilder();
        var lsaUserRights = lsaUserRightsMockBuilder
            .WithGrant(PrincipalSidCurrent, Privilege1)
            .WithGrant(PrincipalSid1, Privilege2)
            .WithGrant(PrincipalSid2, Privilege1, Privilege2)
            .WithGrant(PrincipalSid3, Privilege1, Privilege2)
            .Build();

        using var fixture = new CliMockBuilder(lsaUserRights.Object);

        var rootCommand = fixture.CliBuilder.Build();

        var args = new[] { "privilege", Privilege1, "--revoke-pattern", "^S-1-5-21" };

        // Act.
        var rc = rootCommand.Parse(args).ThrowIfInvalid().Run();

        // Assert.
        Assert.AreEqual(0, rc);
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2, PrincipalSid3 }, lsaUserRightsMockBuilder.Database.Keys.ToArray());
        CollectionAssert.AreEqual(new[] { Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid1]);
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid2]);
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid3]);

        lsaUserRights.Verify(x => x.Connect(), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaEnumerateAccountsWithUserRight(It.Is<string>(s => string.Equals(s, Privilege1, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaRemoveAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSidCurrent), It.Is<string>(s => string.Equals(s, Privilege1, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.VerifyNoOtherCalls();
    }
}