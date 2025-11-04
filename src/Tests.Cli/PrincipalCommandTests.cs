namespace Tests.Cli;

using System.Security.Principal;

using UserRights.Cli;

using static Tests.TestData;

/// <summary>
/// Represents integration tests for modify principal functionality.
/// </summary>
[TestClass]
public class PrincipalCommandTests
{
    /// <summary>
    /// Verifies granting a privilege to a principal and revoking their other privileges is successful and does not modify other assignments.
    /// </summary>
    [TestMethod]
    public void GrantAndRevokeOthersShouldWork()
    {
        // Arrange.
        var principals1 = new List<SecurityIdentifier>
        {
            PrincipalSid1
        };

        var principals2 = new List<SecurityIdentifier>
        {
            PrincipalSid2
        };

        var database = new Dictionary<string, ICollection<SecurityIdentifier>>(StringComparer.Ordinal)
        {
            { Privilege1, principals1 },
            { Privilege2, principals2 }
        };

        var policy = new MockLsaUserRights(database);
        policy.Connect("SystemName");

        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2 }, policy.LsaEnumerateAccountsWithUserRight());
        CollectionAssert.AreEqual(new[] { Privilege1 }, policy.LsaEnumerateAccountRights(PrincipalSid1));
        CollectionAssert.AreEqual(new[] { Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid2));

        policy.ResetConnection();

        using var fixture = new CliBuilderFixture(policy);

        var rootCommand = fixture.CliBuilder.Build();

        var args = new[] { "principal", PrincipalName1, "--grant", Privilege2, "--revoke-others" };

        // Act.
        var rc = rootCommand.Parse(args).ThrowIfInvalid().Run();

        // Assert.
        Assert.AreEqual(0, rc);
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2 }, policy.LsaEnumerateAccountsWithUserRight());
        CollectionAssert.AreEqual(new[] { Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid1));
        CollectionAssert.AreEqual(new[] { Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid2));
    }

    /// <summary>
    /// Verifies a single grant with a single revoke is successful and does not modify other assignments.
    /// </summary>
    [TestMethod]
    public void GrantAndRevokeShouldWork()
    {
        // Arrange.
        var principals1 = new List<SecurityIdentifier>
        {
            PrincipalSid1,
            PrincipalSid2
        };

        var principals2 = new List<SecurityIdentifier>
        {
            PrincipalSid2
        };

        var database = new Dictionary<string, ICollection<SecurityIdentifier>>(StringComparer.Ordinal)
        {
            { Privilege1, principals1 },
            { Privilege2, principals2 }
        };

        var policy = new MockLsaUserRights(database);
        policy.Connect("SystemName");

        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2 }, policy.LsaEnumerateAccountsWithUserRight());
        CollectionAssert.AreEqual(new[] { Privilege1 }, policy.LsaEnumerateAccountRights(PrincipalSid1));
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid2));

        policy.ResetConnection();

        using var fixture = new CliBuilderFixture(policy);

        var rootCommand = fixture.CliBuilder.Build();

        var args = new[] { "principal", PrincipalName1, "--grant", Privilege2, "--revoke", Privilege1 };

        // Act.
        var rc = rootCommand.Parse(args).ThrowIfInvalid().Run();

        // Assert.
        Assert.AreEqual(0, rc);
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2 }, policy.LsaEnumerateAccountsWithUserRight());
        CollectionAssert.AreEqual(new[] { Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid1));
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid2));
    }

    /// <summary>
    /// Verifies a single grant is successful and does not modify other assignments.
    /// </summary>
    [TestMethod]
    public void GrantShouldWork()
    {
        // Arrange.
        var principals1 = new List<SecurityIdentifier>
        {
            PrincipalSid1,
            PrincipalSid2
        };

        var principals2 = new List<SecurityIdentifier>
        {
            PrincipalSid2
        };

        var database = new Dictionary<string, ICollection<SecurityIdentifier>>(StringComparer.Ordinal)
        {
            { Privilege1, principals1 },
            { Privilege2, principals2 }
        };

        var policy = new MockLsaUserRights(database);
        policy.Connect("SystemName");

        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2 }, policy.LsaEnumerateAccountsWithUserRight());
        CollectionAssert.AreEqual(new[] { Privilege1 }, policy.LsaEnumerateAccountRights(PrincipalSid1));
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid2));

        policy.ResetConnection();

        using var fixture = new CliBuilderFixture(policy);

        var rootCommand = fixture.CliBuilder.Build();

        var args = new[] { "principal", PrincipalName1, "--grant", Privilege2 };

        // Act.
        var rc = rootCommand.Parse(args).ThrowIfInvalid().Run();

        // Assert.
        Assert.AreEqual(0, rc);
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2 }, policy.LsaEnumerateAccountsWithUserRight());
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid1));
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid2));
    }

    /// <summary>
    /// Verifies a revoking all privileges for a principal is successful and does not modify other assignments.
    /// </summary>
    [TestMethod]
    public void RevokeAllShouldWork()
    {
        // Arrange.
        var principals1 = new List<SecurityIdentifier>
        {
            PrincipalSid1,
            PrincipalSid2
        };

        var principals2 = new List<SecurityIdentifier>
        {
            PrincipalSid1,
            PrincipalSid2
        };

        var database = new Dictionary<string, ICollection<SecurityIdentifier>>(StringComparer.Ordinal)
        {
            { Privilege1, principals1 },
            { Privilege2, principals2 }
        };

        var policy = new MockLsaUserRights(database);
        policy.Connect("SystemName");

        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2 }, policy.LsaEnumerateAccountsWithUserRight());
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid1));
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid2));

        policy.ResetConnection();

        using var fixture = new CliBuilderFixture(policy);

        var rootCommand = fixture.CliBuilder.Build();

        var args = new[] { "principal", PrincipalName1, "--revoke-all" };

        // Act.
        var rc = rootCommand.Parse(args).ThrowIfInvalid().Run();

        // Assert.
        Assert.AreEqual(0, rc);
        Assert.IsEmpty(policy.LsaEnumerateAccountRights(PrincipalSid1));
        CollectionAssert.AreEqual(new[] { PrincipalSid2 }, policy.LsaEnumerateAccountsWithUserRight());
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid2));
    }

    /// <summary>
    /// Verifies a single revocation is successful and does not modify other assignments.
    /// </summary>
    [TestMethod]
    public void RevokeShouldWork()
    {
        // Arrange.
        var principals1 = new List<SecurityIdentifier>
        {
            PrincipalSid1,
            PrincipalSid2
        };

        var principals2 = new List<SecurityIdentifier>
        {
            PrincipalSid2
        };

        var database = new Dictionary<string, ICollection<SecurityIdentifier>>(StringComparer.Ordinal)
        {
            { Privilege1, principals1 },
            { Privilege2, principals2 }
        };

        var policy = new MockLsaUserRights(database);
        policy.Connect("SystemName");

        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2 }, policy.LsaEnumerateAccountsWithUserRight());
        CollectionAssert.AreEqual(new[] { Privilege1 }, policy.LsaEnumerateAccountRights(PrincipalSid1));
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid2));

        policy.ResetConnection();

        using var fixture = new CliBuilderFixture(policy);

        var rootCommand = fixture.CliBuilder.Build();

        var args = new[] { "principal", PrincipalName2, "--revoke", Privilege2 };

        // Act.
        var rc = rootCommand.Parse(args).ThrowIfInvalid().Run();

        // Assert.
        Assert.AreEqual(0, rc);
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2 }, policy.LsaEnumerateAccountsWithUserRight());
        CollectionAssert.AreEqual(new[] { Privilege1 }, policy.LsaEnumerateAccountRights(PrincipalSid1));
        CollectionAssert.AreEqual(new[] { Privilege1 }, policy.LsaEnumerateAccountRights(PrincipalSid2));
    }
}