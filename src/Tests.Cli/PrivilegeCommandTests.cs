namespace Tests.Cli;

using System.Security.Principal;

using UserRights.Cli;

using static Tests.TestData;

/// <summary>
/// Represents integration tests for modify privilege functionality.
/// </summary>
[TestClass]
public class PrivilegeCommandTests
{
    /// <summary>
    /// Verifies granting a principal to a privilege and revoking its other principals is successful and does not modify other assignments.
    /// </summary>
    [TestMethod]
    public void GrantAndRevokeOthersShouldWork()
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
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2 }, policy.LsaEnumerateAccountsWithUserRight(Privilege1));
        CollectionAssert.AreEqual(new[] { PrincipalSid2 }, policy.LsaEnumerateAccountsWithUserRight(Privilege2));

        policy.ResetConnection();

        using var fixture = new CliBuilderFixture(policy);

        var rootCommand = fixture.CliBuilder.Build();

        var args = new[] { "privilege", Privilege2, "--grant", PrincipalName1, "--revoke-others" };

        // Act.
        var rc = rootCommand.Parse(args).ThrowIfInvalid().Run();

        // Assert.
        Assert.AreEqual(0, rc);
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2 }, policy.LsaEnumerateAccountsWithUserRight());
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid1));
        CollectionAssert.AreEqual(new[] { Privilege1 }, policy.LsaEnumerateAccountRights(PrincipalSid2));
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2 }, policy.LsaEnumerateAccountsWithUserRight(Privilege1));
        CollectionAssert.AreEqual(new[] { PrincipalSid1 }, policy.LsaEnumerateAccountsWithUserRight(Privilege2));
    }

    /// <summary>
    /// Verifies a single grant with a single revoke is successful and does not modify other assignments.
    /// </summary>
    [TestMethod]
    public void GrantAndRevokePasses()
    {
        // Arrange.
        var principals1 = new List<SecurityIdentifier>
        {
            PrincipalSid1
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
        CollectionAssert.AreEqual(new[] { Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid2));

        policy.ResetConnection();

        using var fixture = new CliBuilderFixture(policy);

        var rootCommand = fixture.CliBuilder.Build();

        var args = new[] { "privilege", Privilege1, "--grant", PrincipalName2, "--revoke", PrincipalName1 };

        // Act.
        var rc = rootCommand.Parse(args).ThrowIfInvalid().Run();

        // Assert.
        Assert.AreEqual(0, rc);
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2 }, policy.LsaEnumerateAccountsWithUserRight());
        CollectionAssert.AreEqual(new[] { Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid1));
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid2));
    }

    /// <summary>
    /// Verifies granting a principal to a privilege and revoking all principals matching a pattern is successful and does not modify other assignments.
    /// </summary>
    [TestMethod]
    public void GrantAndRevokePatternPasses()
    {
        // Arrange.
        var principals1 = new List<SecurityIdentifier>
        {
            PrincipalSidCurrent,
            PrincipalSid2,
            PrincipalSid3
        };

        var principals2 = new List<SecurityIdentifier>
        {
            PrincipalSid1,
            PrincipalSid2,
            PrincipalSid3
        };

        var database = new Dictionary<string, ICollection<SecurityIdentifier>>(StringComparer.Ordinal)
        {
            { Privilege1, principals1 },
            { Privilege2, principals2 }
        };

        var policy = new MockLsaUserRights(database);
        policy.Connect("SystemName");

        CollectionAssert.AreEquivalent(new[] { PrincipalSidCurrent, PrincipalSid1, PrincipalSid2, PrincipalSid3 }, policy.LsaEnumerateAccountsWithUserRight());
        CollectionAssert.AreEqual(new[] { Privilege1 }, policy.LsaEnumerateAccountRights(PrincipalSidCurrent));
        CollectionAssert.AreEqual(new[] { Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid1));
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid2));
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid3));

        policy.ResetConnection();

        using var fixture = new CliBuilderFixture(policy);

        var rootCommand = fixture.CliBuilder.Build();

        var args = new[] { "privilege", Privilege1, "--grant", PrincipalName1, "--revoke-pattern", "^S-1-5-21" };

        // Act.
        var rc = rootCommand.Parse(args).ThrowIfInvalid().Run();

        // Assert.
        Assert.AreEqual(0, rc);
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2, PrincipalSid3 }, policy.LsaEnumerateAccountsWithUserRight());
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid1));
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid2));
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid3));
    }

    /// <summary>
    /// Verifies a single grant is successful and does not modify other assignments.
    /// </summary>
    [TestMethod]
    public void GrantPasses()
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

        var args = new[] { "privilege", Privilege2, "--grant", PrincipalName1 };

        // Act.
        var rc = rootCommand.Parse(args).ThrowIfInvalid().Run();

        // Assert.
        Assert.AreEqual(0, rc);
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2 }, policy.LsaEnumerateAccountsWithUserRight());
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid1));
        CollectionAssert.AreEqual(new[] { Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid2));
    }

    /// <summary>
    /// Verifies revoking all principals for a privilege is successful and does not modify other assignments.
    /// </summary>
    [TestMethod]
    public void RevokeAllPasses()
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
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2 }, policy.LsaEnumerateAccountsWithUserRight(Privilege1));
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2 }, policy.LsaEnumerateAccountsWithUserRight(Privilege2));

        policy.ResetConnection();

        using var fixture = new CliBuilderFixture(policy);

        var rootCommand = fixture.CliBuilder.Build();

        var args = new[] { "privilege", Privilege1, "--revoke-all" };

        // Act.
        var rc = rootCommand.Parse(args).ThrowIfInvalid().Run();

        // Assert.
        Assert.AreEqual(0, rc);
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2 }, policy.LsaEnumerateAccountsWithUserRight());
        CollectionAssert.AreEqual(new[] { Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid1));
        CollectionAssert.AreEqual(new[] { Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid2));
        Assert.IsEmpty(policy.LsaEnumerateAccountsWithUserRight(Privilege1));
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2 }, policy.LsaEnumerateAccountsWithUserRight(Privilege2));
    }

    /// <summary>
    /// Verifies a single revocation is successful and does not modify other assignments.
    /// </summary>
    [TestMethod]
    public void RevokePasses()
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

        var args = new[] { "privilege", Privilege1, "--revoke", PrincipalName2 };

        // Act.
        var rc = rootCommand.Parse(args).ThrowIfInvalid().Run();

        // Assert.
        Assert.AreEqual(0, rc);
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2 }, policy.LsaEnumerateAccountsWithUserRight());
        CollectionAssert.AreEqual(new[] { Privilege1 }, policy.LsaEnumerateAccountRights(PrincipalSid1));
        CollectionAssert.AreEqual(new[] { Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid2));
    }

    /// <summary>
    /// Verifies revoking all non-builtin and virtual principals from a privilege is successful.
    /// </summary>
    [TestMethod]
    public void RevokePatternForAllButBuiltinAndVirtualPasses()
    {
        // Arrange.
        var principals1 = new List<SecurityIdentifier>
        {
            PrincipalSidCurrent,
            PrincipalSid2,
            PrincipalSid3
        };

        var principals2 = new List<SecurityIdentifier>
        {
            PrincipalSid1,
            PrincipalSid2,
            PrincipalSid3
        };

        var database = new Dictionary<string, ICollection<SecurityIdentifier>>(StringComparer.Ordinal)
        {
            { Privilege1, principals1 },
            { Privilege2, principals2 }
        };

        var policy = new MockLsaUserRights(database);
        policy.Connect("SystemName");

        CollectionAssert.AreEquivalent(new[] { PrincipalSidCurrent, PrincipalSid1, PrincipalSid2, PrincipalSid3 }, policy.LsaEnumerateAccountsWithUserRight());
        CollectionAssert.AreEqual(new[] { Privilege1 }, policy.LsaEnumerateAccountRights(PrincipalSidCurrent));
        CollectionAssert.AreEqual(new[] { Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid1));
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid2));
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid3));

        policy.ResetConnection();

        using var fixture = new CliBuilderFixture(policy);

        var rootCommand = fixture.CliBuilder.Build();

        var args = new[] { "privilege", Privilege1, "--revoke-pattern", "^S-1-5-21" };

        // Act.
        var rc = rootCommand.Parse(args).ThrowIfInvalid().Run();

        // Assert.
        Assert.AreEqual(0, rc);
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2, PrincipalSid3 }, policy.LsaEnumerateAccountsWithUserRight());
        CollectionAssert.AreEqual(new[] { Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid1));
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid2));
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid3));
    }
}