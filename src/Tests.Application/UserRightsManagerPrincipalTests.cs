namespace Tests.Application;

using System.Security.Principal;

using UserRights.Application;

using static Tests.TestData;

/// <summary>
/// Represents tests for <see cref="IUserRightsManager"/> modify principal functionality.
/// </summary>
[TestClass]
public class UserRightsManagerPrincipalTests
{
    /// <summary>
    /// Gets invalid method arguments for the <see cref="IUserRightsManager.ModifyPrincipal"/> unit test.
    /// </summary>
    public static IEnumerable<(ILsaUserRights Policy, string Principal, string[] Grants, string[] Revocations, bool RevokeAll, bool RevokeOthers, bool DryRun)> InvalidArgumentData
    {
        get
        {
            var policy = new MockLsaUserRights(
                new Dictionary<string, ICollection<SecurityIdentifier>>(StringComparer.InvariantCultureIgnoreCase)
                {
                    { "joey", new List<SecurityIdentifier> { PrincipalSid1 } }
                });

            return
            [
                // Verify null policy instance.
                new(null!, PrincipalName1, [Privilege1], [], false, false, false),

                // Verify null or empty principal.
                new(policy, null!, [Privilege1], [], false, false, false),
                new(policy, string.Empty, [Privilege1], [], false, false, false),

                // Verify null grant collection.
                new(policy, PrincipalName1, null!, [Privilege1], false, false, false),

                // Verify null revocation collection.
                new(policy, PrincipalName1, [Privilege1], null!, false, false, false),

                // Verify RevokeAll requirements.
                new(policy, PrincipalName1, [Privilege1], [], true, false, false),
                new(policy, PrincipalName1, [], [Privilege1], true, false, false),
                new(policy, PrincipalName1, [], [], true, true, false),

                // Verify RevokeOthers requirements.
                new(policy, PrincipalName1, [Privilege1], [], true, true, false),
                new(policy, PrincipalName1, [], [], false, true, false),
                new(policy, PrincipalName1, [Privilege1], [Privilege2], false, true, false),

                // Verify remaining requirements.
                new(policy, PrincipalName1, [], [], false, false, false),

                // Verify grant and revocation set restrictions.
                new(policy, PrincipalName1, [Privilege1], [Privilege1], false, false, false),
                new(policy, PrincipalName1, [Privilege1, Privilege1], [], false, false, false),
                new(policy, PrincipalName1, [], [Privilege1, Privilege1], false, false, false)
            ];
        }
    }

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

        using var fixture = new UserRightsManagerFixture();

        // Act.
        fixture.UserRightsManager.ModifyPrincipal(policy, PrincipalName1, [Privilege2], [], false, true, false);

        // Assert.
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
        CollectionAssert.AreEqual(new[] { Privilege1, Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid2));

        using var fixture = new UserRightsManagerFixture();

        // Act.
        fixture.UserRightsManager.ModifyPrincipal(policy, PrincipalName1, [Privilege2], [Privilege1], false, false, false);

        // Assert.
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2 }, policy.LsaEnumerateAccountsWithUserRight());
        CollectionAssert.AreEqual(new[] { Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid1));
        CollectionAssert.AreEqual(new[] { Privilege1, Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid2));
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
        CollectionAssert.AreEqual(new[] { Privilege1, Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid2));

        using var fixture = new UserRightsManagerFixture();

        // Act.
        fixture.UserRightsManager.ModifyPrincipal(policy, PrincipalName1, [Privilege2], [], false, false, false);

        // Assert.
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2 }, policy.LsaEnumerateAccountsWithUserRight());
        CollectionAssert.AreEqual(new[] { Privilege1, Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid1));
        CollectionAssert.AreEqual(new[] { Privilege1, Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid2));
    }

    /// <summary>
    /// Verifies invalid arguments throw an instance of <see cref="ArgumentException"/>.
    /// </summary>
    /// <param name="policy">A connection to the local security authority.</param>
    /// <param name="principal">The principal to modify.</param>
    /// <param name="grants">The privileges to grant to the principal.</param>
    /// <param name="revocations">The privileges to revoke from the principal.</param>
    /// <param name="revokeAll">Revokes all privileges from the principal.</param>
    /// <param name="revokeOthers">Revokes all privileges from the principal excluding those being granted.</param>
    /// <param name="dryRun">Enables dry-run mode.</param>
    [TestMethod]
    [DynamicData(nameof(InvalidArgumentData))]
    public void InvalidArgumentsThrowsException(ILsaUserRights policy, string principal, string[] grants, string[] revocations, bool revokeAll, bool revokeOthers, bool dryRun)
    {
        // Arrange.
        using var fixture = new UserRightsManagerFixture();

        // Act & Assert.
        Assert.Throws<ArgumentException>(() => fixture.UserRightsManager.ModifyPrincipal(policy, principal, grants, revocations, revokeAll, revokeOthers, dryRun));
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

        using var fixture = new UserRightsManagerFixture();

        // Act.
        fixture.UserRightsManager.ModifyPrincipal(policy, PrincipalName1, [], [], true, false, false);

        // Assert.
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

        using var fixture = new UserRightsManagerFixture();

        // Act.
        fixture.UserRightsManager.ModifyPrincipal(policy, PrincipalName2, [], [Privilege2], false, false, false);

        // Assert.
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2 }, policy.LsaEnumerateAccountsWithUserRight());
        CollectionAssert.AreEqual(new[] { Privilege1 }, policy.LsaEnumerateAccountRights(PrincipalSid1));
        CollectionAssert.AreEqual(new[] { Privilege1 }, policy.LsaEnumerateAccountRights(PrincipalSid2));
    }
}