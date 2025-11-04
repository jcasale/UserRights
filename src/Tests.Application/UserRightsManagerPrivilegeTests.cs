namespace Tests.Application;

using System.Security.Principal;
using System.Text.RegularExpressions;

using UserRights.Application;

using static Tests.TestData;

/// <summary>
/// Represents tests for <see cref="IUserRightsManager"/> modify privilege functionality.
/// </summary>
[TestClass]
public class UserRightsManagerPrivilegeTests
{
    /// <summary>
    /// Gets invalid method arguments for the <see cref="IUserRightsManager.ModifyPrivilege"/> unit test.
    /// </summary>
    /// <returns>A sequence of method arguments.</returns>
    public static IEnumerable<(ILsaUserRights Policy, string Privilege, string[] Grants, string[] Revocations, bool RevokeAll, bool RevokeOthers, string RevokePattern, bool DryRun)> InvalidArgumentData
    {
        get
        {
            var policy = new MockLsaUserRights();
            const string pattern = ".*";

            return
            [
                // Verify null policy instance.
                new(null!, Privilege1, [PrincipalName1], [], false, false, null!, new(false)),

                // Verify null or empty privilege.
                new(policy, null!, [PrincipalName1], [], false, false, null!, new(false)),
                new(policy, string.Empty, [PrincipalName1], [], false, false, null!, new(false)),

                // Verify null grant collection.
                new(policy, Privilege1, null!, [PrincipalName1], false, false, null!, new(false)),

                // Verify null revocation collection.
                new(policy, Privilege1, [PrincipalName1], null!, false, false, null!, new(false)),

                // Verify RevokeAll requirements.
                new(policy, Privilege1, [PrincipalName1], [], true, false, null!, new(false)),
                new(policy, Privilege1, [], [PrincipalName1], true, false, null!, new(false)),
                new(policy, Privilege1, [], [], true, true, null!, new(false)),
                new(policy, Privilege1, [], [], true, false, pattern, new(false)),

                // Verify RevokeOthers requirements.
                new(policy, Privilege1, [], [], false, true, null!, new(false)),
                new(policy, Privilege1, [PrincipalName1], [PrincipalName2], false, true, null!, new(false)),
                new(policy, Privilege2, [], [], true, true, null!, new(false)),
                new(policy, Privilege1, [], [], false, true, pattern, new(false)),

                // Verify RevokePattern requirements.
                new(policy, Privilege1, [], [PrincipalName1], false, false, pattern, new(false)),
                new(policy, Privilege2, [], [], true, false, pattern, new(false)),
                new(policy, Privilege2, [], [], false, true, pattern, new(false)),

                // Verify remaining requirements.
                new(policy, Privilege1, [], [], false, false, null!, new(false)),

                // Verify grant and revocation set restrictions.
                new(policy, Privilege1, [PrincipalName1], [PrincipalName1], false, false, null!, new(false)),
                new(policy, Privilege1, [PrincipalName1, PrincipalName1], [], false, false, null!, new(false)),
                new(policy, Privilege1, [], [PrincipalName1, PrincipalName1], false, false, null!, new(false))
            ];
        }
    }

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

        using var fixture = new UserRightsManagerFixture();

        // Act.
        fixture.UserRightsManager.ModifyPrivilege(policy, Privilege2, [PrincipalName1], [], false, true, null!, false);

        // Assert.
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
    public void GrantAndRevokeShouldWork()
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

        using var fixture = new UserRightsManagerFixture();

        // Act.
        fixture.UserRightsManager.ModifyPrivilege(policy, Privilege1, [PrincipalName2], [PrincipalName1], false, false, null!, false);

        // Assert.
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2 }, policy.LsaEnumerateAccountsWithUserRight());
        CollectionAssert.AreEqual(new[] { Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid1));
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid2));
    }

    /// <summary>
    /// Verifies granting a principal to a privilege and revoking all principals matching a pattern is successful and does not modify other assignments.
    /// </summary>
    [TestMethod]
    public void GrantAndRevokePatternShouldWork()
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

        using var fixture = new UserRightsManagerFixture();
        var pattern = new Regex("^S-1-5-21", RegexOptions.None, TimeSpan.FromSeconds(1));

        // Act.
        fixture.UserRightsManager.ModifyPrivilege(policy, Privilege1, [PrincipalName1], [], false, false, pattern, false);

        // Assert.
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2, PrincipalSid3 }, policy.LsaEnumerateAccountsWithUserRight());
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid1));
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid2));
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid3));
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
        fixture.UserRightsManager.ModifyPrivilege(policy, Privilege2, [PrincipalName1], [], false, false, null!, false);

        // Assert.
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2 }, policy.LsaEnumerateAccountsWithUserRight());
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid1));
        CollectionAssert.AreEqual(new[] { Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid2));
    }

    /// <summary>
    /// Verifies invalid arguments throw an instance of <see cref="ArgumentException"/>.
    /// </summary>
    /// <param name="policy">A connection to the local security authority.</param>
    /// <param name="privilege">The privilege to modify.</param>
    /// <param name="grants">The principals to grant the privilege to.</param>
    /// <param name="revocations">The principals to revoke the privilege from.</param>
    /// <param name="revokeAll">Revokes all principals from the privilege.</param>
    /// <param name="revokeOthers">Revokes all principals from the privilege excluding those being granted.</param>
    /// <param name="revokePattern">Revokes all principals whose SID matches the regular expression excluding those being granted.</param>
    /// <param name="dryRun">Enables dry-run mode.</param>
    [TestMethod]
    [DynamicData(nameof(InvalidArgumentData))]
    public void InvalidArgumentsThrowsException(ILsaUserRights policy, string privilege, string[] grants, string[] revocations, bool revokeAll, bool revokeOthers, string revokePattern, bool dryRun)
    {
        // Arrange.
        using var fixture = new UserRightsManagerFixture();
        var regex = string.IsNullOrWhiteSpace(revokePattern) ? null : new Regex(revokePattern, RegexOptions.None, TimeSpan.FromSeconds(1));

        // Act & Assert.
        Assert.Throws<ArgumentException>(() => fixture.UserRightsManager.ModifyPrivilege(policy, privilege, grants, revocations, revokeAll, revokeOthers, regex, dryRun));
    }

    /// <summary>
    /// Verifies revoking all principals for a privilege is successful and does not modify other assignments.
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
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2 }, policy.LsaEnumerateAccountsWithUserRight(Privilege1));
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2 }, policy.LsaEnumerateAccountsWithUserRight(Privilege2));

        using var fixture = new UserRightsManagerFixture();

        // Act.
        fixture.UserRightsManager.ModifyPrivilege(policy, Privilege1, [], [], true, false, null!, false);

        // Assert.
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
        fixture.UserRightsManager.ModifyPrivilege(policy, Privilege1, [], [PrincipalName2], false, false, null!, false);

        // Assert.
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2 }, policy.LsaEnumerateAccountsWithUserRight());
        CollectionAssert.AreEqual(new[] { Privilege1 }, policy.LsaEnumerateAccountRights(PrincipalSid1));
        CollectionAssert.AreEqual(new[] { Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid2));
    }

    /// <summary>
    /// Verifies revoking all non-builtin and virtual principals from a privilege is successful.
    /// </summary>
    [TestMethod]
    public void RevokePatternForAllButBuiltinAndVirtualShouldWork()
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

        using var fixture = new UserRightsManagerFixture();
        var pattern = new Regex("^S-1-5-21", RegexOptions.None, TimeSpan.FromSeconds(1));

        // Act.
        fixture.UserRightsManager.ModifyPrivilege(policy, Privilege1, [], [], false, false, pattern, false);

        // Assert.
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2, PrincipalSid3 }, policy.LsaEnumerateAccountsWithUserRight());
        CollectionAssert.AreEqual(new[] { Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid1));
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid2));
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid3));
    }
}