namespace Tests.Application;

using System.Security.Principal;
using System.Text.RegularExpressions;

using Moq;

using static Tests.TestData;

/// <summary>
/// Represents tests for modifying the principals for a specified user right.
/// </summary>
[TestClass]
public class UserRightsManagerPrivilegeTests
{
    /// <summary>
    /// Gets invalid method arguments for the modify privilege unit test.
    /// </summary>
    /// <returns>A sequence of method arguments.</returns>
    public static IEnumerable<(string Privilege, string[] Grants, string[] Revocations, bool RevokeAll, bool RevokeOthers, string? RevokePattern, bool DryRun)> InvalidArgumentData
    {
        get
        {
            const string pattern = ".*";

            return
            [
                // Verify null or empty privilege.
                new(null!, [PrincipalName1], [], false, false, null, false),
                new(string.Empty, [PrincipalName1], [], false, false, null, false),

                // Verify null grant collection.
                new(Privilege1, null!, [PrincipalName1], false, false, null, false),

                // Verify null revocation collection.
                new(Privilege1, [PrincipalName1], null!, false, false, null, false),

                // Verify RevokeAll requirements.
                new(Privilege1, [PrincipalName1], [], true, false, null, false),
                new(Privilege1, [], [PrincipalName1], true, false, null, false),
                new(Privilege1, [], [], true, true, null, false),
                new(Privilege1, [], [], true, false, pattern, false),

                // Verify RevokeOthers requirements.
                new(Privilege1, [], [], false, true, null, false),
                new(Privilege1, [PrincipalName1], [PrincipalName2], false, true, null, false),
                new(Privilege2, [], [], true, true, null, false),
                new(Privilege1, [], [], false, true, pattern, false),

                // Verify RevokePattern requirements.
                new(Privilege1, [], [PrincipalName1], false, false, pattern, false),
                new(Privilege2, [], [], true, false, pattern, false),
                new(Privilege2, [], [], false, true, pattern, false),

                // Verify remaining requirements.
                new(Privilege1, [], [], false, false, null, false),

                // Verify grant and revocation set restrictions.
                new(Privilege1, [PrincipalName1], [PrincipalName1], false, false, null, false),
                new(Privilege1, [PrincipalName1, PrincipalName1], [], false, false, null, false),
                new(Privilege1, [], [PrincipalName1, PrincipalName1], false, false, null, false)
            ];
        }
    }

    /// <summary>
    /// Verifies modifying a privilege with a null policy argument throws an exception.
    /// </summary>
    [TestMethod]
    public void ModifyPrivilege_WithInvalidArguments_ThrowsException()
    {
        // Arrange.
        var lsaUserRights = LsaUserRightsMockBuilder.CreateBuilder().Build();
        using var fixture = new UserRightsManagerFixture();

        // Act & Assert.
        Assert.Throws<ArgumentException>(() => fixture.UserRightsManager.ModifyPrivilege(null!, Privilege1, [PrincipalName1], [], false, false, null, false));

        lsaUserRights.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies modifying a privilege with invalid arguments throws an exception.
    /// </summary>
    /// <param name="privilege">The privilege to modify.</param>
    /// <param name="grants">The principals to grant the privilege to.</param>
    /// <param name="revocations">The principals to revoke the privilege from.</param>
    /// <param name="revokeAll">Revokes all principals from the privilege.</param>
    /// <param name="revokeOthers">Revokes all principals from the privilege excluding those being granted.</param>
    /// <param name="revokePattern">Revokes all principals whose SID matches the regular expression excluding those being granted.</param>
    /// <param name="dryRun">Enables dry-run mode.</param>
    [TestMethod]
    [DynamicData(nameof(InvalidArgumentData))]
    public void ModifyPrivilege_WithInvalidArguments_ThrowsException(string privilege, string[] grants, string[] revocations, bool revokeAll, bool revokeOthers, string revokePattern, bool dryRun)
    {
        // Arrange.
        var lsaUserRights = LsaUserRightsMockBuilder.CreateBuilder().Build();
        using var fixture = new UserRightsManagerFixture();
        var regex = string.IsNullOrWhiteSpace(revokePattern) ? null : new Regex(revokePattern, RegexOptions.None, TimeSpan.FromSeconds(1));

        // Act & Assert.
        Assert.Throws<ArgumentException>(() => fixture.UserRightsManager.ModifyPrivilege(lsaUserRights.Object, privilege, grants, revocations, revokeAll, revokeOthers, regex, dryRun));

        lsaUserRights.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies granting a privilege works as expected.
    /// </summary>
    [TestMethod]
    public void ModifyPrivilege_WithGrant_ShouldWork()
    {
        // Arrange.
        var lsaUserRightsMockBuilder = LsaUserRightsMockBuilder.CreateBuilder();
        var lsaUserRights = lsaUserRightsMockBuilder
            .WithGrant(PrincipalSid1, Privilege1)
            .WithGrant(PrincipalSid2, Privilege2)
            .Build();

        using var fixture = new UserRightsManagerFixture();

        // Act.
        fixture.UserRightsManager.ModifyPrivilege(lsaUserRights.Object, Privilege2, [PrincipalName1], [], false, false, null, false);

        // Assert.
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2 }, lsaUserRightsMockBuilder.Database.Keys.ToArray());
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid1]);
        CollectionAssert.AreEqual(new[] { Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid2]);

        lsaUserRights.Verify(x => x.LsaEnumerateAccountsWithUserRight(It.Is<string>(s => string.Equals(s, Privilege2, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaAddAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid1), It.Is<string>(s => string.Equals(s, Privilege2, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies granting a privilege with dry run enabled works as expected.
    /// </summary>
    [TestMethod]
    public void ModifyPrivilege_WithGrantAndDryRun_ShouldWork()
    {
        // Arrange.
        var lsaUserRightsMockBuilder = LsaUserRightsMockBuilder.CreateBuilder();
        var lsaUserRights = lsaUserRightsMockBuilder
            .WithGrant(PrincipalSid1, Privilege1)
            .WithGrant(PrincipalSid2, Privilege2)
            .Build();

        using var fixture = new UserRightsManagerFixture();

        // Act.
        fixture.UserRightsManager.ModifyPrivilege(lsaUserRights.Object, Privilege2, [PrincipalName1], [], false, false, null, true);

        // Assert.
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2 }, lsaUserRightsMockBuilder.Database.Keys.ToArray());
        CollectionAssert.AreEqual(new[] { Privilege1 }, lsaUserRightsMockBuilder.Database[PrincipalSid1]);
        CollectionAssert.AreEqual(new[] { Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid2]);

        lsaUserRights.Verify(x => x.LsaEnumerateAccountsWithUserRight(It.Is<string>(s => string.Equals(s, Privilege2, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies granting a privilege to a principal and revoking the privilege from another principal works as expected.
    /// </summary>
    [TestMethod]
    public void ModifyPrivilege_WithGrantAndRevoke_ShouldWork()
    {
        // Arrange.
        var lsaUserRightsMockBuilder = LsaUserRightsMockBuilder.CreateBuilder();
        var lsaUserRights = lsaUserRightsMockBuilder
            .WithGrant(PrincipalSid1, Privilege1)
            .WithGrant(PrincipalSid2, Privilege2)
            .Build();

        using var fixture = new UserRightsManagerFixture();

        // Act.
        fixture.UserRightsManager.ModifyPrivilege(lsaUserRights.Object, Privilege1, [PrincipalName2], [PrincipalName1], false, false, null, false);

        // Assert.
        CollectionAssert.AreEqual(new[] { PrincipalSid2 }, lsaUserRightsMockBuilder.Database.Keys.ToArray());
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid2]);

        lsaUserRights.Verify(x => x.LsaEnumerateAccountsWithUserRight(It.Is<string>(s => string.Equals(s, Privilege1, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaAddAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid2), It.Is<string>(s => string.Equals(s, Privilege1, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaRemoveAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid1), It.Is<string>(s => string.Equals(s, Privilege1, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies granting a privilege to a principal and revoking the privilege from another principal with dry run enabled works as expected.
    /// </summary>
    [TestMethod]
    public void ModifyPrivilege_WithGrantAndRevokeAndDryRun_ShouldWork()
    {
        // Arrange.
        var lsaUserRightsMockBuilder = LsaUserRightsMockBuilder.CreateBuilder();
        var lsaUserRights = lsaUserRightsMockBuilder
            .WithGrant(PrincipalSid1, Privilege1)
            .WithGrant(PrincipalSid2, Privilege2)
            .Build();

        using var fixture = new UserRightsManagerFixture();

        // Act.
        fixture.UserRightsManager.ModifyPrivilege(lsaUserRights.Object, Privilege1, [PrincipalName2], [PrincipalName1], false, false, null, true);

        // Assert.
        CollectionAssert.AreEquivalent(new[] { PrincipalSid2, PrincipalSid1 }, lsaUserRightsMockBuilder.Database.Keys.ToArray());
        CollectionAssert.AreEqual(new[] { Privilege1 }, lsaUserRightsMockBuilder.Database[PrincipalSid1]);
        CollectionAssert.AreEqual(new[] { Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid2]);

        lsaUserRights.Verify(x => x.LsaEnumerateAccountsWithUserRight(It.Is<string>(s => string.Equals(s, Privilege1, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies granting a privilege to a principal and revoking the privilege from all other principals works as expected.
    /// </summary>
    [TestMethod]
    public void ModifyPrivilege_WithGrantAndRevokeOthers_ShouldWork()
    {
        // Arrange.
        var lsaUserRightsMockBuilder = LsaUserRightsMockBuilder.CreateBuilder();
        var lsaUserRights = lsaUserRightsMockBuilder
            .WithGrant(PrincipalSid1, Privilege1)
            .WithGrant(PrincipalSid2, Privilege1, Privilege2)
            .Build();

        using var fixture = new UserRightsManagerFixture();

        // Act.
        fixture.UserRightsManager.ModifyPrivilege(lsaUserRights.Object, Privilege2, [PrincipalName1], [], false, true, null, false);

        // Assert.
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2 }, lsaUserRightsMockBuilder.Database.Keys.ToArray());
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid1]);
        CollectionAssert.AreEqual(new[] { Privilege1 }, lsaUserRightsMockBuilder.Database[PrincipalSid2]);

        lsaUserRights.Verify(x => x.LsaEnumerateAccountsWithUserRight(It.Is<string>(s => string.Equals(s, Privilege2, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaRemoveAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid2), It.Is<string>(s => string.Equals(s, Privilege2, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaAddAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid1), It.Is<string>(s => string.Equals(s, Privilege2, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies granting a privilege to a principal and revoking the privilege from all other principals with dry run enabled works as expected.
    /// </summary>
    [TestMethod]
    public void ModifyPrivilege_WithGrantAndRevokeOthersAndDryRun_ShouldWork()
    {
        // Arrange.
        var lsaUserRightsMockBuilder = LsaUserRightsMockBuilder.CreateBuilder();
        var lsaUserRights = lsaUserRightsMockBuilder
            .WithGrant(PrincipalSid1, Privilege1)
            .WithGrant(PrincipalSid2, Privilege1, Privilege2)
            .Build();

        using var fixture = new UserRightsManagerFixture();

        // Act.
        fixture.UserRightsManager.ModifyPrivilege(lsaUserRights.Object, Privilege2, [PrincipalName1], [], false, true, null, true);

        // Assert.
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2 }, lsaUserRightsMockBuilder.Database.Keys.ToArray());
        CollectionAssert.AreEqual(new[] { Privilege1 }, lsaUserRightsMockBuilder.Database[PrincipalSid1]);
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid2]);

        lsaUserRights.Verify(x => x.LsaEnumerateAccountsWithUserRight(It.Is<string>(s => string.Equals(s, Privilege2, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies granting a privilege to a principal and revoking the privilege from all principals that match a pattern works as expected.
    /// </summary>
    [TestMethod]
    public void ModifyPrivilege_WithGrantAndRevokePattern_ShouldWork()
    {
        // Arrange.
        var lsaUserRightsMockBuilder = LsaUserRightsMockBuilder.CreateBuilder();
        var lsaUserRights = lsaUserRightsMockBuilder
            .WithGrant(PrincipalSidCurrent, Privilege1)
            .WithGrant(PrincipalSid1, Privilege2)
            .WithGrant(PrincipalSid2, Privilege1, Privilege2)
            .WithGrant(PrincipalSid3, Privilege1, Privilege2)
            .Build();

        using var fixture = new UserRightsManagerFixture();
        var pattern = new Regex("^S-1-5-21", RegexOptions.None, TimeSpan.FromSeconds(1));

        // Act.
        fixture.UserRightsManager.ModifyPrivilege(lsaUserRights.Object, Privilege1, [PrincipalName1], [], false, false, pattern, false);

        // Assert.
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2, PrincipalSid3 }, lsaUserRightsMockBuilder.Database.Keys.ToArray());
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid1]);
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid2]);
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid3]);

        lsaUserRights.Verify(x => x.LsaEnumerateAccountsWithUserRight(It.Is<string>(s => string.Equals(s, Privilege1, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaAddAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid1), It.Is<string>(s => string.Equals(s, Privilege1, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaRemoveAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSidCurrent), It.Is<string>(s => string.Equals(s, Privilege1, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies granting a privilege to a principal and revoking the privilege from all principals that match a pattern with dry run enabled works as expected.
    /// </summary>
    [TestMethod]
    public void ModifyPrivilege_WithGrantAndRevokePatternAndDryRun_ShouldWork()
    {
        // Arrange.
        var lsaUserRightsMockBuilder = LsaUserRightsMockBuilder.CreateBuilder();
        var lsaUserRights = lsaUserRightsMockBuilder
            .WithGrant(PrincipalSidCurrent, Privilege1)
            .WithGrant(PrincipalSid1, Privilege2)
            .WithGrant(PrincipalSid2, Privilege1, Privilege2)
            .WithGrant(PrincipalSid3, Privilege1, Privilege2)
            .Build();

        using var fixture = new UserRightsManagerFixture();
        var pattern = new Regex("^S-1-5-21", RegexOptions.None, TimeSpan.FromSeconds(1));

        // Act.
        fixture.UserRightsManager.ModifyPrivilege(lsaUserRights.Object, Privilege1, [PrincipalName1], [], false, false, pattern, true);

        // Assert.
        CollectionAssert.AreEquivalent(new[] { PrincipalSidCurrent, PrincipalSid1, PrincipalSid2, PrincipalSid3 }, lsaUserRightsMockBuilder.Database.Keys.ToArray());
        CollectionAssert.AreEqual(new[] { Privilege1 }, lsaUserRightsMockBuilder.Database[PrincipalSidCurrent]);
        CollectionAssert.AreEqual(new[] { Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid1]);
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid2]);
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid3]);

        lsaUserRights.Verify(x => x.LsaEnumerateAccountsWithUserRight(It.Is<string>(s => string.Equals(s, Privilege1, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies revoking a privilege from a principal works as expected.
    /// </summary>
    [TestMethod]
    public void ModifyPrivilege_WithRevoke_ShouldWork()
    {
        // Arrange.
        var lsaUserRightsMockBuilder = LsaUserRightsMockBuilder.CreateBuilder();
        var lsaUserRights = lsaUserRightsMockBuilder
            .WithGrant(PrincipalSid1, Privilege1)
            .WithGrant(PrincipalSid2, Privilege1, Privilege2)
            .Build();

        using var fixture = new UserRightsManagerFixture();

        // Act.
        fixture.UserRightsManager.ModifyPrivilege(lsaUserRights.Object, Privilege1, [], [PrincipalName2], false, false, null, false);

        // Assert.
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2 }, lsaUserRightsMockBuilder.Database.Keys.ToArray());
        CollectionAssert.AreEqual(new[] { Privilege1 }, lsaUserRightsMockBuilder.Database[PrincipalSid1]);
        CollectionAssert.AreEqual(new[] { Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid2]);

        lsaUserRights.Verify(x => x.LsaEnumerateAccountsWithUserRight(It.Is<string>(s => string.Equals(s, Privilege1, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaRemoveAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid2), It.Is<string>(s => string.Equals(s, Privilege1, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies revoking a privilege from a principal with dry run enabled works as expected.
    /// </summary>
    [TestMethod]
    public void ModifyPrivilege_WithRevokeAndDryRun_ShouldWork()
    {
        // Arrange.
        var lsaUserRightsMockBuilder = LsaUserRightsMockBuilder.CreateBuilder();
        var lsaUserRights = lsaUserRightsMockBuilder
            .WithGrant(PrincipalSid1, Privilege1)
            .WithGrant(PrincipalSid2, Privilege1, Privilege2)
            .Build();

        using var fixture = new UserRightsManagerFixture();

        // Act.
        fixture.UserRightsManager.ModifyPrivilege(lsaUserRights.Object, Privilege1, [], [PrincipalName2], false, false, null, true);

        // Assert.
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2 }, lsaUserRightsMockBuilder.Database.Keys.ToArray());
        CollectionAssert.AreEqual(new[] { Privilege1 }, lsaUserRightsMockBuilder.Database[PrincipalSid1]);
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid2]);

        lsaUserRights.Verify(x => x.LsaEnumerateAccountsWithUserRight(It.Is<string>(s => string.Equals(s, Privilege1, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies revoking a privilege from all principals works as expected.
    /// </summary>
    [TestMethod]
    public void ModifyPrivilege_WithRevokeAll_ShouldWork()
    {
        // Arrange.
        var lsaUserRightsMockBuilder = LsaUserRightsMockBuilder.CreateBuilder();
        var lsaUserRights = lsaUserRightsMockBuilder
            .WithGrant(PrincipalSid1, Privilege1)
            .WithGrant(PrincipalSid2, Privilege1, Privilege2)
            .Build();

        using var fixture = new UserRightsManagerFixture();

        // Act.
        fixture.UserRightsManager.ModifyPrivilege(lsaUserRights.Object, Privilege1, [], [], true, false, null, false);

        // Assert.
        CollectionAssert.AreEqual(new[] { PrincipalSid2 }, lsaUserRightsMockBuilder.Database.Keys.ToArray());
        CollectionAssert.AreEqual(new[] { Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid2]);

        lsaUserRights.Verify(x => x.LsaEnumerateAccountsWithUserRight(It.Is<string>(s => string.Equals(s, Privilege1, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaRemoveAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid1), It.Is<string>(s => string.Equals(s, Privilege1, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaRemoveAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid2), It.Is<string>(s => string.Equals(s, Privilege1, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies revoking a privilege from all principals with dry run enabled works as expected.
    /// </summary>
    [TestMethod]
    public void ModifyPrivilege_WithRevokeAllAndDryRun_ShouldWork()
    {
        // Arrange.
        var lsaUserRightsMockBuilder = LsaUserRightsMockBuilder.CreateBuilder();
        var lsaUserRights = lsaUserRightsMockBuilder
            .WithGrant(PrincipalSid1, Privilege1)
            .WithGrant(PrincipalSid2, Privilege1, Privilege2)
            .Build();

        using var fixture = new UserRightsManagerFixture();

        // Act.
        fixture.UserRightsManager.ModifyPrivilege(lsaUserRights.Object, Privilege1, [], [], true, false, null, true);

        // Assert.
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2 }, lsaUserRightsMockBuilder.Database.Keys.ToArray());
        CollectionAssert.AreEqual(new[] { Privilege1 }, lsaUserRightsMockBuilder.Database[PrincipalSid1]);
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid2]);

        lsaUserRights.Verify(x => x.LsaEnumerateAccountsWithUserRight(It.Is<string>(s => string.Equals(s, Privilege1, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies revoking a privilege from all principals that match a pattern works as expected.
    /// </summary>
    [TestMethod]
    public void ModifyPrivilege_WithRevokePattern_ShouldWork()
    {
        // Arrange.
        var lsaUserRightsMockBuilder = LsaUserRightsMockBuilder.CreateBuilder();
        var lsaUserRights = lsaUserRightsMockBuilder
            .WithGrant(PrincipalSidCurrent, Privilege1)
            .WithGrant(PrincipalSid1, Privilege2)
            .WithGrant(PrincipalSid2, Privilege1, Privilege2)
            .WithGrant(PrincipalSid3, Privilege1, Privilege2)
            .Build();

        using var fixture = new UserRightsManagerFixture();
        var pattern = new Regex("^S-1-5-21", RegexOptions.None, TimeSpan.FromSeconds(1));

        // Act.
        fixture.UserRightsManager.ModifyPrivilege(lsaUserRights.Object, Privilege1, [], [], false, false, pattern, false);

        // Assert.
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2, PrincipalSid3 }, lsaUserRightsMockBuilder.Database.Keys.ToArray());
        CollectionAssert.AreEqual(new[] { Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid1]);
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid2]);
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid3]);

        lsaUserRights.Verify(x => x.LsaEnumerateAccountsWithUserRight(It.Is<string>(s => string.Equals(s, Privilege1, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaRemoveAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSidCurrent), It.Is<string>(s => string.Equals(s, Privilege1, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies revoking a privilege from all principals that match a pattern with dry run enabled works as expected.
    /// </summary>
    [TestMethod]
    public void ModifyPrivilege_WithRevokePatternAndDryRun_ShouldWork()
    {
        // Arrange.
        var lsaUserRightsMockBuilder = LsaUserRightsMockBuilder.CreateBuilder();
        var lsaUserRights = lsaUserRightsMockBuilder
            .WithGrant(PrincipalSidCurrent, Privilege1)
            .WithGrant(PrincipalSid1, Privilege2)
            .WithGrant(PrincipalSid2, Privilege1, Privilege2)
            .WithGrant(PrincipalSid3, Privilege1, Privilege2)
            .Build();

        using var fixture = new UserRightsManagerFixture();
        var pattern = new Regex("^S-1-5-21", RegexOptions.None, TimeSpan.FromSeconds(1));

        // Act.
        fixture.UserRightsManager.ModifyPrivilege(lsaUserRights.Object, Privilege1, [], [], false, false, pattern, true);

        // Assert.
        CollectionAssert.AreEquivalent(new[] { PrincipalSidCurrent, PrincipalSid1, PrincipalSid2, PrincipalSid3 }, lsaUserRightsMockBuilder.Database.Keys.ToArray());
        CollectionAssert.AreEqual(new[] { Privilege1 }, lsaUserRightsMockBuilder.Database[PrincipalSidCurrent]);
        CollectionAssert.AreEqual(new[] { Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid1]);
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid2]);
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid3]);

        lsaUserRights.Verify(x => x.LsaEnumerateAccountsWithUserRight(It.Is<string>(s => string.Equals(s, Privilege1, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.VerifyNoOtherCalls();
    }
}