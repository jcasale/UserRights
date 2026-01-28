namespace Tests.Application;

using System.Security.Principal;

using Moq;

using static Tests.OptionsTestData;
using static Tests.TestData;

/// <summary>
/// Represents tests for modifying the principals for a specified user right.
/// </summary>
[TestClass]
public class UserRightsManagerPrivilegeTests
{
    /// <summary>
    /// Verifies modifying a privilege with a null policy argument throws an exception.
    /// </summary>
    [TestMethod]
    public void ModifyPrivilege_WithNullPolicy_ThrowsException()
    {
        // Arrange.
        var lsaUserRights = LsaUserRightsMockBuilder.CreateBuilder().Build();
        using var fixture = new UserRightsManagerFixture();

        // Act & Assert.
        Assert.Throws<ArgumentException>(() => fixture.UserRightsManager.ModifyPrivilege(null!, Privilege1, [PrincipalName1], [], false, false, null, false));

        lsaUserRights.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies modifying a privilege with null grants throws an exception.
    /// </summary>
    [TestMethod]
    public void ModifyPrivilege_WithNullGrants_ThrowsException()
    {
        // Arrange.
        var lsaUserRights = LsaUserRightsMockBuilder.CreateBuilder().Build();
        using var fixture = new UserRightsManagerFixture();

        // Act & Assert.
        Assert.Throws<ArgumentException>(() => fixture.UserRightsManager.ModifyPrivilege(lsaUserRights.Object, Privilege1, null!, [], false, false, null, false));

        lsaUserRights.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies modifying a privilege with null revocations throws an exception.
    /// </summary>
    [TestMethod]
    public void ModifyPrivilege_WithNullRevocations_ThrowsException()
    {
        // Arrange.
        var lsaUserRights = LsaUserRightsMockBuilder.CreateBuilder().Build();
        using var fixture = new UserRightsManagerFixture();

        // Act & Assert.
        Assert.Throws<ArgumentException>(() => fixture.UserRightsManager.ModifyPrivilege(lsaUserRights.Object, Privilege1, [], null!, false, false, null, false));

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
    /// <param name="description">The test case description.</param>
    [TestMethod]
    [DynamicData(nameof(PrivilegeInvalidArgumentData), typeof(OptionsTestData))]
    public void ModifyPrivilege_WithInvalidArguments_ThrowsException(string privilege, string[] grants, string[] revocations, bool revokeAll, bool revokeOthers, string revokePattern, string description)
    {
        // Arrange.
        var lsaUserRights = LsaUserRightsMockBuilder.CreateBuilder().Build();
        using var fixture = new UserRightsManagerFixture();

        // Act & Assert.
        Assert.Throws<ArgumentException>(
            () => fixture.UserRightsManager.ModifyPrivilege(lsaUserRights.Object, privilege, grants, revocations, revokeAll, revokeOthers, revokePattern, false),
            description);

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
        const string pattern = "^S-1-5-21";

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
        const string pattern = "^S-1-5-21";

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
        const string pattern = "^S-1-5-21";

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
        const string pattern = "^S-1-5-21";

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