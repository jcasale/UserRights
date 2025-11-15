namespace Tests.Application;

using System.Security.Principal;

using Moq;

using static Tests.TestData;

/// <summary>
/// Represents tests for modifying the user rights for a specified principal.
/// </summary>
[TestClass]
public class UserRightsManagerPrincipalTests
{
    /// <summary>
    /// Gets invalid method arguments for the modify principal unit test.
    /// </summary>
    public static IEnumerable<(string Principal, string[] Grants, string[] Revocations, bool RevokeAll, bool RevokeOthers, bool DryRun)> InvalidArgumentData =>
    [
        // Verify null or empty principal.
        new(null!, [Privilege1], [], false, false, false),
        new(string.Empty, [Privilege1], [], false, false, false),

        // Verify null grant collection.
        new(PrincipalName1, null!, [Privilege1], false, false, false),

        // Verify null revocation collection.
        new(PrincipalName1, [Privilege1], null!, false, false, false),

        // Verify RevokeAll requirements.
        new(PrincipalName1, [Privilege1], [], true, false, false),
        new(PrincipalName1, [], [Privilege1], true, false, false),
        new(PrincipalName1, [], [], true, true, false),

        // Verify RevokeOthers requirements.
        new(PrincipalName1, [Privilege1], [], true, true, false),
        new(PrincipalName1, [], [], false, true, false),
        new(PrincipalName1, [Privilege1], [Privilege2], false, true, false),

        // Verify remaining requirements.
        new(PrincipalName1, [], [], false, false, false),

        // Verify grant and revocation set restrictions.
        new(PrincipalName1, [Privilege1], [Privilege1], false, false, false),
        new(PrincipalName1, [Privilege1, Privilege1], [], false, false, false),
        new(PrincipalName1, [], [Privilege1, Privilege1], false, false, false)
    ];

    /// <summary>
    /// Verifies granting a privilege works as expected.
    /// </summary>
    [TestMethod]
    public void ModifyPrincipal_WithGrant_ShouldWork()
    {
        // Arrange.
        var lsaUserRightsMockBuilder = LsaUserRightsMockBuilder.CreateBuilder();
        var lsaUserRights = lsaUserRightsMockBuilder
            .WithGrant(PrincipalSid1, Privilege1)
            .WithGrant(PrincipalSid2, Privilege1, Privilege2)
            .Build();

        using var fixture = new UserRightsManagerFixture();

        // Act.
        fixture.UserRightsManager.ModifyPrincipal(lsaUserRights.Object, PrincipalName1, [Privilege2], [], false, false, false);

        // Assert.
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2 }, lsaUserRightsMockBuilder.Database.Keys.ToArray());
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid1]);
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid2]);

        lsaUserRights.Verify(x => x.LsaEnumerateAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid1)), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaAddAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid1), It.Is<string>(s => string.Equals(s, Privilege2, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies granting a privilege with dry run enabled works as expected.
    /// </summary>
    [TestMethod]
    public void ModifyPrincipal_WithGrantAndDryRun_ShouldWork()
    {
        // Arrange.
        var lsaUserRightsMockBuilder = LsaUserRightsMockBuilder.CreateBuilder();
        var lsaUserRights = lsaUserRightsMockBuilder
            .WithGrant(PrincipalSid1, Privilege1)
            .WithGrant(PrincipalSid2, Privilege1, Privilege2)
            .Build();

        using var fixture = new UserRightsManagerFixture();

        // Act.
        fixture.UserRightsManager.ModifyPrincipal(lsaUserRights.Object, PrincipalName1, [Privilege2], [], false, false, true);

        // Assert.
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2 }, lsaUserRightsMockBuilder.Database.Keys.ToArray());
        CollectionAssert.AreEqual(new[] { Privilege1 }, lsaUserRightsMockBuilder.Database[PrincipalSid1]);
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid2]);

        lsaUserRights.Verify(x => x.LsaEnumerateAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid1)), Times.Exactly(1));
        lsaUserRights.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies granting and revoking a privilege from a principal works as expected.
    /// </summary>
    [TestMethod]
    public void ModifyPrincipal_WithGrantAndRevoke_ShouldWork()
    {
        // Arrange.
        var lsaUserRightsMockBuilder = LsaUserRightsMockBuilder.CreateBuilder();
        var lsaUserRights = lsaUserRightsMockBuilder
            .WithGrant(PrincipalSid1, Privilege1)
            .WithGrant(PrincipalSid2, Privilege1, Privilege2)
            .Build();

        using var fixture = new UserRightsManagerFixture();

        // Act.
        fixture.UserRightsManager.ModifyPrincipal(lsaUserRights.Object, PrincipalName1, [Privilege2], [Privilege1], false, false, false);

        // Assert.
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2 }, lsaUserRightsMockBuilder.Database.Keys.ToArray());
        CollectionAssert.AreEqual(new[] { Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid1]);
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid2]);

        lsaUserRights.Verify(x => x.LsaEnumerateAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid1)), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaRemoveAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid1), It.Is<string>(s => string.Equals(s, Privilege1, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaAddAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid1), It.Is<string>(s => string.Equals(s, Privilege2, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies granting and revoking a privilege from a principal with dry run enabled works as expected.
    /// </summary>
    [TestMethod]
    public void ModifyPrincipal_WithGrantAndRevokeAndDryRun_ShouldWork()
    {
        // Arrange.
        var lsaUserRightsMockBuilder = LsaUserRightsMockBuilder.CreateBuilder();
        var lsaUserRights = lsaUserRightsMockBuilder
            .WithGrant(PrincipalSid1, Privilege1)
            .WithGrant(PrincipalSid2, Privilege1, Privilege2)
            .Build();

        using var fixture = new UserRightsManagerFixture();

        // Act.
        fixture.UserRightsManager.ModifyPrincipal(lsaUserRights.Object, PrincipalName1, [Privilege2], [Privilege1], false, false, true);

        // Assert.
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2 }, lsaUserRightsMockBuilder.Database.Keys.ToArray());
        CollectionAssert.AreEqual(new[] { Privilege1 }, lsaUserRightsMockBuilder.Database[PrincipalSid1]);
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid2]);

        lsaUserRights.Verify(x => x.LsaEnumerateAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid1)), Times.Exactly(1));
        lsaUserRights.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies granting a privilege and revoking the other privileges from a principal works as expected.
    /// </summary>
    [TestMethod]
    public void ModifyPrincipal_WithGrantAndRevokeOthers_ShouldWork()
    {
        // Arrange.
        var lsaUserRightsMockBuilder = LsaUserRightsMockBuilder.CreateBuilder();
        var lsaUserRights = lsaUserRightsMockBuilder
            .WithGrant(PrincipalSid1, Privilege1)
            .WithGrant(PrincipalSid2, Privilege1, Privilege2)
            .Build();

        using var fixture = new UserRightsManagerFixture();

        // Act.
        fixture.UserRightsManager.ModifyPrincipal(lsaUserRights.Object, PrincipalName1, [Privilege2], [], false, true, false);

        // Assert.
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2 }, lsaUserRightsMockBuilder.Database.Keys.ToArray());
        CollectionAssert.AreEqual(new[] { Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid1]);
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid2]);

        lsaUserRights.Verify(x => x.LsaEnumerateAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid1)), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaRemoveAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid1), It.Is<string>(s => string.Equals(s, Privilege1, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaAddAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid1), It.Is<string>(s => string.Equals(s, Privilege2, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies granting a privilege and revoking the other privileges from a principal with dry run enabled works as expected.
    /// </summary>
    [TestMethod]
    public void ModifyPrincipal_WithGrantAndRevokeOthersAndDryRun_ShouldWork()
    {
        // Arrange.
        var lsaUserRightsMockBuilder = LsaUserRightsMockBuilder.CreateBuilder();
        var lsaUserRights = lsaUserRightsMockBuilder
            .WithGrant(PrincipalSid1, Privilege1)
            .WithGrant(PrincipalSid2, Privilege1, Privilege2)
            .Build();

        using var fixture = new UserRightsManagerFixture();

        // Act.
        fixture.UserRightsManager.ModifyPrincipal(lsaUserRights.Object, PrincipalName1, [Privilege2], [], false, true, true);

        // Assert.
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2 }, lsaUserRightsMockBuilder.Database.Keys.ToArray());
        CollectionAssert.AreEqual(new[] { Privilege1 }, lsaUserRightsMockBuilder.Database[PrincipalSid1]);
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid2]);

        lsaUserRights.Verify(x => x.LsaEnumerateAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid1)), Times.Exactly(1));
        lsaUserRights.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies modifying a principal with a null policy argument throws an exception.
    /// </summary>
    [TestMethod]
    public void ModifyPrincipal_WithInvalidArguments_ThrowsException()
    {
        // Arrange.
        using var fixture = new UserRightsManagerFixture();

        // Act & Assert.
        Assert.Throws<ArgumentException>(() => fixture.UserRightsManager.ModifyPrincipal(null!, PrincipalName1, [Privilege1], [], false, false, false));
    }

    /// <summary>
    /// Verifies modifying a principal with invalid arguments throws an exception.
    /// </summary>
    /// <param name="principal">The principal to modify.</param>
    /// <param name="grants">The privileges to grant to the principal.</param>
    /// <param name="revocations">The privileges to revoke from the principal.</param>
    /// <param name="revokeAll">Revokes all privileges from the principal.</param>
    /// <param name="revokeOthers">Revokes all privileges from the principal excluding those being granted.</param>
    /// <param name="dryRun">Enables dry-run mode.</param>
    [TestMethod]
    [DynamicData(nameof(InvalidArgumentData))]
    public void ModifyPrincipal_WithInvalidArguments_ThrowsException(string principal, string[] grants, string[] revocations, bool revokeAll, bool revokeOthers, bool dryRun)
    {
        // Arrange.
        var lsaUserRights = LsaUserRightsMockBuilder.CreateBuilder().Build();

        using var fixture = new UserRightsManagerFixture();

        // Act & Assert.
        Assert.Throws<ArgumentException>(() => fixture.UserRightsManager.ModifyPrincipal(lsaUserRights.Object, principal, grants, revocations, revokeAll, revokeOthers, dryRun));

        lsaUserRights.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies revoking a privilege from a principal works as expected.
    /// </summary>
    [TestMethod]
    public void ModifyPrincipal_WithRevoke_ShouldWork()
    {
        // Arrange.
        var lsaUserRightsMockBuilder = LsaUserRightsMockBuilder.CreateBuilder();
        var lsaUserRights = lsaUserRightsMockBuilder
            .WithGrant(PrincipalSid1, Privilege1)
            .WithGrant(PrincipalSid2, Privilege1, Privilege2)
            .Build();

        using var fixture = new UserRightsManagerFixture();

        // Act.
        fixture.UserRightsManager.ModifyPrincipal(lsaUserRights.Object, PrincipalName2, [], [Privilege2], false, false, false);

        // Assert.
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2 }, lsaUserRightsMockBuilder.Database.Keys.ToArray());
        CollectionAssert.AreEqual(new[] { Privilege1 }, lsaUserRightsMockBuilder.Database[PrincipalSid1]);
        CollectionAssert.AreEqual(new[] { Privilege1 }, lsaUserRightsMockBuilder.Database[PrincipalSid2]);

        lsaUserRights.Verify(x => x.LsaEnumerateAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid2)), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaRemoveAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid2), It.Is<string>(s => string.Equals(s, Privilege2, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies revoking all privileges from a principal works as expected.
    /// </summary>
    [TestMethod]
    public void ModifyPrincipal_WithRevokeAll_ShouldWork()
    {
        // Arrange.
        var lsaUserRightsMockBuilder = LsaUserRightsMockBuilder.CreateBuilder();
        var lsaUserRights = lsaUserRightsMockBuilder
            .WithGrant(PrincipalSid1, Privilege1)
            .WithGrant(PrincipalSid2, Privilege1, Privilege2)
            .Build();

        using var fixture = new UserRightsManagerFixture();

        // Act.
        fixture.UserRightsManager.ModifyPrincipal(lsaUserRights.Object, PrincipalName1, [], [], true, false, false);

        // Assert.
        CollectionAssert.AreEqual(new[] { PrincipalSid2 }, lsaUserRightsMockBuilder.Database.Keys.ToArray());
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid2]);

        lsaUserRights.Verify(x => x.LsaEnumerateAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid1)), Times.Exactly(1));
        lsaUserRights.Verify(x => x.LsaRemoveAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid1), It.Is<string>(s => string.Equals(s, Privilege1, StringComparison.Ordinal))), Times.Exactly(1));
        lsaUserRights.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies revoking all privileges from a principal works as expected.
    /// </summary>
    [TestMethod]
    public void ModifyPrincipal_WithRevokeAllAndDryRun_ShouldWork()
    {
        // Arrange.
        var lsaUserRightsMockBuilder = LsaUserRightsMockBuilder.CreateBuilder();
        var lsaUserRights = lsaUserRightsMockBuilder
            .WithGrant(PrincipalSid1, Privilege1)
            .WithGrant(PrincipalSid2, Privilege1, Privilege2)
            .Build();

        using var fixture = new UserRightsManagerFixture();

        // Act.
        fixture.UserRightsManager.ModifyPrincipal(lsaUserRights.Object, PrincipalName1, [], [], true, false, true);

        // Assert.
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2 }, lsaUserRightsMockBuilder.Database.Keys.ToArray());
        CollectionAssert.AreEqual(new[] { Privilege1 }, lsaUserRightsMockBuilder.Database[PrincipalSid1]);
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid2]);

        lsaUserRights.Verify(x => x.LsaEnumerateAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid1)), Times.Exactly(1));
        lsaUserRights.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies revoking a privilege from a principal with dry run enabled works as expected.
    /// </summary>
    [TestMethod]
    public void ModifyPrincipal_WithRevokeAndDryRun_ShouldWork()
    {
        // Arrange.
        var lsaUserRightsMockBuilder = LsaUserRightsMockBuilder.CreateBuilder();
        var lsaUserRights = lsaUserRightsMockBuilder
            .WithGrant(PrincipalSid1, Privilege1)
            .WithGrant(PrincipalSid2, Privilege1, Privilege2)
            .Build();

        using var fixture = new UserRightsManagerFixture();

        // Act.
        fixture.UserRightsManager.ModifyPrincipal(lsaUserRights.Object, PrincipalName2, [], [Privilege2], false, false, true);

        // Assert.
        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2 }, lsaUserRightsMockBuilder.Database.Keys.ToArray());
        CollectionAssert.AreEqual(new[] { Privilege1 }, lsaUserRightsMockBuilder.Database[PrincipalSid1]);
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, lsaUserRightsMockBuilder.Database[PrincipalSid2]);

        lsaUserRights.Verify(x => x.LsaEnumerateAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid2)), Times.Exactly(1));
        lsaUserRights.VerifyNoOtherCalls();
    }
}