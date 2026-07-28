namespace Tests.Application;

using System.Security.Principal;

using Moq;

using static Tests.TestData;
using static Tests.ValidateParametersTestData;

/// <summary>
/// Represents tests for modifying the user rights for a specified principal.
/// </summary>
[TestClass]
public class UserRightsManagerPrincipalTests
{
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
        Assert.AreSequenceEqual([PrincipalSid1, PrincipalSid2], [.. lsaUserRightsMockBuilder.Database.Keys], SequenceOrder.InAnyOrder);
        Assert.AreSequenceEqual([Privilege1, Privilege2], lsaUserRightsMockBuilder.Database[PrincipalSid1], StringComparer.Ordinal, SequenceOrder.InAnyOrder);
        Assert.AreSequenceEqual([Privilege1, Privilege2], lsaUserRightsMockBuilder.Database[PrincipalSid2], StringComparer.Ordinal, SequenceOrder.InAnyOrder);

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
        Assert.AreSequenceEqual([PrincipalSid1, PrincipalSid2], [.. lsaUserRightsMockBuilder.Database.Keys], SequenceOrder.InAnyOrder);
        Assert.AreSequenceEqual([Privilege1], lsaUserRightsMockBuilder.Database[PrincipalSid1], StringComparer.Ordinal);
        Assert.AreSequenceEqual([Privilege1, Privilege2], lsaUserRightsMockBuilder.Database[PrincipalSid2], StringComparer.Ordinal, SequenceOrder.InAnyOrder);

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
        Assert.AreSequenceEqual([PrincipalSid1, PrincipalSid2], [.. lsaUserRightsMockBuilder.Database.Keys], SequenceOrder.InAnyOrder);
        Assert.AreSequenceEqual([Privilege2], lsaUserRightsMockBuilder.Database[PrincipalSid1], StringComparer.Ordinal);
        Assert.AreSequenceEqual([Privilege1, Privilege2], lsaUserRightsMockBuilder.Database[PrincipalSid2], StringComparer.Ordinal, SequenceOrder.InAnyOrder);

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
        Assert.AreSequenceEqual([PrincipalSid1, PrincipalSid2], [.. lsaUserRightsMockBuilder.Database.Keys], SequenceOrder.InAnyOrder);
        Assert.AreSequenceEqual([Privilege1], lsaUserRightsMockBuilder.Database[PrincipalSid1], StringComparer.Ordinal);
        Assert.AreSequenceEqual([Privilege1, Privilege2], lsaUserRightsMockBuilder.Database[PrincipalSid2], StringComparer.Ordinal, SequenceOrder.InAnyOrder);

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
        Assert.AreSequenceEqual([PrincipalSid1, PrincipalSid2], [.. lsaUserRightsMockBuilder.Database.Keys], SequenceOrder.InAnyOrder);
        Assert.AreSequenceEqual([Privilege2], lsaUserRightsMockBuilder.Database[PrincipalSid1], StringComparer.Ordinal);
        Assert.AreSequenceEqual([Privilege1, Privilege2], lsaUserRightsMockBuilder.Database[PrincipalSid2], StringComparer.Ordinal, SequenceOrder.InAnyOrder);

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
        Assert.AreSequenceEqual([PrincipalSid1, PrincipalSid2], [.. lsaUserRightsMockBuilder.Database.Keys], SequenceOrder.InAnyOrder);
        Assert.AreSequenceEqual([Privilege1], lsaUserRightsMockBuilder.Database[PrincipalSid1], StringComparer.Ordinal);
        Assert.AreSequenceEqual([Privilege1, Privilege2], lsaUserRightsMockBuilder.Database[PrincipalSid2], StringComparer.Ordinal, SequenceOrder.InAnyOrder);

        lsaUserRights.Verify(x => x.LsaEnumerateAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid1)), Times.Exactly(1));
        lsaUserRights.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies modifying a principal with a null policy argument throws an exception.
    /// </summary>
    [TestMethod]
    public void ModifyPrincipal_WithNullPolicy_ThrowsException()
    {
        // Arrange.
        using var fixture = new UserRightsManagerFixture();

        // Act & Assert.
        Assert.Throws<ArgumentException>(() => fixture.UserRightsManager.ModifyPrincipal(null!, PrincipalName1, [Privilege1], [], false, false, false));
    }

    /// <summary>
    /// Verifies modifying a principal with null grants throws an exception.
    /// </summary>
    [TestMethod]
    public void ModifyPrincipal_WithNullGrants_ThrowsException()
    {
        // Arrange.
        var lsaUserRights = LsaUserRightsMockBuilder.CreateBuilder().Build();
        using var fixture = new UserRightsManagerFixture();

        // Act & Assert.
        Assert.Throws<ArgumentException>(() => fixture.UserRightsManager.ModifyPrincipal(lsaUserRights.Object, PrincipalName1, null!, [], false, false, false));

        lsaUserRights.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies modifying a principal with null revocations throws an exception.
    /// </summary>
    [TestMethod]
    public void ModifyPrincipal_WithNullRevocations_ThrowsException()
    {
        // Arrange.
        var lsaUserRights = LsaUserRightsMockBuilder.CreateBuilder().Build();
        using var fixture = new UserRightsManagerFixture();

        // Act & Assert.
        Assert.Throws<ArgumentException>(() => fixture.UserRightsManager.ModifyPrincipal(lsaUserRights.Object, PrincipalName1, [], null!, false, false, false));

        lsaUserRights.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies modifying a principal with invalid arguments throws an exception.
    /// </summary>
    /// <param name="principal">The principal to modify.</param>
    /// <param name="grants">The privileges to grant to the principal.</param>
    /// <param name="revocations">The privileges to revoke from the principal.</param>
    /// <param name="revokeAll">Revokes all privileges from the principal.</param>
    /// <param name="revokeOthers">Revokes all privileges from the principal excluding those being granted.</param>
    /// <param name="description">The test case description.</param>
    [TestMethod]
    [DynamicData(nameof(PrincipalInvalidArgumentData), typeof(ValidateParametersTestData))]
    public void ModifyPrincipal_WithInvalidArguments_ThrowsException(string principal, string[] grants, string[] revocations, bool revokeAll, bool revokeOthers, string description)
    {
        // Arrange.
        var lsaUserRights = LsaUserRightsMockBuilder.CreateBuilder().Build();

        using var fixture = new UserRightsManagerFixture();

        // Act & Assert.
        Assert.Throws<ArgumentException>(
            () => fixture.UserRightsManager.ModifyPrincipal(lsaUserRights.Object, principal, grants, revocations, revokeAll, revokeOthers, false),
            description);

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
        Assert.AreSequenceEqual([PrincipalSid1, PrincipalSid2], [.. lsaUserRightsMockBuilder.Database.Keys], SequenceOrder.InAnyOrder);
        Assert.AreSequenceEqual([Privilege1], lsaUserRightsMockBuilder.Database[PrincipalSid1], StringComparer.Ordinal);
        Assert.AreSequenceEqual([Privilege1], lsaUserRightsMockBuilder.Database[PrincipalSid2], StringComparer.Ordinal);

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
        Assert.AreSequenceEqual([PrincipalSid2], [.. lsaUserRightsMockBuilder.Database.Keys]);
        Assert.AreSequenceEqual([Privilege1, Privilege2], lsaUserRightsMockBuilder.Database[PrincipalSid2], StringComparer.Ordinal, SequenceOrder.InAnyOrder);

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
        Assert.AreSequenceEqual([PrincipalSid1, PrincipalSid2], [.. lsaUserRightsMockBuilder.Database.Keys], SequenceOrder.InAnyOrder);
        Assert.AreSequenceEqual([Privilege1], lsaUserRightsMockBuilder.Database[PrincipalSid1], StringComparer.Ordinal);
        Assert.AreSequenceEqual([Privilege1, Privilege2], lsaUserRightsMockBuilder.Database[PrincipalSid2], StringComparer.Ordinal, SequenceOrder.InAnyOrder);

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
        Assert.AreSequenceEqual([PrincipalSid1, PrincipalSid2], [.. lsaUserRightsMockBuilder.Database.Keys], SequenceOrder.InAnyOrder);
        Assert.AreSequenceEqual([Privilege1], lsaUserRightsMockBuilder.Database[PrincipalSid1], StringComparer.Ordinal);
        Assert.AreSequenceEqual([Privilege1, Privilege2], lsaUserRightsMockBuilder.Database[PrincipalSid2], StringComparer.Ordinal, SequenceOrder.InAnyOrder);

        lsaUserRights.Verify(x => x.LsaEnumerateAccountRights(It.Is<SecurityIdentifier>(s => s == PrincipalSid2)), Times.Exactly(1));
        lsaUserRights.VerifyNoOtherCalls();
    }
}