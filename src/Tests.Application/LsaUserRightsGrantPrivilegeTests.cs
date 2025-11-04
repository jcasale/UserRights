namespace Tests.Application;

using System.Security.Principal;

using UserRights.Application;

using static Tests.PrivilegeConstants;
using static Tests.SecurityIdentifierConstants;

/// <summary>
/// Represents tests for <see cref="LsaUserRights"/> grant functionality.
/// </summary>
[TestClass]
[DoNotParallelize]
public sealed class LsaUserRightsGrantPrivilegeTests : LsaUserRightsSnapshotFixture
{
    /// <summary>
    /// Tests granting a privilege.
    /// </summary>
    /// <remarks>
    /// The test verifies that the BUILTIN\Users group is not assigned the SeTakeOwnershipPrivilege user right.
    /// </remarks>
    [TestMethod]
    [RunWhenElevated]
    public void GrantPrivilegeShouldWork()
    {
        // Arrange.
        var securityIdentifier = new SecurityIdentifier(Users);

        InitialState.TryGetValue(SeMachineAccountPrivilege, out var initial);
        Assert.DoesNotContain(securityIdentifier, initial ?? []);

        // Act.
        using var policy = new LsaUserRights();
        policy.Connect();
        policy.LsaAddAccountRights(securityIdentifier, SeMachineAccountPrivilege);

        var current = GetCurrentState();

        current.TryGetValue(SeMachineAccountPrivilege, out var collection);

        // Assert.
        Assert.IsNotNull(collection);
        Assert.Contains(securityIdentifier, collection);
    }

    /// <summary>
    /// Tests granting a privilege without connecting throws an exception.
    /// </summary>
    [TestMethod]
    [RunWhenElevated]
    public void GrantPrivilegeWithoutConnectingThrowsException()
    {
        // Arrange.
        var securityIdentifier = new SecurityIdentifier(Users);

        // Act.
        using var policy = new LsaUserRights();

        // Assert.
        Assert.Throws<InvalidOperationException>(() => policy.LsaAddAccountRights(securityIdentifier, SeMachineAccountPrivilege));
    }
}