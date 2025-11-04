namespace Tests.Application;

using System.Security.Principal;

using UserRights.Application;

using static Tests.PrivilegeConstants;
using static Tests.SecurityIdentifierConstants;

/// <summary>
/// Represents tests for <see cref="LsaUserRights"/> revoke functionality.
/// </summary>
[TestClass]
[DoNotParallelize]
public sealed class LsaUserRightsRevokePrivilegeTests : LsaUserRightsSnapshotFixture
{
    /// <summary>
    /// Tests revoking a privilege.
    /// </summary>
    /// <remarks>
    /// The test requires that the BUILTIN\Backup Operators group is assigned the SeBackupPrivilege user right.
    /// </remarks>
    [TestMethod]
    [RunWhenElevated]
    public void RevokePrivilegeShouldWork()
    {
        // Arrange.
        var securityIdentifier = new SecurityIdentifier(BackupOperators);

        InitialState.TryGetValue(SeBackupPrivilege, out var initial);

        Assert.IsNotNull(initial);
        Assert.Contains(securityIdentifier, initial);

        // Act.
        using var policy = new LsaUserRights();
        policy.Connect();
        policy.LsaRemoveAccountRights(securityIdentifier, SeBackupPrivilege);

        var current = GetCurrentState();

        current.TryGetValue(SeBackupPrivilege, out var collection);

        // Assert.
        Assert.DoesNotContain(securityIdentifier, collection ?? []);
    }

    /// <summary>
    /// Tests revoking a privilege without connecting throws an exception.
    /// </summary>
    [TestMethod]
    [RunWhenElevated]
    public void RevokePrivilegeWithoutConnectingThrowsException()
    {
        // Arrange.
        var securityIdentifier = new SecurityIdentifier(BackupOperators);

        // Act.
        using var policy = new LsaUserRights();

        // Assert.
        Assert.Throws<InvalidOperationException>(() => policy.LsaRemoveAccountRights(securityIdentifier, SeBackupPrivilege));
    }
}