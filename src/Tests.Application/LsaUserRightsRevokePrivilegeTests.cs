namespace Tests.Application;

using System.Security.Principal;
using UserRights.Application;
using Xunit;

/// <summary>
/// Represents tests for <see cref="LsaUserRights"/> revoke functionality.
/// </summary>
[Collection("lsa")]
public sealed class LsaUserRightsRevokePrivilegeTests : LsaUserRightsTestBase
{
    /// <summary>
    /// Tests revoking a privilege.
    /// </summary>
    /// <remarks>
    /// We assume the BUILTIN\Backup Operators is granted the SeBackupPrivilege privilege.
    /// </remarks>
    [AdminOnlyFact]
    public void RevokePrivilegeShouldWork()
    {
        const string privilege = "SeBackupPrivilege";
        const string sid = "S-1-5-32-551";
        var securityIdentifier = new SecurityIdentifier(sid);

        this.InitialState.TryGetValue(privilege, out var initial);

        Assert.NotNull(initial);
        Assert.Contains(securityIdentifier, initial);

        using var policy = new LsaUserRights();
        policy.Connect(null);
        policy.RevokePrivilege(securityIdentifier, privilege);

        var current = this.GetCurrentState();

        if (current.TryGetValue(privilege, out var collection))
        {
            Assert.DoesNotContain(securityIdentifier, collection);
        }
    }

    /// <summary>
    /// Tests revoking a privilege without connecting throws an exception.
    /// </summary>
    [AdminOnlyFact]
    public void RevokePrivilegeWithoutConnectingThrowsException()
    {
        const string privilege = "SeMachineAccountPrivilege";
        const string sid = "S-1-5-32-545";
        var securityIdentifier = new SecurityIdentifier(sid);

        using var policy = new LsaUserRights();

        Assert.Throws<InvalidOperationException>(() => policy.RevokePrivilege(securityIdentifier, privilege));
    }
}