namespace Tests.Application;

using System.Security.Principal;
using UserRights.Application;
using Xunit;

/// <summary>
/// Represents tests for <see cref="LsaUserRights"/> grant functionality.
/// </summary>
[Collection("lsa")]
public sealed class LsaUserRightsGrantPrivilegeTests : LsaUserRightsTestBase
{
    /// <summary>
    /// Tests granting a privilege.
    /// </summary>
    /// <remarks>
    /// We assume the BUILTIN\Users group is not granted the SeTakeOwnershipPrivilege privilege.
    /// </remarks>
    [AdminOnlyFact]
    public void GrantPrivilegeShouldWork()
    {
        const string privilege = "SeMachineAccountPrivilege";
        const string sid = "S-1-5-32-545";
        var securityIdentifier = new SecurityIdentifier(sid);

        if (this.InitialState.TryGetValue(privilege, out var initial))
        {
            Assert.DoesNotContain(securityIdentifier, initial);
        }

        using var policy = new LsaUserRights();
        policy.Connect(null);
        policy.GrantPrivilege(securityIdentifier, privilege);

        var current = this.GetCurrentState();

        current.TryGetValue(privilege, out var collection);

        Assert.NotNull(collection);
        Assert.Contains(securityIdentifier, collection);
    }

    /// <summary>
    /// Tests granting a privilege without connecting throws an exception.
    /// </summary>
    [AdminOnlyFact]
    public void GrantPrivilegeWithoutConnectingThrowsException()
    {
        const string privilege = "SeMachineAccountPrivilege";
        const string sid = "S-1-5-32-545";
        var securityIdentifier = new SecurityIdentifier(sid);

        using var policy = new LsaUserRights();

        Assert.Throws<InvalidOperationException>(() => policy.GrantPrivilege(securityIdentifier, privilege));
    }
}