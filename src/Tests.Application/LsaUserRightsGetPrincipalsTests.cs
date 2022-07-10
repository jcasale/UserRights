namespace Tests.Application;

using System.Security.Principal;
using UserRights.Application;
using Xunit;

/// <summary>
/// Represents tests for <see cref="LsaUserRights"/> list functionality.
/// </summary>
[Collection("lsa")]
public sealed class LsaUserRightsGetPrincipalsTests : LsaUserRightsTestBase
{
    /// <summary>
    /// Tests listing all the principals assigned to all privileges.
    /// </summary>
    [AdminOnlyFact]
    public void GetPrincipalsShouldWork()
    {
        var expected = this.InitialState.Values
            .SelectMany(p => p)
            .Distinct()
            .OrderBy(p => p)
            .ToArray();

        using var policy = new LsaUserRights();
        policy.Connect(null);

        var actual = policy.GetPrincipals()
            .OrderBy(p => p)
            .ToArray();

        Assert.Equal(expected, actual);
    }

    /// <summary>
    /// Tests listing the principals assigned to a single privilege.
    /// </summary>
    /// <remarks>
    /// We assume the BUILTIN\Administrators group is granted the SeTakeOwnershipPrivilege privilege.
    /// </remarks>
    [AdminOnlyFact]
    public void GetPrincipalsSinglePrivilegeShouldWork()
    {
        const string privilege = "SeTakeOwnershipPrivilege";
        const string sid = "S-1-5-32-544";
        var securityIdentifier = new SecurityIdentifier(sid);

        using var policy = new LsaUserRights();
        policy.Connect(null);

        var collection = policy.GetPrincipals(privilege).ToArray();

        Assert.Contains(securityIdentifier, collection);
    }

    /// <summary>
    /// Tests listing all the principals assigned to all privileges without connecting throws an exception.
    /// </summary>
    [AdminOnlyFact]
    public void GetPrincipalsWithoutConnectingThrowsException()
    {
        using var policy = new LsaUserRights();

        Assert.Throws<InvalidOperationException>(() => policy.GetPrincipals().ToArray());
    }

    /// <summary>
    /// Tests listing the principals assigned to a single privilege without connecting throws an exception.
    /// </summary>
    [AdminOnlyFact]
    public void GetPrincipalsSinglePrivilegeWithoutConnectingThrowsException()
    {
        const string privilege = "SeTakeOwnershipPrivilege";

        using var policy = new LsaUserRights();

        Assert.Throws<InvalidOperationException>(() => policy.GetPrincipals(privilege).ToArray());
    }
}