namespace Tests.Application;

using System.Security.Principal;

using UserRights.Application;

using static Tests.PrivilegeConstants;
using static Tests.SecurityIdentifierConstants;

/// <summary>
/// Represents tests for <see cref="LsaUserRights"/> list functionality.
/// </summary>
[TestClass]
[DoNotParallelize]
public sealed class LsaUserRightsGetPrincipalsTests : LsaUserRightsSnapshotFixture
{
    /// <summary>
    /// Tests listing all the principals assigned to all privileges.
    /// </summary>
    [TestMethod]
    [RunWhenElevated]
    public void GetPrincipalsShouldWork()
    {
        // Arrange.
        var expected = InitialState.Values
            .SelectMany(p => p)
            .Distinct()
            .Order()
            .ToArray();

        using var policy = new LsaUserRights();
        policy.Connect();

        // Act.
        var actual = policy.LsaEnumerateAccountsWithUserRight()
            .Order()
            .ToArray();

        // Assert.
        CollectionAssert.AreEqual(expected, actual);
    }

    /// <summary>
    /// Tests listing the principals assigned to a single privilege.
    /// </summary>
    /// <remarks>
    /// The test verifies that the BUILTIN\Administrators group is assigned the SeTakeOwnershipPrivilege user right.
    /// </remarks>
    [TestMethod]
    [RunWhenElevated]
    public void GetPrincipalsSinglePrivilegeShouldWork()
    {
        // Arrange.
        var securityIdentifier = new SecurityIdentifier(Administrators);

        using var policy = new LsaUserRights();
        policy.Connect();

        // Act.
        var collection = policy.LsaEnumerateAccountsWithUserRight(SeTakeOwnershipPrivilege);

        // Assert.
        Assert.Contains(securityIdentifier, collection);
    }

    /// <summary>
    /// Tests listing all the principals assigned to all privileges without connecting throws an exception.
    /// </summary>
    [TestMethod]
    [RunWhenElevated]
    public void GetPrincipalsWithoutConnectingThrowsException()
    {
        // Arrange.
        using var policy = new LsaUserRights();

        // Act & Assert.
        Assert.Throws<InvalidOperationException>(() => policy.LsaEnumerateAccountsWithUserRight());
    }

    /// <summary>
    /// Tests listing the principals assigned to a single privilege without connecting throws an exception.
    /// </summary>
    [TestMethod]
    [RunWhenElevated]
    public void GetPrincipalsSinglePrivilegeWithoutConnectingThrowsException()
    {
        // Arrange.
        using var policy = new LsaUserRights();

        // Act & Assert.
        Assert.Throws<InvalidOperationException>(() => policy.LsaEnumerateAccountsWithUserRight(SeTakeOwnershipPrivilege));
    }
}