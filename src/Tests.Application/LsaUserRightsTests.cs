namespace Tests.Application;

using System.Security.Cryptography;
using System.Security.Principal;

using UserRights.Application;

using static Tests.PrivilegeConstants;
using static Tests.SecurityIdentifierConstants;

/// <summary>
/// Represents tests for interacting with the local security authority (LSA) database.
/// </summary>
[TestClass]
[DoNotParallelize]
public class LsaUserRightsTests
{
    /// <summary>
    /// Verifies connecting more than once will throw an exception.
    /// </summary>
    [TestMethod]
    [RunWhenElevated]
    public void Connect_WithConnectingMultipleTimes_ThrowsException()
    {
        // Arrange.
        using var policy = new LsaUserRights();
        policy.Connect();

        // Act & Assert.
        Assert.Throws<InvalidOperationException>(() => policy.Connect());
    }

    /// <summary>
    /// Verifies adding account rights works as expected.
    /// </summary>
    [TestMethod]
    [RunWhenElevated]
    public void LsaAddAccountRights_WithAccountAndPrivilege_ShouldWork()
    {
        // Arrange.
        using var fixture = new LsaUserRightsSnapshotFixture();

        var securityIdentifier = new SecurityIdentifier(Users);

        // Select a random user right that has not been assigned to the BUILTIN\Users group from the initial state.
        var (right, existingAccounts) = fixture.InitialState.First(kvp => !kvp.Value.Contains(securityIdentifier));

        Assert.DoesNotContain(securityIdentifier, existingAccounts);

        // Act.
        using var policy = new LsaUserRights();
        policy.Connect();
        policy.LsaAddAccountRights(securityIdentifier, right);

        var current = fixture.GetCurrentState();

        current.TryGetValue(right, out var updatedAccounts);

        // Assert.
        Assert.IsNotNull(updatedAccounts);
        Assert.Contains(securityIdentifier, updatedAccounts);
    }

    /// <summary>
    /// Verifies adding account rights without first connecting will throw an exception.
    /// </summary>
    [TestMethod]
    [RunWhenElevated]
    public void LsaAddAccountRights_WithAccountAndPrivilegeAndWithoutConnecting_ThrowsException()
    {
        // Arrange.
        using var fixture = new LsaUserRightsSnapshotFixture();

        var securityIdentifier = new SecurityIdentifier(Users);

        // Act.
        using var policy = new LsaUserRights();

        // Assert.
        Assert.Throws<InvalidOperationException>(() => policy.LsaAddAccountRights(securityIdentifier, SeMachineAccountPrivilege));
    }

    /// <summary>
    /// Verifies enumerating all accounts with user rights works as expected.
    /// </summary>
    [TestMethod]
    [RunWhenElevated]
    public void LsaEnumerateAccountsWithUserRight_ShouldWork()
    {
        // Arrange.
        using var fixture = new LsaUserRightsSnapshotFixture();

        var expected = fixture.InitialState.Values
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
    /// Verifies enumerating all accounts with user rights without first connecting will throw an exception.
    /// </summary>
    [TestMethod]
    [RunWhenElevated]
    public void LsaEnumerateAccountsWithUserRight_WithoutConnecting_ThrowsException()
    {
        // Arrange.
        using var policy = new LsaUserRights();

        // Act & Assert.
        Assert.Throws<InvalidOperationException>(() => policy.LsaEnumerateAccountsWithUserRight());
    }

    /// <summary>
    /// Verifies enumerating all accounts with a specific user right works as expected.
    /// </summary>
    [TestMethod]
    [RunWhenElevated]
    public void LsaEnumerateAccountsWithUserRight_WithPrivilege_ShouldWork()
    {
        // Arrange.
        using var fixture = new LsaUserRightsSnapshotFixture();

        // Select a random user right and the assigned accounts from the initial state.
        var (right, expected) = fixture.InitialState.ElementAt(RandomNumberGenerator.GetInt32(fixture.InitialState.Count));

        using var policy = new LsaUserRights();
        policy.Connect();

        // Act.
        var collection = policy.LsaEnumerateAccountsWithUserRight(right);

        // Assert.
        CollectionAssert.AreEquivalent(expected.ToArray(), collection);
    }

    /// <summary>
    /// Verifies enumerating accounts with a specific user right without first connecting will throw an exception.
    /// </summary>
    [TestMethod]
    [RunWhenElevated]
    public void LsaEnumerateAccountsWithUserRight_WithPrivilegeAndWithoutConnecting_ThrowsException()
    {
        // Arrange.
        using var policy = new LsaUserRights();

        // Act & Assert.
        Assert.Throws<InvalidOperationException>(() => policy.LsaEnumerateAccountsWithUserRight(SeTakeOwnershipPrivilege));
    }

    /// <summary>
    /// Verifies removing a user right from an account works as expected.
    /// </summary>
    [TestMethod]
    [RunWhenElevated]
    public void LsaRemoveAccountRights_WithAccountAndPrivilege_ShouldWork()
    {
        // Arrange.
        using var fixture = new LsaUserRightsSnapshotFixture();

        var securityIdentifier = new SecurityIdentifier(BackupOperators);

        // Select a random user right that has been assigned to the BUILTIN\Backup Operators group from the initial state.
        var (right, existingAccounts) = fixture.InitialState.First(kvp => kvp.Value.Contains(securityIdentifier));

        Assert.Contains(securityIdentifier, existingAccounts);

        using var policy = new LsaUserRights();
        policy.Connect();

        // Act.
        policy.LsaRemoveAccountRights(securityIdentifier, right);

        var current = fixture.GetCurrentState();

        current.TryGetValue(right, out var updatedAccounts);

        // Assert.
        Assert.DoesNotContain(securityIdentifier, updatedAccounts ?? []);
    }

    /// <summary>
    /// Verifies removing a user right from an account without first connecting will throw an exception.
    /// </summary>
    [TestMethod]
    [RunWhenElevated]
    public void LsaRemoveAccountRights_WithoutConnecting_ThrowsException()
    {
        // Arrange.
        using var fixture = new LsaUserRightsSnapshotFixture();

        var securityIdentifier = new SecurityIdentifier(BackupOperators);

        // Act.
        using var policy = new LsaUserRights();

        // Assert.
        Assert.Throws<InvalidOperationException>(() => policy.LsaRemoveAccountRights(securityIdentifier, SeBackupPrivilege));
    }
}