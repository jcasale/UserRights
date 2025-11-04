namespace Tests.Application;

using UserRights.Application;

/// <summary>
/// Represents tests for <see cref="LsaUserRights"/> connection functionality.
/// </summary>
[TestClass]
public class LsaUserRightsConnectTests
{
    /// <summary>
    /// Tests that only a single connection to the local security authority is allowed.
    /// </summary>
    [TestMethod]
    [RunWhenElevated]
    public void MultipleConnectionsThrowsException()
    {
        // Arrange.
        using var policy = new LsaUserRights();
        policy.Connect();

        // Act & Assert.
        Assert.Throws<InvalidOperationException>(() => policy.Connect());
    }
}