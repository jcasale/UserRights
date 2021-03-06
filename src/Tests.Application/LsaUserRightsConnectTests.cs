namespace Tests.Application;

using UserRights.Application;
using Xunit;

/// <summary>
/// Represents tests for <see cref="LsaUserRights"/> connection functionality.
/// </summary>
[Collection("lsa")]
public class LsaUserRightsConnectTests
{
    /// <summary>
    /// Tests that only a single connection to the local security authority is allowed.
    /// </summary>
    [AdminOnlyFact]
    public void MultipleConnectionsThrowsException()
    {
        using var policy = new LsaUserRights();
        policy.Connect(null);

        Assert.Throws<InvalidOperationException>(() => policy.Connect(null));
    }
}