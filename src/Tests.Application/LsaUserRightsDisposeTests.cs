namespace Tests.Application;

using UserRights.Application;

/// <summary>
/// Represents tests for <see cref="LsaUserRights"/> disposal functionality.
/// </summary>
[TestClass]
public class LsaUserRightsDisposeTests
{
    /// <summary>
    /// Tests whether dispose can be successfully called multiple times.
    /// </summary>
    [TestMethod]
    [RunWhenElevated]
    public void CanBeDisposedMultipleTimes()
    {
        // Arrange.
        var policy = new LsaUserRights();

        policy.Dispose();

        // Act & Assert.
        try
        {
            policy.Dispose();
        }
        catch (Exception e)
        {
            Assert.Fail($"Multiple calls to Dispose() should not fail: {e}");
        }
    }
}