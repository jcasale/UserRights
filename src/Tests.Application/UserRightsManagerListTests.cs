namespace Tests.Application;

using UserRights.Application;

using static Tests.TestData;

/// <summary>
/// Represents tests for enumerating all user rights.
/// </summary>
[TestClass]
public class UserRightsManagerListTests
{
    /// <summary>
    /// Verifies enumerating all user rights works as expected.
    /// </summary>
    [TestMethod]
    public void GetUserRights_ShouldWork()
    {
        // Arrange.
        UserRightEntry[] expected =
        [
            new(Privilege1, PrincipalSid1.Value, PrincipalName1),
            new(Privilege1, PrincipalSid2.Value, PrincipalName2),
            new(Privilege2, PrincipalSid2.Value, PrincipalName2),
            new(Privilege2, PrincipalSid3.Value, PrincipalName3)
        ];

        var lsaUserRights = LsaUserRightsMockBuilder.CreateBuilder()
            .WithGrant(expected)
            .Build();

        using var fixture = new UserRightsManagerFixture();

        // Act.
        var actual = fixture.UserRightsManager.GetUserRights(lsaUserRights.Object).ToArray();

        // Assert.
        CollectionAssert.AreEquivalent(expected, actual);
    }
}