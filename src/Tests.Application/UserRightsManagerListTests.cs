namespace Tests.Application;

using System.Security.Principal;

using UserRights.Application;
using UserRights.Extensions.Security;

using static Tests.TestData;

/// <summary>
/// Represents tests for <see cref="IUserRightsManager"/> list functionality.
/// </summary>
[TestClass]
public class UserRightsManagerListTests
{
    /// <summary>
    /// Verifies listing user rights.
    /// </summary>
    [TestMethod]
    public void SerializingToCsvShouldWork()
    {
        // Arrange.
        var principals1 = new List<SecurityIdentifier>
        {
            PrincipalSid1,
            PrincipalSid2
        };

        var principals2 = new List<SecurityIdentifier>
        {
            PrincipalSid1,
            PrincipalSid2
        };

        var database = new Dictionary<string, ICollection<SecurityIdentifier>>(StringComparer.Ordinal)
        {
            { Privilege1, principals1 },
            { Privilege2, principals2 }
        };

        var expected = database
            .SelectMany(kvp => kvp.Value.Select(p => new UserRightEntry(kvp.Key, p.Value, p.ToAccount().Value)))
            .ToArray();

        var policy = new MockLsaUserRights(database);
        policy.Connect("SystemName");

        CollectionAssert.AreEquivalent(new[] { PrincipalSid1, PrincipalSid2 }, policy.LsaEnumerateAccountsWithUserRight());
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid1));
        CollectionAssert.AreEquivalent(new[] { Privilege1, Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid2));

        using var fixture = new UserRightsManagerFixture();

        // Act.
        var actual = fixture.UserRightsManager.GetUserRights(policy).ToArray();

        // Assert.
        CollectionAssert.AreEquivalent(expected, actual);
    }
}