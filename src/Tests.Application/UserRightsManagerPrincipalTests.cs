namespace Tests.Application;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;

using Microsoft.Extensions.DependencyInjection;
using UserRights.Application;
using Xunit;

using static Tests.TestData;

/// <summary>
/// Represents tests for <see cref="IUserRightsManager"/> modify principal functionality.
/// </summary>
public sealed class UserRightsManagerPrincipalTests : UserRightsManagerTestBase
{
    /// <summary>
    /// Generates invalid method arguments for the <see cref="IUserRightsManager.ModifyPrincipal"/> method.
    /// </summary>
    /// <returns>A sequence of method arguments.</returns>
    public static TheoryData<IUserRightsSerializable, string, string[], string[], bool, bool, bool> InvalidArguments()
    {
        var policy = new MockLsaUserRights(
            new Dictionary<string, ICollection<SecurityIdentifier>>(StringComparer.InvariantCultureIgnoreCase)
            {
                { "joey", new List<SecurityIdentifier> { PrincipalSid1 } }
            });

        return new TheoryData<IUserRightsSerializable, string, string[], string[], bool, bool, bool>
        {
            // Verify null policy instance.
            { null!, PrincipalName1, [Privilege1], [], false, false, false },

            // Verify null or empty principal.
            { policy, null!, [Privilege1], [], false, false, false },
            { policy, string.Empty, [Privilege1], [], false, false, false },

            // Verify null grant collection.
            { policy, PrincipalName1, null!, [Privilege1], false, false, false },

            // Verify null revocation collection.
            { policy, PrincipalName1, [Privilege1], null!, false, false, false },

            // Verify RevokeAll requirements.
            { policy, PrincipalName1, [Privilege1], [], true, false, false },
            { policy, PrincipalName1, [], [Privilege1], true, false, false },
            { policy, PrincipalName1, [], [], true, true, false },

            // Verify RevokeOthers requirements.
            { policy, PrincipalName1, [Privilege1], [], true, true, false },
            { policy, PrincipalName1, [], [], false, true, false },
            { policy, PrincipalName1, [Privilege1], [Privilege2], false, true, false },

            // Verify remaining requirements.
            { policy, PrincipalName1, [], [], false, false, false },

            // Verify grant and revocation set restrictions.
            { policy, PrincipalName1, [Privilege1], [Privilege1], false, false, false },
            { policy, PrincipalName1, [Privilege1, Privilege1], [], false, false, false },
            { policy, PrincipalName1, [], [Privilege1, Privilege1], false, false, false }
        };
    }

    /// <summary>
    /// Verifies a granting a privilege to a principal and revoking their other privileges is successful and does not modify other assignments.
    /// </summary>
    [Fact]
    public void GrantAndRevokeOthersShouldWork()
    {
        var principals1 = new List<SecurityIdentifier>
        {
            PrincipalSid1
        };

        var principals2 = new List<SecurityIdentifier>
        {
            PrincipalSid2
        };

        var database = new Dictionary<string, ICollection<SecurityIdentifier>>(StringComparer.Ordinal)
        {
            { Privilege1, principals1 },
            { Privilege2, principals2 }
        };

        var policy = new MockLsaUserRights(database);
        policy.Connect("SystemName");

        Assert.Equal([PrincipalSid1, PrincipalSid2], policy.LsaEnumerateAccountsWithUserRight().Order());
        Assert.Equal(new[] { Privilege1 }, policy.LsaEnumerateAccountRights(PrincipalSid1));
        Assert.Equal(new[] { Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid2));

        var manager = ServiceProvider.GetRequiredService<IUserRightsManager>();
        manager.ModifyPrincipal(policy, PrincipalName1, [Privilege2], [], false, true, false);

        Assert.Equal([PrincipalSid1, PrincipalSid2], policy.LsaEnumerateAccountsWithUserRight().Order());
        Assert.Equal(new[] { Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid1));
        Assert.Equal(new[] { Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid2));
    }

    /// <summary>
    /// Verifies a single grant with a single revoke is successful and does not modify other assignments.
    /// </summary>
    [Fact]
    public void GrantAndRevokeShouldWork()
    {
        var principals1 = new List<SecurityIdentifier>
        {
            PrincipalSid1,
            PrincipalSid2
        };

        var principals2 = new List<SecurityIdentifier>
        {
            PrincipalSid2
        };

        var database = new Dictionary<string, ICollection<SecurityIdentifier>>(StringComparer.Ordinal)
        {
            { Privilege1, principals1 },
            { Privilege2, principals2 }
        };

        var policy = new MockLsaUserRights(database);
        policy.Connect("SystemName");

        Assert.Equal(new[] { PrincipalSid1, PrincipalSid2 }.Order(), policy.LsaEnumerateAccountsWithUserRight().Order());
        Assert.Equal(new[] { Privilege1 }, policy.LsaEnumerateAccountRights(PrincipalSid1));
        Assert.Equal(new[] { Privilege1, Privilege2 }.Order(StringComparer.OrdinalIgnoreCase), policy.LsaEnumerateAccountRights(PrincipalSid2).Order(StringComparer.OrdinalIgnoreCase));

        var manager = ServiceProvider.GetRequiredService<IUserRightsManager>();
        manager.ModifyPrincipal(policy, PrincipalName1, [Privilege2], [Privilege1], false, false, false);

        Assert.Equal(new[] { PrincipalSid1, PrincipalSid2 }.Order(), policy.LsaEnumerateAccountsWithUserRight().Order());
        Assert.Equal(new[] { Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid1));
        Assert.Equal(new[] { Privilege1, Privilege2 }.Order(StringComparer.OrdinalIgnoreCase), policy.LsaEnumerateAccountRights(PrincipalSid2).Order(StringComparer.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Verifies a single grant is successful and does not modify other assignments.
    /// </summary>
    [Fact]
    public void GrantShouldWork()
    {
        var principals1 = new List<SecurityIdentifier>
        {
            PrincipalSid1,
            PrincipalSid2
        };

        var principals2 = new List<SecurityIdentifier>
        {
            PrincipalSid2
        };

        var database = new Dictionary<string, ICollection<SecurityIdentifier>>(StringComparer.Ordinal)
        {
            { Privilege1, principals1 },
            { Privilege2, principals2 }
        };

        var policy = new MockLsaUserRights(database);
        policy.Connect("SystemName");

        Assert.Equal(new[] { PrincipalSid1, PrincipalSid2 }.Order(), policy.LsaEnumerateAccountsWithUserRight().Order());
        Assert.Equal(new[] { Privilege1 }, policy.LsaEnumerateAccountRights(PrincipalSid1));
        Assert.Equal(new[] { Privilege1, Privilege2 }.Order(StringComparer.OrdinalIgnoreCase), policy.LsaEnumerateAccountRights(PrincipalSid2).Order(StringComparer.OrdinalIgnoreCase));

        var manager = ServiceProvider.GetRequiredService<IUserRightsManager>();
        manager.ModifyPrincipal(policy, PrincipalName1, [Privilege2], [], false, false, false);

        Assert.Equal(new[] { PrincipalSid1, PrincipalSid2 }.Order(), policy.LsaEnumerateAccountsWithUserRight().Order());
        Assert.Equal(new[] { Privilege1, Privilege2 }.Order(StringComparer.OrdinalIgnoreCase), policy.LsaEnumerateAccountRights(PrincipalSid1).Order(StringComparer.OrdinalIgnoreCase));
        Assert.Equal(new[] { Privilege1, Privilege2 }.Order(StringComparer.OrdinalIgnoreCase), policy.LsaEnumerateAccountRights(PrincipalSid2).Order(StringComparer.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Verifies invalid arguments throw an instance of <see cref="ArgumentException"/>.
    /// </summary>
    /// <param name="policy">A connection to the local security authority.</param>
    /// <param name="principal">The principal to modify.</param>
    /// <param name="grants">The privileges to grant to the principal.</param>
    /// <param name="revocations">The privileges to revoke from the principal.</param>
    /// <param name="revokeAll">Revokes all privileges from the principal.</param>
    /// <param name="revokeOthers">Revokes all privileges from the principal excluding those being granted.</param>
    /// <param name="dryRun">Enables dry-run mode.</param>
    [Theory]
    [MemberData(nameof(InvalidArguments))]
    public void InvalidArgumentsThrowsException(IUserRightsSerializable policy, string principal, string[] grants, string[] revocations, bool revokeAll, bool revokeOthers, bool dryRun)
    {
        var manager = ServiceProvider.GetRequiredService<IUserRightsManager>();

        Assert.ThrowsAny<ArgumentException>(() => manager.ModifyPrincipal(policy, principal, grants, revocations, revokeAll, revokeOthers, dryRun));
    }

    /// <summary>
    /// Verifies a revoking all privileges for a principal is successful and does not modify other assignments.
    /// </summary>
    [Fact]
    public void RevokeAllShouldWork()
    {
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

        var policy = new MockLsaUserRights(database);
        policy.Connect("SystemName");

        Assert.Equal(new[] { PrincipalSid1, PrincipalSid2 }.Order(), policy.LsaEnumerateAccountsWithUserRight().Order());
        Assert.Equal(new[] { Privilege1, Privilege2 }.Order(StringComparer.OrdinalIgnoreCase), policy.LsaEnumerateAccountRights(PrincipalSid1).Order(StringComparer.OrdinalIgnoreCase));
        Assert.Equal(new[] { Privilege1, Privilege2 }.Order(StringComparer.OrdinalIgnoreCase), policy.LsaEnumerateAccountRights(PrincipalSid2).Order(StringComparer.OrdinalIgnoreCase));

        var manager = ServiceProvider.GetRequiredService<IUserRightsManager>();
        manager.ModifyPrincipal(policy, PrincipalName1, [], [], true, false, false);

        Assert.Empty(policy.LsaEnumerateAccountRights(PrincipalSid1));
        Assert.Equal([PrincipalSid2], policy.LsaEnumerateAccountsWithUserRight());
        Assert.Equal(new[] { Privilege1, Privilege2 }.Order(StringComparer.OrdinalIgnoreCase), policy.LsaEnumerateAccountRights(PrincipalSid2).Order(StringComparer.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Verifies a single revocation is successful and does not modify other assignments.
    /// </summary>
    [Fact]
    public void RevokeShouldWork()
    {
        var principals1 = new List<SecurityIdentifier>
        {
            PrincipalSid1,
            PrincipalSid2
        };

        var principals2 = new List<SecurityIdentifier>
        {
            PrincipalSid2
        };

        var database = new Dictionary<string, ICollection<SecurityIdentifier>>(StringComparer.Ordinal)
        {
            { Privilege1, principals1 },
            { Privilege2, principals2 }
        };

        var policy = new MockLsaUserRights(database);
        policy.Connect("SystemName");

        Assert.Equal(new[] { PrincipalSid1, PrincipalSid2 }.Order(), policy.LsaEnumerateAccountsWithUserRight().Order());
        Assert.Equal(new[] { Privilege1 }, policy.LsaEnumerateAccountRights(PrincipalSid1));
        Assert.Equal(new[] { Privilege1, Privilege2 }.Order(StringComparer.OrdinalIgnoreCase), policy.LsaEnumerateAccountRights(PrincipalSid2).Order(StringComparer.OrdinalIgnoreCase));

        var manager = ServiceProvider.GetRequiredService<IUserRightsManager>();
        manager.ModifyPrincipal(policy, PrincipalName2, [], [Privilege2], false, false, false);

        Assert.Equal(new[] { PrincipalSid1, PrincipalSid2 }.Order(), policy.LsaEnumerateAccountsWithUserRight().Order());
        Assert.Equal(new[] { Privilege1 }, policy.LsaEnumerateAccountRights(PrincipalSid1));
        Assert.Equal(new[] { Privilege1 }, policy.LsaEnumerateAccountRights(PrincipalSid2));
    }
}