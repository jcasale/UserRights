namespace Tests.Application;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Text.RegularExpressions;

using Microsoft.Extensions.DependencyInjection;

using UserRights.Application;

using Xunit;

using static Tests.TestData;

/// <summary>
/// Represents integration tests for modify privilege functionality.
/// </summary>
public sealed class UserRightsManagerPrivilegeTests : UserRightsManagerTestBase
{
    /// <summary>
    /// Generates invalid method arguments for the <see cref="IUserRightsManager.ModifyPrivilege"/> method.
    /// </summary>
    /// <returns>A sequence of method arguments.</returns>
    public static TheoryData<IUserRightsSerializable, string, string[], string[], bool, bool, string, bool> InvalidArguments()
    {
        var policy = new MockLsaUserRights();
        const string pattern = ".*";

        return new()
        {
            // Verify null policy instance.
            { null!, Privilege1, [PrincipalName1], [], false, false, null!, false },

            // Verify null or empty privilege.
            { policy, null!, [PrincipalName1], [], false, false, null!, false },
            { policy, string.Empty, [PrincipalName1], [], false, false, null!, false },

            // Verify null grant collection.
            { policy, Privilege1, null!, [PrincipalName1], false, false, null!, false },

            // Verify null revocation collection.
            { policy, Privilege1, [PrincipalName1], null!, false, false, null!, false },

            // Verify RevokeAll requirements.
            { policy, Privilege1, [PrincipalName1], [], true, false, null!, false },
            { policy, Privilege1, [], [PrincipalName1], true, false, null!, false },
            { policy, Privilege1, [], [], true, true, null!, false },
            { policy, Privilege1, [], [], true, false, pattern, false },

            // Verify RevokeOthers requirements.
            { policy, Privilege1, [], [], false, true, null!, false },
            { policy, Privilege1, [PrincipalName1], [PrincipalName2], false, true, null!, false },
            { policy, Privilege2, [], [], true, true, null!, false },
            { policy, Privilege1, [], [], false, true, pattern, false },

            // Verify RevokePattern requirements.
            { policy, Privilege1, [], [PrincipalName1], false, false, pattern, false },
            { policy, Privilege2, [], [], true, false, pattern, false },
            { policy, Privilege2, [], [], false, true, pattern, false },

            // Verify remaining requirements.
            { policy, Privilege1, [], [], false, false, null!, false },

            // Verify grant and revocation set restrictions.
            { policy, Privilege1, [PrincipalName1], [PrincipalName1], false, false, null!, false },
            { policy, Privilege1, [PrincipalName1, PrincipalName1], [], false, false, null!, false },
            { policy, Privilege1, [], [PrincipalName1, PrincipalName1], false, false, null!, false }
        };
    }

    /// <summary>
    /// Verifies granting a principal to a privilege and revoking its other principals is successful and does not modify other assignments.
    /// </summary>
    [Fact]
    public void GrantAndRevokeOthersShouldWork()
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
        Assert.Equal(new[] { PrincipalSid1, PrincipalSid2 }.Order(), policy.LsaEnumerateAccountsWithUserRight(Privilege1).Order());
        Assert.Equal([PrincipalSid2], policy.LsaEnumerateAccountsWithUserRight(Privilege2));

        var manager = ServiceProvider.GetRequiredService<IUserRightsManager>();
        manager.ModifyPrivilege(policy, Privilege2, [PrincipalName1], [], false, true, null!, false);

        Assert.Equal(new[] { PrincipalSid1, PrincipalSid2 }.Order(), policy.LsaEnumerateAccountsWithUserRight().Order());
        Assert.Equal(new[] { Privilege1, Privilege2 }.Order(StringComparer.OrdinalIgnoreCase), policy.LsaEnumerateAccountRights(PrincipalSid1).Order(StringComparer.OrdinalIgnoreCase));
        Assert.Equal([Privilege1], policy.LsaEnumerateAccountRights(PrincipalSid2));
        Assert.Equal(new[] { PrincipalSid1, PrincipalSid2 }.Order(), policy.LsaEnumerateAccountsWithUserRight(Privilege1).Order());
        Assert.Equal([PrincipalSid1], policy.LsaEnumerateAccountsWithUserRight(Privilege2));
    }

    /// <summary>
    /// Verifies a single grant with a single revoke is successful and does not modify other assignments.
    /// </summary>
    [Fact]
    public void GrantAndRevokeShouldWork()
    {
        var principals1 = new List<SecurityIdentifier>
        {
            PrincipalSid1
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
        Assert.Equal(new[] { Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid2));

        var manager = ServiceProvider.GetRequiredService<IUserRightsManager>();
        manager.ModifyPrivilege(policy, Privilege1, [PrincipalName2], [PrincipalName1], false, false, null!, false);

        Assert.Equal(new[] { PrincipalSid1, PrincipalSid2 }.Order(), policy.LsaEnumerateAccountsWithUserRight().Order());
        Assert.Equal(new[] { Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid1));
        Assert.Equal(new[] { Privilege1, Privilege2 }.Order(StringComparer.OrdinalIgnoreCase), policy.LsaEnumerateAccountRights(PrincipalSid2).Order(StringComparer.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Verifies granting a principal to a privilege and revoking all principals matching a pattern is successful and does not modify other assignments.
    /// </summary>
    [Fact]
    public void GrantAndRevokePatternShouldWork()
    {
        var principals1 = new List<SecurityIdentifier>
        {
            PrincipalSidCurrent,
            PrincipalSid2,
            PrincipalSid3
        };

        var principals2 = new List<SecurityIdentifier>
        {
            PrincipalSid1,
            PrincipalSid2,
            PrincipalSid3
        };

        var database = new Dictionary<string, ICollection<SecurityIdentifier>>(StringComparer.Ordinal)
        {
            { Privilege1, principals1 },
            { Privilege2, principals2 }
        };

        var policy = new MockLsaUserRights(database);
        policy.Connect("SystemName");

        Assert.Equal(new[] { PrincipalSidCurrent, PrincipalSid1, PrincipalSid2, PrincipalSid3 }.Order(), policy.LsaEnumerateAccountsWithUserRight().Order());
        Assert.Equal(new[] { Privilege1 }, policy.LsaEnumerateAccountRights(PrincipalSidCurrent));
        Assert.Equal(new[] { Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid1));
        Assert.Equal(new[] { Privilege1, Privilege2 }.Order(StringComparer.OrdinalIgnoreCase), policy.LsaEnumerateAccountRights(PrincipalSid2).Order(StringComparer.OrdinalIgnoreCase));
        Assert.Equal(new[] { Privilege1, Privilege2 }.Order(StringComparer.OrdinalIgnoreCase), policy.LsaEnumerateAccountRights(PrincipalSid3).Order(StringComparer.OrdinalIgnoreCase));

        var manager = ServiceProvider.GetRequiredService<IUserRightsManager>();
        var pattern = new Regex("^S-1-5-21", RegexOptions.None, TimeSpan.FromSeconds(1));
        manager.ModifyPrivilege(policy, Privilege1, [PrincipalName1], [], false, false, pattern, false);

        Assert.Equal(new[] { PrincipalSid1, PrincipalSid2, PrincipalSid3 }.Order(), policy.LsaEnumerateAccountsWithUserRight().Order());
        Assert.Equal(new[] { Privilege1, Privilege2 }.Order(StringComparer.OrdinalIgnoreCase), policy.LsaEnumerateAccountRights(PrincipalSid1).Order(StringComparer.OrdinalIgnoreCase));
        Assert.Equal([Privilege1, Privilege2], policy.LsaEnumerateAccountRights(PrincipalSid2).Order(StringComparer.OrdinalIgnoreCase));
        Assert.Equal([Privilege1, Privilege2], policy.LsaEnumerateAccountRights(PrincipalSid3).Order(StringComparer.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Verifies a single grant is successful and does not modify other assignments.
    /// </summary>
    [Fact]
    public void GrantShouldWork()
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

        Assert.Equal(new[] { PrincipalSid1, PrincipalSid2 }.Order(), policy.LsaEnumerateAccountsWithUserRight().Order());
        Assert.Equal(new[] { Privilege1 }, policy.LsaEnumerateAccountRights(PrincipalSid1));
        Assert.Equal(new[] { Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid2));

        var manager = ServiceProvider.GetRequiredService<IUserRightsManager>();
        manager.ModifyPrivilege(policy, Privilege2, [PrincipalName1], [], false, false, null!, false);

        Assert.Equal(new[] { PrincipalSid1, PrincipalSid2 }.Order(), policy.LsaEnumerateAccountsWithUserRight().Order());
        Assert.Equal(new[] { Privilege1, Privilege2 }.Order(StringComparer.OrdinalIgnoreCase), policy.LsaEnumerateAccountRights(PrincipalSid1).Order(StringComparer.OrdinalIgnoreCase));
        Assert.Equal(new[] { Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid2));
    }

    /// <summary>
    /// Verifies invalid arguments throw an instance of <see cref="ArgumentException"/>.
    /// </summary>
    /// <param name="policy">A connection to the local security authority.</param>
    /// <param name="privilege">The privilege to modify.</param>
    /// <param name="grants">The principals to grant the privilege to.</param>
    /// <param name="revocations">The principals to revoke the privilege from.</param>
    /// <param name="revokeAll">Revokes all principals from the privilege.</param>
    /// <param name="revokeOthers">Revokes all principals from the privilege excluding those being granted.</param>
    /// <param name="revokePattern">Revokes all principals whose SID matches the regular expression excluding those being granted.</param>
    /// <param name="dryRun">Enables dry-run mode.</param>
    [Theory]
    [MemberData(nameof(InvalidArguments))]
    public void InvalidArgumentsThrowsException(IUserRightsSerializable policy, string privilege, string[] grants, string[] revocations, bool revokeAll, bool revokeOthers, string revokePattern, bool dryRun)
    {
        var manager = ServiceProvider.GetRequiredService<IUserRightsManager>();
        var regex = string.IsNullOrWhiteSpace(revokePattern) ? null : new Regex(revokePattern, RegexOptions.None, TimeSpan.FromSeconds(1));

        Assert.ThrowsAny<ArgumentException>(() => manager.ModifyPrivilege(policy, privilege, grants, revocations, revokeAll, revokeOthers, regex, dryRun));
    }

    /// <summary>
    /// Verifies revoking all principals for a privilege is successful and does not modify other assignments.
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
        Assert.Equal(new[] { PrincipalSid1, PrincipalSid2 }.Order(), policy.LsaEnumerateAccountsWithUserRight(Privilege1).Order());
        Assert.Equal(new[] { PrincipalSid1, PrincipalSid2 }.Order(), policy.LsaEnumerateAccountsWithUserRight(Privilege2).Order());

        var manager = ServiceProvider.GetRequiredService<IUserRightsManager>();
        manager.ModifyPrivilege(policy, Privilege1, [], [], true, false, null!, false);

        Assert.Equal(new[] { PrincipalSid1, PrincipalSid2 }.Order(), policy.LsaEnumerateAccountsWithUserRight().Order());
        Assert.Equal(new[] { Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid1));
        Assert.Equal(new[] { Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid2));
        Assert.Empty(policy.LsaEnumerateAccountsWithUserRight(Privilege1));
        Assert.Equal(new[] { PrincipalSid1, PrincipalSid2 }.Order(), policy.LsaEnumerateAccountsWithUserRight(Privilege2).Order());
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
        manager.ModifyPrivilege(policy, Privilege1, [], [PrincipalName2], false, false, null!, false);

        Assert.Equal(new[] { PrincipalSid1, PrincipalSid2 }.Order(), policy.LsaEnumerateAccountsWithUserRight().Order());
        Assert.Equal(new[] { Privilege1 }, policy.LsaEnumerateAccountRights(PrincipalSid1));
        Assert.Equal(new[] { Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid2));
    }

    /// <summary>
    /// Verifies revoking all non builtin and virtual principals from a privilege is successful.
    /// </summary>
    [Fact]
    public void RevokePatternForAllButBuiltinAndVirtualShouldWork()
    {
        var principals1 = new List<SecurityIdentifier>
        {
            PrincipalSidCurrent,
            PrincipalSid2,
            PrincipalSid3
        };

        var principals2 = new List<SecurityIdentifier>
        {
            PrincipalSid1,
            PrincipalSid2,
            PrincipalSid3
        };

        var database = new Dictionary<string, ICollection<SecurityIdentifier>>(StringComparer.Ordinal)
        {
            { Privilege1, principals1 },
            { Privilege2, principals2 }
        };

        var policy = new MockLsaUserRights(database);
        policy.Connect("SystemName");

        Assert.Equal(new[] { PrincipalSidCurrent, PrincipalSid1, PrincipalSid2, PrincipalSid3 }.Order(), policy.LsaEnumerateAccountsWithUserRight().Order());
        Assert.Equal([Privilege1], policy.LsaEnumerateAccountRights(PrincipalSidCurrent));
        Assert.Equal([Privilege2], policy.LsaEnumerateAccountRights(PrincipalSid1));
        Assert.Equal(new[] { Privilege1, Privilege2 }.Order(StringComparer.OrdinalIgnoreCase), policy.LsaEnumerateAccountRights(PrincipalSid2).Order(StringComparer.OrdinalIgnoreCase));
        Assert.Equal(new[] { Privilege1, Privilege2 }.Order(StringComparer.OrdinalIgnoreCase), policy.LsaEnumerateAccountRights(PrincipalSid3).Order(StringComparer.OrdinalIgnoreCase));

        var manager = ServiceProvider.GetRequiredService<IUserRightsManager>();
        var pattern = new Regex("^S-1-5-21", RegexOptions.None, TimeSpan.FromSeconds(1));
        manager.ModifyPrivilege(policy, Privilege1, [], [], false, false, pattern, false);

        Assert.Equal(new[] { PrincipalSid1, PrincipalSid2, PrincipalSid3 }.Order(), policy.LsaEnumerateAccountsWithUserRight().Order());
        Assert.Equal([Privilege2], policy.LsaEnumerateAccountRights(PrincipalSid1));
        Assert.Equal([Privilege1, Privilege2], policy.LsaEnumerateAccountRights(PrincipalSid2).Order(StringComparer.OrdinalIgnoreCase));
        Assert.Equal([Privilege1, Privilege2], policy.LsaEnumerateAccountRights(PrincipalSid3).Order(StringComparer.OrdinalIgnoreCase));
    }
}