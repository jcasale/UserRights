namespace Tests.Cli;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;

using Microsoft.Extensions.DependencyInjection;
using UserRights.Application;
using UserRights.Cli;
using Xunit;

using static Tests.TestData;

/// <summary>
/// Represents integration tests for modify principal functionality.
/// </summary>
public sealed class PrincipalCommandTests : CliTestBase
{
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

        Assert.Equal(new[] { PrincipalSid1, PrincipalSid2 }, policy.LsaEnumerateAccountsWithUserRight().Order());
        Assert.Equal(new[] { Privilege1 }, policy.LsaEnumerateAccountRights(PrincipalSid1));
        Assert.Equal(new[] { Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid2));

        policy.ResetConnection();

        ServiceCollection.AddSingleton<ILsaUserRights>(policy);
        ServiceCollection.AddSingleton<IUserRightsManager, UserRightsManager>();
        ServiceCollection.AddSingleton<CliBuilder>();

        var builder = ServiceProvider.GetRequiredService<CliBuilder>();

        var configuration = builder.Build();

        var args = new[]
        {
            "principal",
            PrincipalName1,
            "--grant",
            Privilege2,
            "--revoke-others"
        };

        var rc = configuration.Parse(args).Validate().Invoke();

        Assert.Equal(0, rc);
        Assert.Equal(new[] { PrincipalSid1, PrincipalSid2 }, policy.LsaEnumerateAccountsWithUserRight().Order());
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

        policy.ResetConnection();

        ServiceCollection.AddSingleton<ILsaUserRights>(policy);
        ServiceCollection.AddSingleton<IUserRightsManager, UserRightsManager>();
        ServiceCollection.AddSingleton<CliBuilder>();

        var builder = ServiceProvider.GetRequiredService<CliBuilder>();

        var configuration = builder.Build();

        var args = new[]
        {
            "principal",
            PrincipalName1,
            "--grant",
            Privilege2,
            "--revoke",
            Privilege1
        };

        var rc = configuration.Parse(args).Validate().Invoke();

        Assert.Equal(0, rc);
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

        policy.ResetConnection();

        ServiceCollection.AddSingleton<ILsaUserRights>(policy);
        ServiceCollection.AddSingleton<IUserRightsManager, UserRightsManager>();
        ServiceCollection.AddSingleton<CliBuilder>();

        var builder = ServiceProvider.GetRequiredService<CliBuilder>();

        var configuration = builder.Build();

        var args = new[]
        {
            "principal",
            PrincipalName1,
            "--grant",
            Privilege2
        };

        var rc = configuration.Parse(args).Validate().Invoke();

        Assert.Equal(0, rc);
        Assert.Equal(new[] { PrincipalSid1, PrincipalSid2 }.Order(), policy.LsaEnumerateAccountsWithUserRight().Order());
        Assert.Equal(new[] { Privilege1, Privilege2 }.Order(StringComparer.OrdinalIgnoreCase), policy.LsaEnumerateAccountRights(PrincipalSid1).Order(StringComparer.OrdinalIgnoreCase));
        Assert.Equal(new[] { Privilege1, Privilege2 }.Order(StringComparer.OrdinalIgnoreCase), policy.LsaEnumerateAccountRights(PrincipalSid2).Order(StringComparer.OrdinalIgnoreCase));
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

        policy.ResetConnection();

        ServiceCollection.AddSingleton<ILsaUserRights>(policy);
        ServiceCollection.AddSingleton<IUserRightsManager, UserRightsManager>();
        ServiceCollection.AddSingleton<CliBuilder>();

        var builder = ServiceProvider.GetRequiredService<CliBuilder>();

        var configuration = builder.Build();

        var args = new[]
        {
            "principal",
            PrincipalName1,
            "--revoke-all"
        };

        var rc = configuration.Parse(args).Validate().Invoke();

        Assert.Equal(0, rc);
        Assert.Empty(policy.LsaEnumerateAccountRights(PrincipalSid1));
        Assert.Equal(new[] { PrincipalSid2 }, policy.LsaEnumerateAccountsWithUserRight());
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

        policy.ResetConnection();

        ServiceCollection.AddSingleton<ILsaUserRights>(policy);
        ServiceCollection.AddSingleton<IUserRightsManager, UserRightsManager>();
        ServiceCollection.AddSingleton<CliBuilder>();

        var builder = ServiceProvider.GetRequiredService<CliBuilder>();

        var configuration = builder.Build();

        var args = new[]
        {
            "principal",
            PrincipalName2,
            "--revoke",
            Privilege2
        };

        var rc = configuration.Parse(args).Validate().Invoke();

        Assert.Equal(0, rc);
        Assert.Equal(new[] { PrincipalSid1, PrincipalSid2 }.Order(), policy.LsaEnumerateAccountsWithUserRight().Order());
        Assert.Equal(new[] { Privilege1 }, policy.LsaEnumerateAccountRights(PrincipalSid1));
        Assert.Equal(new[] { Privilege1 }, policy.LsaEnumerateAccountRights(PrincipalSid2));
    }
}