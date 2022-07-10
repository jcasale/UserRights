namespace Tests.Cli;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using UserRights.Application;
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
        var principals1 = new HashSet<SecurityIdentifier>
        {
            PrincipalSid1
        };

        var principals2 = new HashSet<SecurityIdentifier>
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

        Assert.Equal(new[] { PrincipalSid1, PrincipalSid2 }, policy.GetPrincipals().OrderBy(p => p));
        Assert.Equal(new[] { Privilege1 }, policy.GetPrivileges(PrincipalSid1));
        Assert.Equal(new[] { Privilege2 }, policy.GetPrivileges(PrincipalSid2));

        policy.ResetConnection();

        this.Registrar.RegisterInstance(typeof(ILsaUserRights), policy);
        this.Registrar.Register(typeof(IUserRightsManager), typeof(UserRightsManager));

        var args = new[]
        {
            "principal",
            PrincipalName1,
            "--grant",
            Privilege2,
            "--revoke-others"
        };

        this.CommandApp.Run(args);

        Assert.Equal(new[] { PrincipalSid1, PrincipalSid2 }, policy.GetPrincipals().OrderBy(p => p));
        Assert.Equal(new[] { Privilege2 }, policy.GetPrivileges(PrincipalSid1));
        Assert.Equal(new[] { Privilege2 }, policy.GetPrivileges(PrincipalSid2));
    }

    /// <summary>
    /// Verifies a single grant with a single revoke is successful and does not modify other assignments.
    /// </summary>
    [Fact]
    public void GrantAndRevokeShouldWork()
    {
        var principals1 = new HashSet<SecurityIdentifier>
        {
            PrincipalSid1,
            PrincipalSid2
        };

        var principals2 = new HashSet<SecurityIdentifier>
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

        Assert.Equal(new[] { PrincipalSid1, PrincipalSid2 }.OrderBy(p => p), policy.GetPrincipals().OrderBy(p => p));
        Assert.Equal(new[] { Privilege1 }, policy.GetPrivileges(PrincipalSid1));
        Assert.Equal(new[] { Privilege1, Privilege2 }.OrderBy(p => p), policy.GetPrivileges(PrincipalSid2).OrderBy(p => p));

        policy.ResetConnection();

        this.Registrar.RegisterInstance(typeof(ILsaUserRights), policy);
        this.Registrar.Register(typeof(IUserRightsManager), typeof(UserRightsManager));

        var args = new[]
        {
            "principal",
            PrincipalName1,
            "--grant",
            Privilege2,
            "--revoke",
            Privilege1
        };

        this.CommandApp.Run(args);

        Assert.Equal(new[] { PrincipalSid1, PrincipalSid2 }.OrderBy(p => p), policy.GetPrincipals().OrderBy(p => p));
        Assert.Equal(new[] { Privilege2 }, policy.GetPrivileges(PrincipalSid1));
        Assert.Equal(new[] { Privilege1, Privilege2 }.OrderBy(p => p), policy.GetPrivileges(PrincipalSid2).OrderBy(p => p));
    }

    /// <summary>
    /// Verifies a single grant is successful and does not modify other assignments.
    /// </summary>
    [Fact]
    public void GrantShouldWork()
    {
        var principals1 = new HashSet<SecurityIdentifier>
        {
            PrincipalSid1,
            PrincipalSid2
        };

        var principals2 = new HashSet<SecurityIdentifier>
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

        Assert.Equal(new[] { PrincipalSid1, PrincipalSid2 }.OrderBy(p => p), policy.GetPrincipals().OrderBy(p => p));
        Assert.Equal(new[] { Privilege1 }, policy.GetPrivileges(PrincipalSid1));
        Assert.Equal(new[] { Privilege1, Privilege2 }.OrderBy(p => p), policy.GetPrivileges(PrincipalSid2).OrderBy(p => p));

        policy.ResetConnection();

        this.Registrar.RegisterInstance(typeof(ILsaUserRights), policy);
        this.Registrar.Register(typeof(IUserRightsManager), typeof(UserRightsManager));

        var args = new[]
        {
            "principal",
            PrincipalName1,
            "--grant",
            Privilege2
        };

        this.CommandApp.Run(args);

        Assert.Equal(new[] { PrincipalSid1, PrincipalSid2 }.OrderBy(p => p), policy.GetPrincipals().OrderBy(p => p));
        Assert.Equal(new[] { Privilege1, Privilege2 }.OrderBy(p => p), policy.GetPrivileges(PrincipalSid1).OrderBy(p => p));
        Assert.Equal(new[] { Privilege1, Privilege2 }.OrderBy(p => p), policy.GetPrivileges(PrincipalSid2).OrderBy(p => p));
    }

    /// <summary>
    /// Verifies a revoking all privileges for a principal is successful and does not modify other assignments.
    /// </summary>
    [Fact]
    public void RevokeAllShouldWork()
    {
        var principals1 = new HashSet<SecurityIdentifier>
        {
            PrincipalSid1,
            PrincipalSid2
        };

        var principals2 = new HashSet<SecurityIdentifier>
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

        Assert.Equal(new[] { PrincipalSid1, PrincipalSid2 }.OrderBy(p => p), policy.GetPrincipals().OrderBy(p => p));
        Assert.Equal(new[] { Privilege1, Privilege2 }.OrderBy(p => p), policy.GetPrivileges(PrincipalSid1).OrderBy(p => p));
        Assert.Equal(new[] { Privilege1, Privilege2 }.OrderBy(p => p), policy.GetPrivileges(PrincipalSid2).OrderBy(p => p));

        policy.ResetConnection();

        this.Registrar.RegisterInstance(typeof(ILsaUserRights), policy);
        this.Registrar.Register(typeof(IUserRightsManager), typeof(UserRightsManager));

        var args = new[]
        {
            "principal",
            PrincipalName1,
            "--revoke-all"
        };

        this.CommandApp.Run(args);

        Assert.Empty(policy.GetPrivileges(PrincipalSid1));
        Assert.Equal(new[] { PrincipalSid2 }, policy.GetPrincipals());
        Assert.Equal(new[] { Privilege1, Privilege2 }.OrderBy(p => p), policy.GetPrivileges(PrincipalSid2).OrderBy(p => p));
    }

    /// <summary>
    /// Verifies a single revocation is successful and does not modify other assignments.
    /// </summary>
    [Fact]
    public void RevokeShouldWork()
    {
        var principals1 = new HashSet<SecurityIdentifier>
        {
            PrincipalSid1,
            PrincipalSid2
        };

        var principals2 = new HashSet<SecurityIdentifier>
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

        Assert.Equal(new[] { PrincipalSid1, PrincipalSid2 }.OrderBy(p => p), policy.GetPrincipals().OrderBy(p => p));
        Assert.Equal(new[] { Privilege1 }, policy.GetPrivileges(PrincipalSid1));
        Assert.Equal(new[] { Privilege1, Privilege2 }.OrderBy(p => p), policy.GetPrivileges(PrincipalSid2).OrderBy(p => p));

        policy.ResetConnection();

        this.Registrar.RegisterInstance(typeof(ILsaUserRights), policy);
        this.Registrar.Register(typeof(IUserRightsManager), typeof(UserRightsManager));

        var args = new[]
        {
            "principal",
            PrincipalName2,
            "--revoke",
            Privilege2
        };

        this.CommandApp.Run(args);

        Assert.Equal(new[] { PrincipalSid1, PrincipalSid2 }.OrderBy(p => p), policy.GetPrincipals().OrderBy(p => p));
        Assert.Equal(new[] { Privilege1 }, policy.GetPrivileges(PrincipalSid1));
        Assert.Equal(new[] { Privilege1 }, policy.GetPrivileges(PrincipalSid2));
    }
}