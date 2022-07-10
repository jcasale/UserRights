namespace Tests.Cli;

using Spectre.Console.Cli;
using UserRights.Application;
using Xunit;

/// <summary>
/// Represents syntax tests for principal functionality.
/// </summary>
public sealed class PrincipalSyntaxTests : CliTestBase
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PrincipalSyntaxTests"/> class.
    /// </summary>
    public PrincipalSyntaxTests()
    {
        this.Registrar.Register(typeof(ILsaUserRights), typeof(MockLsaUserRights));
        this.Registrar.Register(typeof(IUserRightsManager), typeof(MockUserRightsManager));
    }

    /// <summary>
    /// Ensures granting a privilege and revoking a different privilege is accepted.
    /// </summary>
    [Fact]
    public void GrantAndRevokeShouldWork()
    {
        var args = new[] { "principal", "DOMAIN\\UserOrGroup", "--grant", "SeServiceLogonRight", "--revoke", "SeBatchLogonRight" };

        var exception = Record.Exception(() => this.CommandApp.Run(args));

        Assert.Null(exception);
    }

    /// <summary>
    /// Ensures granting multiple privileges is accepted.
    /// </summary>
    [Fact]
    public void GrantMultipleShouldWork()
    {
        var args = new[] { "principal", "DOMAIN\\UserOrGroup", "--grant", "SeServiceLogonRight", "--grant", "SeBatchLogonRight" };

        var exception = Record.Exception(() => this.CommandApp.Run(args));

        Assert.Null(exception);
    }

    /// <summary>
    /// Ensures granting a privilege is accepted.
    /// </summary>
    [Fact]
    public void GrantShouldWork()
    {
        var args = new[] { "principal", "DOMAIN\\UserOrGroup", "--grant", "SeServiceLogonRight" };

        var exception = Record.Exception(() => this.CommandApp.Run(args));

        Assert.Null(exception);
    }

    /// <summary>
    /// Ensures granting a privilege and revoking all other privileges is rejected.
    /// </summary>
    [Fact]
    public void GrantWithRevokeAllThrowsException()
    {
        var args = new[] { "principal", "DOMAIN\\UserOrGroup", "--grant", "SeServiceLogonRight", "--revoke-all" };

        Assert.Throws<CommandRuntimeException>(() => this.CommandApp.Run(args));
    }

    /// <summary>
    /// Ensures specifying no options is rejected.
    /// </summary>
    [Fact]
    public void NoOptionsThrowsException()
    {
        var args = new[] { "principal" };

        Assert.Throws<CommandRuntimeException>(() => this.CommandApp.Run(args));
    }

    /// <summary>
    /// Ensures overlapping or duplicate privileges is rejected.
    /// </summary>
    /// <param name="args">The test arguments.</param>
    [Theory]
    [InlineData("principal", "DOMAIN\\UserOrGroup", "--grant", "SeServiceLogonRight", "--revoke", "SeServiceLogonRight")]
    [InlineData("principal", "DOMAIN\\UserOrGroup", "--grant", "SeServiceLogonRight", "--grant", "SeServiceLogonRight")]
    [InlineData("principal", "DOMAIN\\UserOrGroup", "--revoke", "SeServiceLogonRight", "--revoke", "SeServiceLogonRight")]
    public void OverlappingGrantsAndRevokesThrowsException(params string[] args)
        => Assert.Throws<CommandRuntimeException>(() => this.CommandApp.Run(args));

    /// <summary>
    /// Ensures revoking all privileges is accepted.
    /// </summary>
    [Fact]
    public void RevokeAllShouldWork()
    {
        var args = new[] { "principal", "DOMAIN\\UserOrGroup", "--revoke-all" };

        var exception = Record.Exception(() => this.CommandApp.Run(args));

        Assert.Null(exception);
    }

    /// <summary>
    /// Ensures granting a privilege and granting all privileges is rejected.
    /// </summary>
    [Fact]
    public void RevokeAllWithGrantsThrowsException()
    {
        var args = new[] { "principal", "DOMAIN\\UserOrGroup", "--revoke-all", "--grant", "SeServiceLogonRight" };

        Assert.Throws<CommandRuntimeException>(() => this.CommandApp.Run(args));
    }

    /// <summary>
    /// Ensures revoking a privilege and revoking all privileges is rejected.
    /// </summary>
    [Fact]
    public void RevokeAllWithRevocationsThrowsException()
    {
        var args = new[] { "principal", "DOMAIN\\UserOrGroup", "--revoke-all", "--revoke", "SeServiceLogonRight" };

        Assert.Throws<CommandRuntimeException>(() => this.CommandApp.Run(args));
    }

    /// <summary>
    /// Ensures revoking all privileges and revoking other privileges is rejected.
    /// </summary>
    [Fact]
    public void RevokeAllWithRevokeOthersThrowsException()
    {
        var args = new[] { "principal", "DOMAIN\\UserOrGroup", "--revoke-all", "--revoke-others" };

        Assert.Throws<CommandRuntimeException>(() => this.CommandApp.Run(args));
    }

    /// <summary>
    /// Ensures revoking multiple privileges is accepted.
    /// </summary>
    [Fact]
    public void RevokeMultipleShouldWork()
    {
        var args = new[] { "principal", "DOMAIN\\UserOrGroup", "--revoke", "SeServiceLogonRight", "--revoke", "SeBatchLogonRight" };

        var exception = Record.Exception(() => this.CommandApp.Run(args));

        Assert.Null(exception);
    }

    /// <summary>
    /// Ensures revoke other privileges without granting a privilege is rejected.
    /// </summary>
    [Fact]
    public void RevokeOthersWithOutGrantsThrowsException()
    {
        var args = new[] { "principal", "DOMAIN\\UserOrGroup", "--revoke-others" };

        Assert.Throws<CommandRuntimeException>(() => this.CommandApp.Run(args));
    }

    /// <summary>
    /// Ensures revoke other privileges with revoking a privilege is rejected.
    /// </summary>
    [Fact]
    public void RevokeOthersWithRevocationsThrowsException()
    {
        var args = new[] { "principal", "DOMAIN\\UserOrGroup", "--revoke-others", "--revoke", "SeServiceLogonRight" };

        Assert.Throws<CommandRuntimeException>(() => this.CommandApp.Run(args));
    }

    /// <summary>
    /// Ensures revoking a privilege is accepted.
    /// </summary>
    [Fact]
    public void RevokeShouldWork()
    {
        var args = new[] { "principal", "DOMAIN\\UserOrGroup", "--revoke", "SeServiceLogonRight" };

        var exception = Record.Exception(() => this.CommandApp.Run(args));

        Assert.Null(exception);
    }
}