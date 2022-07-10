namespace Tests.Cli;

using Spectre.Console.Cli;
using UserRights.Application;
using UserRights.Cli;
using Xunit;

/// <summary>
/// Represents syntax tests for privilege functionality.
/// </summary>
public sealed class PrivilegeSyntaxTests : CliTestBase
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PrivilegeSyntaxTests"/> class.
    /// </summary>
    public PrivilegeSyntaxTests()
    {
        this.Registrar.Register(typeof(ILsaUserRights), typeof(MockLsaUserRights));
        this.Registrar.Register(typeof(IUserRightsManager), typeof(MockUserRightsManager));
    }

    /// <summary>
    /// Ensures granting a context and revoking a different context is accepted.
    /// </summary>
    [Fact]
    public void GrantAndRevokeShouldWork()
    {
        var args = new[] { "privilege", "SeServiceLogonRight", "--grant", "DOMAIN\\User", "--revoke", "DOMAIN\\Group" };

        var exception = Record.Exception(() => this.CommandApp.Run(args));

        Assert.Null(exception);
    }

    /// <summary>
    /// Ensures granting multiple contexts is accepted.
    /// </summary>
    [Fact]
    public void GrantMultipleShouldWork()
    {
        var args = new[] { "privilege", "SeServiceLogonRight", "--grant", "DOMAIN\\User", "--grant", "DOMAIN\\Group" };

        var exception = Record.Exception(() => this.CommandApp.Run(args));

        Assert.Null(exception);
    }

    /// <summary>
    /// Ensures granting a context is accepted.
    /// </summary>
    [Fact]
    public void GrantShouldWork()
    {
        var args = new[] { "privilege", "SeServiceLogonRight", "--grant", "DOMAIN\\User" };

        var exception = Record.Exception(() => this.CommandApp.Run(args));

        Assert.Null(exception);
    }

    /// <summary>
    /// Ensures granting a context and revoking all contexts is rejected.
    /// </summary>
    [Fact]
    public void GrantWithRevokeAllThrowsException()
    {
        var args = new[] { "privilege", "SeServiceLogonRight", "--grant", "DOMAIN\\User", "--revoke-all" };

        Assert.Throws<CommandRuntimeException>(() => this.CommandApp.Run(args));
    }

    /// <summary>
    /// Ensures specifying no options is rejected.
    /// </summary>
    [Fact]
    public void NoOptionsThrowsException()
    {
        var args = new[] { "privilege" };

        Assert.Throws<CommandRuntimeException>(() => this.CommandApp.Run(args));
    }

    /// <summary>
    /// Ensures overlapping or duplicate contexts is rejected.
    /// </summary>
    /// <param name="args">The test arguments.</param>
    [Theory]
    [InlineData("privilege", "SeServiceLogonRight", "--grant", "DOMAIN\\UserOrGroup", "--revoke", "DOMAIN\\UserOrGroup")]
    [InlineData("privilege", "SeServiceLogonRight", "--grant", "DOMAIN\\UserOrGroup", "--grant", "DOMAIN\\UserOrGroup")]
    [InlineData("privilege", "SeServiceLogonRight", "--revoke", "DOMAIN\\UserOrGroup", "--revoke", "DOMAIN\\UserOrGroup")]
    public void OverlappingGrantsAndRevokesThrowsException(params string[] args)
        => Assert.Throws<CommandRuntimeException>(() => this.CommandApp.Run(args));

    /// <summary>
    /// Ensures revoking all contexts is accepted.
    /// </summary>
    [Fact]
    public void RevokeAllShouldWork()
    {
        var args = new[] { "privilege", "SeServiceLogonRight", "--revoke-all" };

        var exception = Record.Exception(() => this.CommandApp.Run(args));

        Assert.Null(exception);
    }

    /// <summary>
    /// Ensures granting a context and revoking all contexts is rejected.
    /// </summary>
    [Fact]
    public void RevokeAllWithGrantsThrowsException()
    {
        var args = new[] { "privilege", "SeServiceLogonRight", "--revoke-all", "--grant", "DOMAIN\\UserOrGroup" };

        Assert.Throws<CommandRuntimeException>(() => this.CommandApp.Run(args));
    }

    /// <summary>
    /// Ensures revoking a context and revoking all contexts is rejected.
    /// </summary>
    [Fact]
    public void RevokeAllWithRevocationsThrowsException()
    {
        var args = new[] { "privilege", "SeServiceLogonRight", "--revoke-all", "--revoke", "DOMAIN\\UserOrGroup" };

        Assert.Throws<CommandRuntimeException>(() => this.CommandApp.Run(args));
    }

    /// <summary>
    /// Ensures revoking all contexts and revoking other contexts is rejected.
    /// </summary>
    [Fact]
    public void RevokeAllWithRevokeOthersThrowsException()
    {
        var args = new[] { "privilege", "SeServiceLogonRight", "--revoke-all", "--revoke-others" };

        Assert.Throws<CommandRuntimeException>(() => this.CommandApp.Run(args));
    }

    /// <summary>
    /// Ensures revoking multiple contexts is accepted.
    /// </summary>
    [Fact]
    public void RevokeMultipleShouldWork()
    {
        var args = new[] { "privilege", "SeServiceLogonRight", "--revoke", "DOMAIN\\User", "--revoke", "DOMAIN\\Group" };

        var exception = Record.Exception(() => this.CommandApp.Run(args));

        Assert.Null(exception);
    }

    /// <summary>
    /// Ensures revoke other contexts without granting a context is rejected.
    /// </summary>
    [Fact]
    public void RevokeOthersWithOutGrantsThrowsException()
    {
        var args = new[] { "privilege", "SeServiceLogonRight", "--revoke-others" };

        Assert.Throws<CommandRuntimeException>(() => this.CommandApp.Run(args));
    }

    /// <summary>
    /// Ensures revoke other contexts with revoking a context is rejected.
    /// </summary>
    [Fact]
    public void RevokeOthersWithRevocationsThrowsException()
    {
        var args = new[] { "privilege", "SeServiceLogonRight", "--revoke-others", "--revoke", "DOMAIN\\UserOrGroup" };

        Assert.Throws<CommandRuntimeException>(() => this.CommandApp.Run(args));
    }

    /// <summary>
    /// Ensures revoking a valid pattern is accepted.
    /// </summary>
    [Fact]
    public void RevokePatternShouldWork()
    {
        var args = new[] { "privilege", "SeServiceLogonRight", "--revoke-pattern", "^S-1-5-21-" };

        var exception = Record.Exception(() => this.CommandApp.Run(args));

        Assert.Null(exception);
    }

    /// <summary>
    /// Ensures granting a context and revoking a valid pattern is accepted.
    /// </summary>
    [Fact]
    public void RevokePatternWithGrantShouldWork()
    {
        var args = new[] { "privilege", "SeServiceLogonRight", "--grant", "DOMAIN\\UserOrGroup", "--revoke-pattern", "^S-1-5-21-" };

        var exception = Record.Exception(() => this.CommandApp.Run(args));

        Assert.Null(exception);
    }

    /// <summary>
    /// Ensures revoking a valid regex is accepted.
    /// </summary>
    /// <param name="args">The test arguments.</param>
    [Theory]
    [InlineData("privilege", "SeServiceLogonRight", "--revoke-pattern", "^xyz.*")]
    [InlineData("privilege", "SeServiceLogonRight", "--revoke-pattern", "^S-1-5-21-")]
    [InlineData("privilege", "SeServiceLogonRight", "--revoke-pattern", "(?i)^[A-Z]+")]
    public void RevokePatternWithValidRegexShouldWork(params string[] args)
    {
        var exception = Record.Exception(() => this.CommandApp.Run(args));

        Assert.Null(exception);
    }

    /// <summary>
    /// Ensures revoking a pattern and revoking all contexts is rejected.
    /// </summary>
    [Fact]
    public void RevokePatternWithRevokeAllThrowsException()
    {
        var args = new[] { "privilege", "SeServiceLogonRight", "--revoke-pattern", "^S-1-5-21-", "--revoke-all" };

        Assert.Throws<CommandRuntimeException>(() => this.CommandApp.Run(args));
    }

    /// <summary>
    /// Ensures revoking a pattern and revoking other contexts is rejected.
    /// </summary>
    [Fact]
    public void RevokePatternWithRevokeOthersThrowsException()
    {
        var args = new[] { "privilege", "SeServiceLogonRight", "--revoke-pattern", "^S-1-5-21-", "--revoke-others" };

        Assert.Throws<CommandRuntimeException>(() => this.CommandApp.Run(args));
    }

    /// <summary>
    /// Ensures revoking a pattern and revoking a context is rejected.
    /// </summary>
    [Fact]
    public void RevokePatternWithRevokeThrowsException()
    {
        var args = new[] { "privilege", "SeServiceLogonRight", "--revoke-pattern", "^S-1-5-21-", "--revoke", "DOMAIN\\UserOrGroup" };

        Assert.Throws<CommandRuntimeException>(() => this.CommandApp.Run(args));
    }

    /// <summary>
    /// Ensures revoking an invalid regex is rejected.
    /// </summary>
    /// <param name="args">The test arguments.</param>
    [Theory]
    [InlineData("privilege", "SeServiceLogonRight", "--revoke-pattern", "[0-9]{3,1}")]
    [InlineData("privilege", "SeServiceLogonRight", "--revoke-pattern", "^[S-1-5-21-")]
    public void RevokePatternWithInvalidRegexThrowsException(params string[] args)
        => Assert.Throws<SyntaxException>(() => this.CommandApp.Run(args));

    /// <summary>
    /// Ensures revoking a context is accepted.
    /// </summary>
    [Fact]
    public void RevokeShouldWork()
    {
        var args = new[] { "privilege", "SeServiceLogonRight", "--revoke", "DOMAIN\\UserOrGroup" };

        var exception = Record.Exception(() => this.CommandApp.Run(args));

        Assert.Null(exception);
    }
}