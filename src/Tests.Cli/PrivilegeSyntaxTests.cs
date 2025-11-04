namespace Tests.Cli;

using UserRights.Cli;

/// <summary>
/// Represents syntax tests for privilege functionality.
/// </summary>
[TestClass]
public sealed class PrivilegeSyntaxTests : CliBuilderFixture
{
    /// <summary>
    /// Ensures granting a context and revoking a different context is accepted.
    /// </summary>
    [TestMethod]
    public void GrantAndRevokeShouldWork()
    {
        // Arrange.
        var args = new[] { "privilege", "SeServiceLogonRight", "--grant", "DOMAIN\\User", "--revoke", "DOMAIN\\Group" };
        var rootCommand = CliBuilder.Build();

        // Act.
        var rc = rootCommand.Parse(args).ThrowIfInvalid().Run();

        // Assert.
        Assert.AreEqual(0, rc);
    }

    /// <summary>
    /// Ensures granting multiple contexts is accepted.
    /// </summary>
    [TestMethod]
    public void GrantMultipleShouldWork()
    {
        // Arrange.
        var args = new[] { "privilege", "SeServiceLogonRight", "--grant", "DOMAIN\\User", "--grant", "DOMAIN\\Group" };
        var rootCommand = CliBuilder.Build();

        // Act.
        var rc = rootCommand.Parse(args).ThrowIfInvalid().Run();

        // Assert.
        Assert.AreEqual(0, rc);
    }

    /// <summary>
    /// Ensures granting a context is accepted.
    /// </summary>
    [TestMethod]
    public void GrantShouldWork()
    {
        // Arrange.
        var args = new[] { "privilege", "SeServiceLogonRight", "--grant", "DOMAIN\\User" };
        var rootCommand = CliBuilder.Build();

        // Act.
        var rc = rootCommand.Parse(args).ThrowIfInvalid().Run();

        // Assert.
        Assert.AreEqual(0, rc);
    }

    /// <summary>
    /// Ensures an empty or whitespace grant is rejected.
    /// </summary>
    /// <param name="args">The test arguments.</param>
    [TestMethod]
    [DataRow("privilege", "SeServiceLogonRight", "--grant", "")]
    [DataRow("privilege", "SeServiceLogonRight", "--grant", " ")]
    public void GrantWithInvalidStringThrowsException(params string[] args)
        => Assert.Throws<SyntaxException>(() => CliBuilder.Build().Parse(args).ThrowIfInvalid().Run());

    /// <summary>
    /// Ensures granting a context and revoking all contexts is rejected.
    /// </summary>
    [TestMethod]
    public void GrantWithRevokeAllThrowsException()
    {
        // Arrange.
        var args = new[] { "privilege", "SeServiceLogonRight", "--grant", "DOMAIN\\User", "--revoke-all" };
        var rootCommand = CliBuilder.Build();

        // Act & Assert.
        Assert.Throws<SyntaxException>(() => rootCommand.Parse(args).ThrowIfInvalid().Run());
    }

    /// <summary>
    /// Ensures specifying no options is rejected.
    /// </summary>
    [TestMethod]
    public void NoOptionsThrowsException()
    {
        // Arrange.
        var args = new[] { "privilege" };
        var rootCommand = CliBuilder.Build();

        // Act & Assert.
        Assert.Throws<SyntaxException>(() => rootCommand.Parse(args).ThrowIfInvalid().Run());
    }

    /// <summary>
    /// Ensures overlapping or duplicate contexts are rejected.
    /// </summary>
    /// <param name="args">The test arguments.</param>
    [TestMethod]
    [DataRow("privilege", "SeServiceLogonRight", "--grant", "DOMAIN\\UserOrGroup", "--revoke", "DOMAIN\\UserOrGroup")]
    [DataRow("privilege", "SeServiceLogonRight", "--grant", "DOMAIN\\UserOrGroup", "--grant", "DOMAIN\\UserOrGroup")]
    [DataRow("privilege", "SeServiceLogonRight", "--revoke", "DOMAIN\\UserOrGroup", "--revoke", "DOMAIN\\UserOrGroup")]
    public void OverlappingGrantsAndRevokesThrowsException(params string[] args)
        => Assert.Throws<SyntaxException>(() => CliBuilder.Build().Parse(args).ThrowIfInvalid().Run());

    /// <summary>
    /// Ensures an empty or whitespace principal is rejected.
    /// </summary>
    /// <param name="args">The test arguments.</param>
    [TestMethod]
    [DataRow("privilege", "", "--grant", "DOMAIN\\UserOrGroup")]
    [DataRow("privilege", " ", "--grant", "DOMAIN\\UserOrGroup")]
    public void PrivilegeWithInvalidStringThrowsException(params string[] args)
        => Assert.Throws<SyntaxException>(() => CliBuilder.Build().Parse(args).ThrowIfInvalid().Run());

    /// <summary>
    /// Ensures revoking all contexts is accepted.
    /// </summary>
    [TestMethod]
    public void RevokeAllShouldWork()
    {
        // Arrange.
        var args = new[] { "privilege", "SeServiceLogonRight", "--revoke-all" };
        var rootCommand = CliBuilder.Build();

        // Act.
        var rc = rootCommand.Parse(args).ThrowIfInvalid().Run();

        // Assert.
        Assert.AreEqual(0, rc);
    }

    /// <summary>
    /// Ensures granting a context and revoking all contexts is rejected.
    /// </summary>
    [TestMethod]
    public void RevokeAllWithGrantsThrowsException()
    {
        // Arrange.
        var args = new[] { "privilege", "SeServiceLogonRight", "--revoke-all", "--grant", "DOMAIN\\UserOrGroup" };
        var rootCommand = CliBuilder.Build();

        // Act & Assert.
        Assert.Throws<SyntaxException>(() => rootCommand.Parse(args).ThrowIfInvalid().Run());
    }

    /// <summary>
    /// Ensures revoking a context and revoking all contexts is rejected.
    /// </summary>
    [TestMethod]
    public void RevokeAllWithRevocationsThrowsException()
    {
        // Arrange.
        var args = new[] { "privilege", "SeServiceLogonRight", "--revoke-all", "--revoke", "DOMAIN\\UserOrGroup" };
        var rootCommand = CliBuilder.Build();

        // Act & Assert.
        Assert.Throws<SyntaxException>(() => rootCommand.Parse(args).ThrowIfInvalid().Run());
    }

    /// <summary>
    /// Ensures revoking all contexts and revoking other contexts is rejected.
    /// </summary>
    [TestMethod]
    public void RevokeAllWithRevokeOthersThrowsException()
    {
        // Arrange.
        var args = new[] { "privilege", "SeServiceLogonRight", "--revoke-all", "--revoke-others" };
        var rootCommand = CliBuilder.Build();

        // Act & Assert.
        Assert.Throws<SyntaxException>(() => rootCommand.Parse(args).ThrowIfInvalid().Run());
    }

    /// <summary>
    /// Ensures revoking multiple contexts is accepted.
    /// </summary>
    [TestMethod]
    public void RevokeMultipleShouldWork()
    {
        // Arrange.
        var args = new[] { "privilege", "SeServiceLogonRight", "--revoke", "DOMAIN\\User", "--revoke", "DOMAIN\\Group" };
        var rootCommand = CliBuilder.Build();

        // Act.
        var rc = rootCommand.Parse(args).ThrowIfInvalid().Run();

        // Assert.
        Assert.AreEqual(0, rc);
    }

    /// <summary>
    /// Ensures revoke other contexts without granting a context is rejected.
    /// </summary>
    [TestMethod]
    public void RevokeOthersWithOutGrantsThrowsException()
    {
        // Arrange.
        var args = new[] { "privilege", "SeServiceLogonRight", "--revoke-others" };
        var rootCommand = CliBuilder.Build();

        // Act & Assert.
        Assert.Throws<SyntaxException>(() => rootCommand.Parse(args).ThrowIfInvalid().Run());
    }

    /// <summary>
    /// Ensures revoke other contexts with revoking a context is rejected.
    /// </summary>
    [TestMethod]
    public void RevokeOthersWithRevocationsThrowsException()
    {
        // Arrange.
        var args = new[] { "privilege", "SeServiceLogonRight", "--revoke-others", "--revoke", "DOMAIN\\UserOrGroup" };
        var rootCommand = CliBuilder.Build();

        // Act & Assert.
        Assert.Throws<SyntaxException>(() => rootCommand.Parse(args).ThrowIfInvalid().Run());
    }

    /// <summary>
    /// Ensures revoking a valid pattern is accepted.
    /// </summary>
    [TestMethod]
    public void RevokePatternShouldWork()
    {
        // Arrange.
        var args = new[] { "privilege", "SeServiceLogonRight", "--revoke-pattern", "^S-1-5-21-" };
        var rootCommand = CliBuilder.Build();

        // Act.
        var rc = rootCommand.Parse(args).ThrowIfInvalid().Run();

        // Assert.
        Assert.AreEqual(0, rc);
    }

    /// <summary>
    /// Ensures granting a context and revoking a valid pattern is accepted.
    /// </summary>
    [TestMethod]
    public void RevokePatternWithGrantShouldWork()
    {
        // Arrange.
        var args = new[] { "privilege", "SeServiceLogonRight", "--grant", "DOMAIN\\UserOrGroup", "--revoke-pattern", "^S-1-5-21-" };
        var rootCommand = CliBuilder.Build();

        // Act.
        var rc = rootCommand.Parse(args).ThrowIfInvalid().Run();

        // Assert.
        Assert.AreEqual(0, rc);
    }

    /// <summary>
    /// Ensures revoking a valid regex is accepted.
    /// </summary>
    /// <param name="args">The test arguments.</param>
    [TestMethod]
    [DataRow("privilege", "SeServiceLogonRight", "--revoke-pattern", "^xyz.*")]
    [DataRow("privilege", "SeServiceLogonRight", "--revoke-pattern", "^S-1-5-21-")]
    [DataRow("privilege", "SeServiceLogonRight", "--revoke-pattern", "(?i)^[A-Z]+")]
    public void RevokePatternWithValidRegexShouldWork(params string[] args)
    {
        // Arrange.
        var rootCommand = CliBuilder.Build();

        // Act.
        var rc = rootCommand.Parse(args).ThrowIfInvalid().Run();

        // Assert.
        Assert.AreEqual(0, rc);
    }

    /// <summary>
    /// Ensures revoking a pattern and revoking all contexts is rejected.
    /// </summary>
    [TestMethod]
    public void RevokePatternWithRevokeAllThrowsException()
    {
        // Arrange.
        var args = new[] { "privilege", "SeServiceLogonRight", "--revoke-pattern", "^S-1-5-21-", "--revoke-all" };
        var rootCommand = CliBuilder.Build();

        // Act & Assert.
        Assert.Throws<SyntaxException>(() => rootCommand.Parse(args).ThrowIfInvalid().Run());
    }

    /// <summary>
    /// Ensures revoking a pattern and revoking other contexts is rejected.
    /// </summary>
    [TestMethod]
    public void RevokePatternWithRevokeOthersThrowsException()
    {
        // Arrange.
        var args = new[] { "privilege", "SeServiceLogonRight", "--revoke-pattern", "^S-1-5-21-", "--revoke-others" };
        var rootCommand = CliBuilder.Build();

        // Act & Assert.
        Assert.Throws<SyntaxException>(() => rootCommand.Parse(args).ThrowIfInvalid().Run());
    }

    /// <summary>
    /// Ensures revoking a pattern and revoking a context is rejected.
    /// </summary>
    [TestMethod]
    public void RevokePatternWithRevokeThrowsException()
    {
        // Arrange.
        var args = new[] { "privilege", "SeServiceLogonRight", "--revoke-pattern", "^S-1-5-21-", "--revoke", "DOMAIN\\UserOrGroup" };
        var rootCommand = CliBuilder.Build();

        // Act & Assert.
        Assert.Throws<SyntaxException>(() => rootCommand.Parse(args).ThrowIfInvalid().Run());
    }

    /// <summary>
    /// Ensures revoking an invalid regex is rejected.
    /// </summary>
    /// <param name="args">The test arguments.</param>
    [TestMethod]
    [DataRow("privilege", "SeServiceLogonRight", "--revoke-pattern", "[0-9]{3,1}")]
    [DataRow("privilege", "SeServiceLogonRight", "--revoke-pattern", "^[S-1-5-21-")]
    public void RevokePatternWithInvalidRegexThrowsException(params string[] args)
        => Assert.Throws<SyntaxException>(() => CliBuilder.Build().Parse(args).ThrowIfInvalid().Run());

    /// <summary>
    /// Ensures an empty or whitespace revocation pattern is rejected.
    /// </summary>
    /// <param name="args">The test arguments.</param>
    [TestMethod]
    [DataRow("privilege", "SeServiceLogonRight", "--revoke-pattern", "")]
    [DataRow("privilege", "SeServiceLogonRight", "--revoke-pattern", " ")]
    public void RevokePatternWithInvalidStringThrowsException(params string[] args)
        => Assert.Throws<SyntaxException>(() => CliBuilder.Build().Parse(args).ThrowIfInvalid().Run());

    /// <summary>
    /// Ensures revoking a context is accepted.
    /// </summary>
    [TestMethod]
    public void RevokeShouldWork()
    {
        // Arrange.
        var args = new[] { "privilege", "SeServiceLogonRight", "--revoke", "DOMAIN\\UserOrGroup" };
        var rootCommand = CliBuilder.Build();

        // Act.
        var rc = rootCommand.Parse(args).ThrowIfInvalid().Run();

        // Assert.
        Assert.AreEqual(0, rc);
    }

    /// <summary>
    /// Ensures an empty or whitespace revocation is rejected.
    /// </summary>
    /// <param name="args">The test arguments.</param>
    [TestMethod]
    [DataRow("privilege", "SeServiceLogonRight", "--revoke", "")]
    [DataRow("privilege", "SeServiceLogonRight", "--revoke", " ")]
    public void RevokeWithInvalidStringThrowsException(params string[] args)
        => Assert.Throws<SyntaxException>(() => CliBuilder.Build().Parse(args).ThrowIfInvalid().Run());

    /// <summary>
    /// Ensures an empty or whitespace system name is rejected.
    /// </summary>
    /// <param name="args">The test arguments.</param>
    [TestMethod]
    [DataRow("privilege", "SeServiceLogonRight", "--grant", "DOMAIN\\UserOrGroup", "--system-name", "")]
    [DataRow("privilege", "SeServiceLogonRight", "--grant", "DOMAIN\\UserOrGroup", "--system-name", " ")]
    public void SystemNameWithInvalidStringThrowsException(params string[] args)
        => Assert.Throws<SyntaxException>(() => CliBuilder.Build().Parse(args).ThrowIfInvalid().Run());
}