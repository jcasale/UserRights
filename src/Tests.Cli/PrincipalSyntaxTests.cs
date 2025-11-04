namespace Tests.Cli;

using UserRights.Cli;

/// <summary>
/// Represents syntax tests for principal functionality.
/// </summary>
[TestClass]
public sealed class PrincipalSyntaxTests : CliBuilderFixture
{
    /// <summary>
    /// Ensures granting a privilege and revoking a different privilege is accepted.
    /// </summary>
    [TestMethod]
    public void GrantAndRevokeShouldWork()
    {
        // Arrange.
        var args = new[] { "principal", "DOMAIN\\UserOrGroup", "--grant", "SeServiceLogonRight", "--revoke", "SeBatchLogonRight" };
        var rootCommand = CliBuilder.Build();

        // Act.
        var rc = rootCommand.Parse(args).ThrowIfInvalid().Run();

        // Assert.
        Assert.AreEqual(0, rc);
    }

    /// <summary>
    /// Ensures granting multiple privileges is accepted.
    /// </summary>
    [TestMethod]
    public void GrantMultipleShouldWork()
    {
        // Arrange.
        var args = new[] { "principal", "DOMAIN\\UserOrGroup", "--grant", "SeServiceLogonRight", "--grant", "SeBatchLogonRight" };
        var rootCommand = CliBuilder.Build();

        // Act.
        var rc = rootCommand.Parse(args).ThrowIfInvalid().Run();

        // Assert.
        Assert.AreEqual(0, rc);
    }

    /// <summary>
    /// Ensures granting a privilege is accepted.
    /// </summary>
    [TestMethod]
    public void GrantShouldWork()
    {
        // Arrange.
        var args = new[] { "principal", "DOMAIN\\UserOrGroup", "--grant", "SeServiceLogonRight" };
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
    [DataRow("principal", "DOMAIN\\UserOrGroup", "--grant", "")]
    [DataRow("principal", "DOMAIN\\UserOrGroup", "--grant", " ")]
    public void GrantWithInvalidStringThrowsException(params string[] args)
        => Assert.Throws<SyntaxException>(() => CliBuilder.Build().Parse(args).ThrowIfInvalid().Run());

    /// <summary>
    /// Ensures granting a privilege and revoking all other privileges is rejected.
    /// </summary>
    [TestMethod]
    public void GrantWithRevokeAllThrowsException()
    {
        // Arrange.
        var args = new[] { "principal", "DOMAIN\\UserOrGroup", "--grant", "SeServiceLogonRight", "--revoke-all" };
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
        var args = new[] { "principal" };
        var rootCommand = CliBuilder.Build();

        // Act & Assert.
        Assert.Throws<SyntaxException>(() => rootCommand.Parse(args).ThrowIfInvalid().Run());
    }

    /// <summary>
    /// Ensures overlapping or duplicate privileges are rejected.
    /// </summary>
    /// <param name="args">The test arguments.</param>
    [TestMethod]
    [DataRow("principal", "DOMAIN\\UserOrGroup", "--grant", "SeServiceLogonRight", "--revoke", "SeServiceLogonRight")]
    [DataRow("principal", "DOMAIN\\UserOrGroup", "--grant", "SeServiceLogonRight", "--grant", "SeServiceLogonRight")]
    [DataRow("principal", "DOMAIN\\UserOrGroup", "--revoke", "SeServiceLogonRight", "--revoke", "SeServiceLogonRight")]
    public void OverlappingGrantsAndRevokesThrowsException(params string[] args)
        => Assert.Throws<SyntaxException>(() => CliBuilder.Build().Parse(args).ThrowIfInvalid().Run());

    /// <summary>
    /// Ensures an empty or whitespace principal is rejected.
    /// </summary>
    /// <param name="args">The test arguments.</param>
    [TestMethod]
    [DataRow("principal", "", "--grant", "SeServiceLogonRight")]
    [DataRow("principal", " ", "--grant", "SeServiceLogonRight")]
    public void PrincipalWithInvalidStringThrowsException(params string[] args)
        => Assert.Throws<SyntaxException>(() => CliBuilder.Build().Parse(args).ThrowIfInvalid().Run());

    /// <summary>
    /// Ensures revoking all privileges is accepted.
    /// </summary>
    [TestMethod]
    public void RevokeAllShouldWork()
    {
        // Arrange.
        var args = new[] { "principal", "DOMAIN\\UserOrGroup", "--revoke-all" };
        var rootCommand = CliBuilder.Build();

        // Act.
        var rc = rootCommand.Parse(args).ThrowIfInvalid().Run();

        // Assert.
        Assert.AreEqual(0, rc);
    }

    /// <summary>
    /// Ensures granting a privilege and revoking all privileges is rejected.
    /// </summary>
    [TestMethod]
    public void RevokeAllWithGrantsThrowsException()
    {
        // Arrange.
        var args = new[] { "principal", "DOMAIN\\UserOrGroup", "--revoke-all", "--grant", "SeServiceLogonRight" };
        var rootCommand = CliBuilder.Build();

        // Act & Assert.
        Assert.Throws<SyntaxException>(() => rootCommand.Parse(args).ThrowIfInvalid().Run());
    }

    /// <summary>
    /// Ensures revoking a privilege and revoking all privileges is rejected.
    /// </summary>
    [TestMethod]
    public void RevokeAllWithRevocationsThrowsException()
    {
        // Arrange.
        var args = new[] { "principal", "DOMAIN\\UserOrGroup", "--revoke-all", "--revoke", "SeServiceLogonRight" };
        var rootCommand = CliBuilder.Build();

        // Act & Assert.
        Assert.Throws<SyntaxException>(() => rootCommand.Parse(args).ThrowIfInvalid().Run());
    }

    /// <summary>
    /// Ensures revoking all privileges and revoking other privileges is rejected.
    /// </summary>
    [TestMethod]
    public void RevokeAllWithRevokeOthersThrowsException()
    {
        // Arrange.
        var args = new[] { "principal", "DOMAIN\\UserOrGroup", "--revoke-all", "--revoke-others" };
        var rootCommand = CliBuilder.Build();

        // Act & Assert.
        Assert.Throws<SyntaxException>(() => rootCommand.Parse(args).ThrowIfInvalid().Run());
    }

    /// <summary>
    /// Ensures revoking multiple privileges is accepted.
    /// </summary>
    [TestMethod]
    public void RevokeMultipleShouldWork()
    {
        // Arrange.
        var args = new[] { "principal", "DOMAIN\\UserOrGroup", "--revoke", "SeServiceLogonRight", "--revoke", "SeBatchLogonRight" };
        var rootCommand = CliBuilder.Build();

        // Act.
        var rc = rootCommand.Parse(args).ThrowIfInvalid().Run();

        // Assert.
        Assert.AreEqual(0, rc);
    }

    /// <summary>
    /// Ensures revoke other privileges without granting a privilege is rejected.
    /// </summary>
    [TestMethod]
    public void RevokeOthersWithOutGrantsThrowsException()
    {
        // Arrange.
        var args = new[] { "principal", "DOMAIN\\UserOrGroup", "--revoke-others" };

        // Act & Assert.
        Assert.Throws<SyntaxException>(() => CliBuilder.Build().Parse(args).ThrowIfInvalid().Run());
    }

    /// <summary>
    /// Ensures revoke other privileges while also revoking a privilege is rejected.
    /// </summary>
    [TestMethod]
    public void RevokeOthersWithRevocationsThrowsException()
    {
        // Arrange.
        var args = new[] { "principal", "DOMAIN\\UserOrGroup", "--revoke-others", "--revoke", "SeServiceLogonRight" };
        var rootCommand = CliBuilder.Build();

        // Act & Assert.
        Assert.Throws<SyntaxException>(() => rootCommand.Parse(args).ThrowIfInvalid().Run());
    }

    /// <summary>
    /// Ensures revoking a privilege is accepted.
    /// </summary>
    [TestMethod]
    public void RevokeShouldWork()
    {
        // Arrange.
        var args = new[] { "principal", "DOMAIN\\UserOrGroup", "--revoke", "SeServiceLogonRight" };
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
    [DataRow("principal", "DOMAIN\\UserOrGroup", "--revoke", "")]
    [DataRow("principal", "DOMAIN\\UserOrGroup", "--revoke", " ")]
    public void RevokeWithInvalidStringThrowsException(params string[] args)
        => Assert.Throws<SyntaxException>(() => CliBuilder.Build().Parse(args).ThrowIfInvalid().Run());

    /// <summary>
    /// Ensures an empty or whitespace system name is rejected.
    /// </summary>
    /// <param name="args">The test arguments.</param>
    [TestMethod]
    [DataRow("principal", "DOMAIN\\UserOrGroup", "--grant", "SeServiceLogonRight", "--system-name", "")]
    [DataRow("principal", "DOMAIN\\UserOrGroup", "--grant", "SeServiceLogonRight", "--system-name", " ")]
    public void SystemNameWithInvalidStringThrowsException(params string[] args)
        => Assert.Throws<SyntaxException>(() => CliBuilder.Build().Parse(args).ThrowIfInvalid().Run());
}