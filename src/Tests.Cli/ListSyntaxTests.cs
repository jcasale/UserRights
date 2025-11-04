namespace Tests.Cli;

using UserRights.Cli;

/// <summary>
/// Represents syntax tests for list functionality.
/// </summary>
[TestClass]
public sealed class ListSyntaxTests : CliBuilderFixture
{
    /// <summary>
    /// Verifies list mode with CSV formatted output sent to STDOUT is parsed successfully.
    /// </summary>
    [TestMethod]
    public void CsvToStdoutShouldWork()
    {
        // Arrange.
        var args = new[] { "list" };
        var rootCommand = CliBuilder.Build();

        // Act.
        var rc = rootCommand.Parse(args).ThrowIfInvalid().Run();

        // Assert.
        Assert.AreEqual(0, rc);
    }

    /// <summary>
    /// Verifies list mode with CSV formatted output sent to a file is parsed successfully.
    /// </summary>
    [TestMethod]
    public void CsvToPathShouldWork()
    {
        // Arrange.
        var args = new[] { "list", "--path", "file.csv" };
        var rootCommand = CliBuilder.Build();

        // Act.
        var rc = rootCommand.Parse(args).ThrowIfInvalid().Run();

        // Assert.
        Assert.AreEqual(0, rc);
    }

    /// <summary>
    /// Ensures an empty or whitespace path is rejected.
    /// </summary>
    /// <param name="args">The test arguments.</param>
    [TestMethod]
    [DataRow("list", "--path", "")]
    [DataRow("list", "--path", " ")]
    public void PathWithInvalidStringThrowsException(params string[] args)
        => Assert.Throws<SyntaxException>(() => CliBuilder.Build().Parse(args).ThrowIfInvalid().Run());

    /// <summary>
    /// Ensures an empty or whitespace system name is rejected.
    /// </summary>
    /// <param name="args">The test arguments.</param>
    [TestMethod]
    [DataRow("list", "--system-name", "")]
    [DataRow("list", "--system-name", " ")]
    public void SystemNameWithInvalidStringThrowsException(params string[] args)
        => Assert.Throws<SyntaxException>(() => CliBuilder.Build().Parse(args).ThrowIfInvalid().Run());

    /// <summary>
    /// Verifies list mode with JSON formatted output sent to STDOUT is parsed successfully.
    /// </summary>
    [TestMethod]
    public void JsonToStdoutShouldWork()
    {
        // Arrange.
        var args = new[] { "list", "--json" };
        var rootCommand = CliBuilder.Build();

        // Act.
        var rc = rootCommand.Parse(args).ThrowIfInvalid().Run();

        // Assert.
        Assert.AreEqual(0, rc);
    }

    /// <summary>
    /// Verifies list mode with JSON formatted output sent to a file is parsed successfully.
    /// </summary>
    [TestMethod]
    public void JsonToPathShouldWork()
    {
        // Arrange.
        var args = new[] { "list", "--json", "--path", "file.json" };
        var rootCommand = CliBuilder.Build();

        // Act.
        var rc = rootCommand.Parse(args).ThrowIfInvalid().Run();

        // Assert.
        Assert.AreEqual(0, rc);
    }
}