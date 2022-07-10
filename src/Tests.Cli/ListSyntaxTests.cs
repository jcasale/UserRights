namespace Tests.Cli;

using UserRights.Application;
using Xunit;

/// <summary>
/// Represents syntax tests for list functionality.
/// </summary>
public sealed class ListSyntaxTests : CliTestBase
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ListSyntaxTests"/> class.
    /// </summary>
    public ListSyntaxTests()
    {
        this.Registrar.Register(typeof(ILsaUserRights), typeof(MockLsaUserRights));
        this.Registrar.Register(typeof(IUserRightsManager), typeof(MockUserRightsManager));
    }

    /// <summary>
    /// Verifies list mode with CSV formatted output sent to STDOUT is parsed successfully.
    /// </summary>
    [Fact]
    public void CsvToStdoutShouldWork()
    {
        var args = new[] { "list" };

        var exception = Record.Exception(() => this.CommandApp.Run(args));

        Assert.Null(exception);
    }

    /// <summary>
    /// Verifies list mode with CSV formatted output sent to a file is parsed successfully.
    /// </summary>
    [Fact]
    public void CsvToPathShouldWork()
    {
        var args = new[] { "list", "--path", "file.csv" };

        var exception = Record.Exception(() => this.CommandApp.Run(args));

        Assert.Null(exception);
    }

    /// <summary>
    /// Verifies list mode with JSON formatted output sent to STDOUT is parsed successfully.
    /// </summary>
    [Fact]
    public void JsonToStdoutShouldWork()
    {
        var args = new[] { "list", "--json" };

        var exception = Record.Exception(() => this.CommandApp.Run(args));

        Assert.Null(exception);
    }

    /// <summary>
    /// Verifies list mode with JSON formatted output sent to a file is parsed successfully.
    /// </summary>
    [Fact]
    public void JsonToPathShouldWork()
    {
        var args = new[] { "list", "--json", "--path", "file.csv" };

        var exception = Record.Exception(() => this.CommandApp.Run(args));

        Assert.Null(exception);
    }
}