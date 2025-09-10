namespace Tests.Cli;

using Microsoft.Extensions.DependencyInjection;
using UserRights.Application;
using UserRights.Cli;
using Xunit;

/// <summary>
/// Represents syntax tests for list functionality.
/// </summary>
public sealed class ListSyntaxTests : CliTestBase
{
    private readonly CliBuilder _builder;

    /// <summary>
    /// Initializes a new instance of the <see cref="ListSyntaxTests"/> class.
    /// </summary>
    public ListSyntaxTests()
    {
        ServiceCollection.AddSingleton<ILsaUserRights, MockLsaUserRights>();
        ServiceCollection.AddSingleton<IUserRightsManager, MockUserRightsManager>();
        ServiceCollection.AddSingleton<CliBuilder>();

        _builder = ServiceProvider.GetRequiredService<CliBuilder>();
    }

    /// <summary>
    /// Verifies list mode with CSV formatted output sent to STDOUT is parsed successfully.
    /// </summary>
    [Fact]
    public void CsvToStdoutShouldWork()
    {
        var args = new[] { "list" };
        var configuration = _builder.Build();

        var rc = configuration.Parse(args).Validate().Invoke();

        Assert.Equal(0, rc);
    }

    /// <summary>
    /// Verifies list mode with CSV formatted output sent to a file is parsed successfully.
    /// </summary>
    [Fact]
    public void CsvToPathShouldWork()
    {
        var args = new[] { "list", "--path", "file.csv" };
        var configuration = _builder.Build();

        var rc = configuration.Parse(args).Validate().Invoke();

        Assert.Equal(0, rc);
    }

    /// <summary>
    /// Ensures an empty or whitespace path is rejected.
    /// </summary>
    /// <param name="args">The test arguments.</param>
    [Theory]
    [InlineData("list", "--path", "")]
    [InlineData("list", "--path", " ")]
    public void PathWithInvalidStringThrowsException(params string[] args)
        => Assert.Throws<SyntaxException>(() => _builder.Build().Parse(args).Validate().Invoke());

    /// <summary>
    /// Ensures an empty or whitespace system name is rejected.
    /// </summary>
    /// <param name="args">The test arguments.</param>
    [Theory]
    [InlineData("list", "--system-name", "")]
    [InlineData("list", "--system-name", " ")]
    public void SystemNameWithInvalidStringThrowsException(params string[] args)
        => Assert.Throws<SyntaxException>(() => _builder.Build().Parse(args).Validate().Invoke());

    /// <summary>
    /// Verifies list mode with JSON formatted output sent to STDOUT is parsed successfully.
    /// </summary>
    [Fact]
    public void JsonToStdoutShouldWork()
    {
        var args = new[] { "list", "--json" };
        var configuration = _builder.Build();

        var rc = configuration.Parse(args).Validate().Invoke();

        Assert.Equal(0, rc);
    }

    /// <summary>
    /// Verifies list mode with JSON formatted output sent to a file is parsed successfully.
    /// </summary>
    [Fact]
    public void JsonToPathShouldWork()
    {
        var args = new[] { "list", "--json", "--path", "file.csv" };
        var configuration = _builder.Build();

        var rc = configuration.Parse(args).Validate().Invoke();

        Assert.Equal(0, rc);
    }
}