namespace Tests.Logging;

using Microsoft.Extensions.Logging;
using Microsoft.VisualStudio.TestTools.UnitTesting;

/// <summary>
/// Represents a logger provider that writes log messages to a <see cref="TestContext"/>.
/// </summary>
public sealed class TestContextLoggerProvider : ILoggerProvider
{
    private readonly TestContext _testContext;

    /// <summary>
    /// Initializes a new instance of the <see cref="TestContextLoggerProvider"/> class.
    /// </summary>
    /// <param name="testContext">The test context instance.</param>
    public TestContextLoggerProvider(TestContext testContext) =>
        _testContext = testContext ?? throw new ArgumentNullException(nameof(testContext));

    /// <inheritdoc />
    public ILogger CreateLogger(string categoryName) =>
        new TestContextLogger(_testContext, categoryName);

    /// <inheritdoc />
    public void Dispose()
    {
    }
}