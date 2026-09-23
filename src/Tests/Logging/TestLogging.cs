namespace Tests.Logging;

using Microsoft.Extensions.Logging;

/// <summary>
/// Represents a class for configuring logging in unit tests.
/// </summary>
public static class TestLogging
{
    /// <summary>
    /// Creates a new instance of the <see cref="TestLogging"/> class.
    /// </summary>
    /// <param name="testContext">The test context instance.</param>
    /// <returns>An instance of a <see cref="ILoggerFactory"/> enabled for <see cref="LogLevel.Trace"/> with a <see cref="TestContextLogger"/>.</returns>
    public static ILoggerFactory CreateLoggerFactory(TestContext testContext)
    {
        ArgumentNullException.ThrowIfNull(testContext);

        return LoggerFactory.Create(builder =>
        {
            builder.SetMinimumLevel(LogLevel.Trace);
            builder.AddProvider(new TestContextLoggerProvider(testContext));
        });
    }
}