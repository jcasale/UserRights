namespace Tests.Logging;

using Microsoft.Extensions.Logging;

/// <summary>
/// Represents a logger that writes log messages to a <see cref="TestContext"/>.
/// </summary>
internal sealed class TestContextLogger : ILogger
{
    private readonly TestContext _testContext;
    private readonly string _category;

    /// <summary>
    /// Initializes a new instance of the <see cref="TestContextLogger"/> class.
    /// </summary>
    /// <param name="testContext">The test context instance.</param>
    /// <param name="category">The logging category.</param>
    public TestContextLogger(TestContext testContext, string category)
    {
        ArgumentNullException.ThrowIfNull(testContext);
        ArgumentException.ThrowIfNullOrWhiteSpace(category);

        _testContext = testContext;
        _category = category;
    }

    /// <inheritdoc />
    public IDisposable BeginScope<TState>(TState state)
        where TState : notnull => NullScope.Instance;

    /// <inheritdoc />
    public bool IsEnabled(LogLevel logLevel) => logLevel != LogLevel.None;

    /// <inheritdoc />
    public void Log<TState>(
        LogLevel logLevel,
        EventId eventId,
        TState state,
        Exception? exception,
        Func<TState, Exception?, string> formatter)
    {
        if (!IsEnabled(logLevel))
        {
            return;
        }

        var message = formatter(state, exception);
        _testContext.WriteLine($"[{logLevel}] {_category}: {message}");

        if (exception is not null)
        {
            _testContext.WriteLine(exception.ToString());
        }
    }
}