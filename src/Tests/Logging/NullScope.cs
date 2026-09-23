namespace Tests.Logging;

/// <summary>
/// Represents a no-op logging scope.
/// </summary>
internal sealed class NullScope : IDisposable
{
    /// <summary>
    /// Gets a singleton instance of the <see cref="NullScope"/> class.
    /// </summary>
    public static readonly NullScope Instance = new();

    /// <inheritdoc />
    public void Dispose()
    {
    }
}