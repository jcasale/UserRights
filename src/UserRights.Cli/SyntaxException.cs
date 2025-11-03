namespace UserRights.Cli;

/// <summary>
/// Represents the exception that is thrown when a syntax error occurs.
/// </summary>
public class SyntaxException : Exception
{
    /// <summary>
    /// Initializes a new instance of the <see cref="SyntaxException" /> class.
    /// </summary>
    public SyntaxException()
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SyntaxException" /> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    public SyntaxException(string message)
        : base(message)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SyntaxException" /> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="innerException">The exception that is the cause of the current exception.</param>
    public SyntaxException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}