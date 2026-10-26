namespace UserRights.Extensions.Security;

/// <summary>
/// Represents the exception thrown when an error occurs translating security contexts.
/// </summary>
public class SecurityTranslationException : Exception
{
    /// <summary>
    /// Initializes a new instance of the <see cref="SecurityTranslationException" /> class.
    /// </summary>
    public SecurityTranslationException()
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SecurityTranslationException" /> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    public SecurityTranslationException(string message)
        : base(message)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SecurityTranslationException" /> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="innerException">The exception that is the cause of the current exception.</param>
    public SecurityTranslationException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}