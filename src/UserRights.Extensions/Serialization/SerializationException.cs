namespace UserRights.Extensions.Serialization;

using System;

/// <summary>
/// Represents the exception thrown when an error occurs serializing data.
/// </summary>
public class SerializationException : Exception
{
    /// <summary>
    /// Initializes a new instance of the <see cref="SerializationException" /> class.
    /// </summary>
    public SerializationException()
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SerializationException" /> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    public SerializationException(string message)
        : base(message)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SerializationException" /> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="innerException">The exception that is the cause of the current exception.</param>
    public SerializationException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}