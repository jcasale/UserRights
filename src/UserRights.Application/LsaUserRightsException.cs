namespace UserRights.Application;

using System;
using System.Runtime.Serialization;

/// <summary>
/// Represents the exception that is thrown when an error occurs interacting with the local security authority user right functions.
/// </summary>
[Serializable]
public class LsaUserRightsException : Exception
{
    /// <summary>
    /// Initializes a new instance of the <see cref="LsaUserRightsException" /> class.
    /// </summary>
    public LsaUserRightsException()
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="LsaUserRightsException" /> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    public LsaUserRightsException(string message)
        : base(message)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="LsaUserRightsException" /> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="innerException">The exception that is the cause of the current exception.</param>
    public LsaUserRightsException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="LsaUserRightsException" /> class.
    /// </summary>
    /// <param name="info">The <see cref="SerializationInfo" /> that holds the serialized object data about the exception being thrown.</param>
    /// <param name="context">The <see cref="StreamingContext" /> that contains contextual information about the source or destination.</param>
    protected LsaUserRightsException(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
    }
}