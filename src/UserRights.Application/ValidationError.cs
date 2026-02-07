namespace UserRights.Application;

/// <summary>
/// Represents a parameter validation error.
/// </summary>
public record ValidationError
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ValidationError"/> class.
    /// </summary>
    /// <param name="parameterName">The name of the parameter that failed validation.</param>
    /// <param name="message">The validation error message.</param>
    public ValidationError(string parameterName, string message)
    {
        ArgumentException.ThrowIfNullOrEmpty(parameterName);
        ArgumentException.ThrowIfNullOrEmpty(message);

        ParameterName = parameterName;
        Message = message;
    }

    /// <summary>
    /// Gets the name of the parameter that failed validation.
    /// </summary>
    public string ParameterName { get; }

    /// <summary>
    /// Gets the validation error message.
    /// </summary>
    public string Message { get; }

    /// <summary>
    /// Returns the deconstructed values of the validation error.
    /// </summary>
    /// <param name="parameterName">The name of the parameter that failed validation.</param>
    /// <param name="message">The validation error message.</param>
    public void Deconstruct(out string parameterName, out string message)
    {
        parameterName = ParameterName;
        message = Message;
    }
}