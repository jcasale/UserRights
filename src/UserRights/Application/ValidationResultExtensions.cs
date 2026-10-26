namespace UserRights.Application;

/// <summary>
/// Represents extension methods for <see cref="ValidationResult"/> objects.
/// </summary>
public static class ValidationResultExtensions
{
    /// <summary>
    /// Adds validation errors to an error handler.
    /// </summary>
    /// <param name="result">The validation result containing errors.</param>
    /// <param name="addError">The action to invoke for each error message.</param>
    public static void AddErrorsTo(this ValidationResult result, Action<string> addError)
    {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(addError);

        foreach (var (_, message) in result.Errors)
        {
            addError(message);
        }
    }

    /// <summary>
    /// Throws an <see cref="ArgumentException"/> if the validation results contain errors.
    /// </summary>
    /// <param name="result">The validation result to check.</param>
    /// <exception cref="ArgumentException">Thrown when the validation result contains errors.</exception>
    public static void ThrowIfInvalid(this ValidationResult result)
    {
        ArgumentNullException.ThrowIfNull(result);

        if (result.IsValid)
        {
            return;
        }

        var (parameterName, message) = result.Errors[0];

        throw new ArgumentException(message, parameterName);
    }
}