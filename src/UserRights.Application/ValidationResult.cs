namespace UserRights.Application;

/// <summary>
/// Represents a container for the results of a parameter validation request.
/// </summary>
public record ValidationResult
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ValidationResult"/> class.
    /// </summary>
    /// <param name="errors">The collection of validation errors.</param>
    public ValidationResult(IEnumerable<ValidationError> errors)
    {
        ArgumentNullException.ThrowIfNull(errors);

        Errors = [.. errors];
    }

    /// <summary>
    /// Prevents a default instance of the <see cref="ValidationResult"/> class from being created.
    /// </summary>
    private ValidationResult() => Errors = [];

    /// <summary>
    /// Gets a successful validation result with no errors.
    /// </summary>
    public static ValidationResult Success { get; } = new();

    /// <summary>
    /// Gets the collection of validation errors.
    /// </summary>
    public IReadOnlyList<ValidationError> Errors { get; }

    /// <summary>
    /// Gets a value indicating whether the validation was successful.
    /// </summary>
    public bool IsValid => Errors.Count == 0;
}