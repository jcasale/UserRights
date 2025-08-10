namespace UserRights.Cli;

using System;
using System.CommandLine;
using System.Globalization;
using System.Text;

/// <summary>
/// Represents extensions for parsing and invoking command line arguments.
/// </summary>
public static class CliExtensions
{
    /// <summary>
    /// Validates the parse result for any errors.
    /// </summary>
    /// <param name="parseResult">The command line input parsing results.</param>
    /// <returns>The validated command line input parsing results.</returns>
    /// <exception cref="SyntaxException">Thrown when the parse results contain any errors.</exception>
    public static ParseResult Validate(this ParseResult parseResult)
    {
        ArgumentNullException.ThrowIfNull(parseResult);

        if (parseResult.Errors.Count > 0)
        {
            var stringBuilder = new StringBuilder();
            stringBuilder.AppendLine("Syntax error:");

            foreach (var error in parseResult.Errors)
            {
                stringBuilder.AppendLine(CultureInfo.InvariantCulture, $"  - {error.Message}");
            }

            throw new SyntaxException(stringBuilder.ToString().TrimEnd());
        }

        return parseResult;
    }
}