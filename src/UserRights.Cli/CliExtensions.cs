namespace UserRights.Cli;

using System;
using System.CommandLine;
using System.Globalization;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

/// <summary>
/// Represents extensions for parsing and invoking command line arguments.
/// </summary>
public static class CliExtensions
{
    /// <summary>
    /// Invokes the appropriate command handler for a parsed command line input.
    /// </summary>
    /// <param name="parseResult">The command line input parsing results.</param>
    /// <param name="cancellationToken">A token that can be used to cancel an invocation.</param>
    /// <returns>A task whose result can be used as a process exit code.</returns>
    public static async Task<int> RunAsync(this ParseResult parseResult, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(parseResult);

        var invocationConfiguration = new InvocationConfiguration
        {
            // Disable the default exception handler to allow logging errors to the event log.
            EnableDefaultExceptionHandler = false
        };

        return await parseResult.InvokeAsync(invocationConfiguration, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Invokes the appropriate command handler for a parsed command line input.
    /// </summary>
    /// <param name="parseResult">The command line input parsing results.</param>
    /// <returns>A value that can be used as a process exit code.</returns>
    public static int Run(this ParseResult parseResult)
    {
        ArgumentNullException.ThrowIfNull(parseResult);

        var invocationConfiguration = new InvocationConfiguration
        {
            // Disable the default exception handler to allow logging errors to the event log.
            EnableDefaultExceptionHandler = false
        };

        return parseResult.Invoke(invocationConfiguration);
    }

    /// <summary>
    /// Throws a <see cref="SyntaxException"/> if <see cref="ParseResult.Errors"/> contains any errors.
    /// </summary>
    /// <param name="parseResult">The command line input parsing results.</param>
    /// <returns>The same command line input parsing results.</returns>
    /// <exception cref="SyntaxException">Thrown when the parse results contain any errors.</exception>
    public static ParseResult ThrowIfInvalid(this ParseResult parseResult)
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