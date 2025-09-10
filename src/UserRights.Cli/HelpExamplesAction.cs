namespace UserRights.Cli;

using System;
using System.CommandLine;
using System.CommandLine.Help;
using System.CommandLine.Invocation;
using System.Globalization;
using System.Text;

/// <summary>
/// Represents a command-line action that provides help information for examples.
/// </summary>
public class HelpExamplesAction : SynchronousCommandLineAction
{
    private readonly HelpAction helpAction;

    /// <summary>
    /// Initializes a new instance of the <see cref="HelpExamplesAction"/> class.
    /// </summary>
    /// <param name="helpAction">The default help action instance.</param>
    public HelpExamplesAction(HelpAction helpAction)
    {
        ArgumentNullException.ThrowIfNull(helpAction);

        helpAction = helpAction;
    }

    /// <inheritdoc />
    public override int Invoke(ParseResult parseResult)
    {
        ArgumentNullException.ThrowIfNull(parseResult);

        var result = helpAction.Invoke(parseResult);

        GenerateExamples(parseResult);

        return result;
    }

    /// <summary>
    /// Adds examples to the help output based on the command being executed.
    /// </summary>
    /// <param name="parseResult">The default help action instance.</param>
    private static void GenerateExamples(ParseResult parseResult)
    {
        ArgumentNullException.ThrowIfNull(parseResult);

        string[] examples;
        switch (parseResult.CommandResult.IdentifierToken.Value)
        {
            case "list":

                examples =
                [
                    "list",
                    "list --json",
                    "list --path x:\\path\\file.csv"
                ];

                break;

            case "principal":

                examples =
                [
                    "principal DOMAIN\\UserOrGroup --grant SeDenyServiceLogonRight",
                    "principal DOMAIN\\UserOrGroup --revoke SeDenyServiceLogonRight",
                    "principal DOMAIN\\UserOrGroup --grant SeServiceLogonRight --revoke SeDenyServiceLogonRight",
                    "principal DOMAIN\\UserOrGroup --grant SeServiceLogonRight --grant SeInteractiveLogonRight --revoke-others"
                ];

                break;

            case "privilege":

                examples =
                [
                    "privilege SeServiceLogonRight --grant DOMAIN\\UserOrGroup --revoke DOMAIN\\Group",
                    "privilege SeServiceLogonRight --revoke DOMAIN\\UserOrGroup",
                    "privilege SeServiceLogonRight --grant DOMAIN\\UserOrGroup --revoke-pattern \"^S-1-5-21-\"",
                    "privilege SeServiceLogonRight --revoke-pattern \"^S-1-5-21-\"",
                    "privilege SeServiceLogonRight --revoke-all"
                ];

                break;

            default:

                return;
        }

        var stringBuilder = new StringBuilder();
        stringBuilder.AppendLine("Examples:");

        foreach (var example in examples)
        {
            stringBuilder.AppendLine(CultureInfo.InvariantCulture, $"  {ProgramInfo.Program} {example}");
        }

        parseResult.Configuration.Output.WriteLine(stringBuilder.ToString().TrimEnd());
    }
}