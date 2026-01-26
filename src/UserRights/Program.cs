namespace UserRights;

using System.Globalization;
using System.Text;

using Microsoft.Extensions.DependencyInjection;

using Serilog;
using Serilog.Context;
using Serilog.Core;
using Serilog.Events;
using Serilog.Templates;
using Serilog.Templates.Themes;

using UserRights.Application;
using UserRights.Cli;
using UserRights.Logging;

using static UserRights.Logging.OperationId;

/// <summary>
/// Implements the user right utility.
/// </summary>
internal static class Program
{
    /// <summary>
    /// Represents the programs main entry point.
    /// </summary>
    /// <param name="args">The command line arguments.</param>
    /// <returns>A value representing the operation status code.</returns>
    private static async Task<int> Main(string[] args)
    {
        int rc;

        // Wrap the execution with error handling.
        try
        {
            rc = await Run(args).ConfigureAwait(false);
        }
        catch (SyntaxException e)
        {
            // Log syntax errors to assist with instrumenting automation.
            using (LogContext.PushProperty("EventId", SyntaxError))
            {
                Log.Fatal("{SyntaxError}", e.Message);
            }

            rc = 1;
        }
        catch (Exception e)
        {
            // Log all other errors as execution failures.
            using (LogContext.PushProperty("EventId", FatalError))
            {
                Log.Fatal(e, "Execution failed.");
            }

            rc = 2;
        }
        finally
        {
            await Log.CloseAndFlushAsync().ConfigureAwait(false);
        }

        return rc;
    }

    /// <summary>
    /// Formats command line arguments.
    /// </summary>
    /// <param name="args">The command line arguments.</param>
    /// <returns>A formatted string representation of the arguments.</returns>
    private static string FormatArguments(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);

        var stringBuilder = new StringBuilder();

        stringBuilder.Append('[');

        foreach (var arg in args)
        {
            stringBuilder.Append(CultureInfo.InvariantCulture, $" \"{arg}\"");
        }

        stringBuilder.Append(" ]");

        return stringBuilder.ToString();
    }

    /// <summary>
    /// Represents the programs execution logic.
    /// </summary>
    /// <param name="args">The command line arguments.</param>
    private static async Task<int> Run(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);

        // Use Coalesce to accomodate EventIds from Microsoft.Extensions.Logging and Serilog.
        const string consoleTemplate =
            "[{@t:yyyy-MM-dd HH:mm:ss.fff}] " +
            "[{@l}] " +
            "[{Coalesce(EventId.Id, EventId)}] " +
            "{#if DryRun = true}[DryRun] {#end}" +
            "{@m:l}\n" +
            "{#if ConsoleException is not null}{ConsoleException}\n{#end}";

        const string eventLogTemplate =
            "Context: {EnvironmentUserName}\n" +
            "Process Id: {ProcessId}\n" +
            "Correlation Id: {CorrelationId}\n" +
            "Arguments: {Arguments}\n\n" +
            "{@m:l}" +
            "{#if @x is not null}\n\n{@x}{#end}";

        // Configure the initial logging state with the console sink only enabled for warning level.
        var levelSwitch = new LoggingLevelSwitch { MinimumLevel = LogEventLevel.Warning };

        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Verbose()
            .Enrich.FromGlobalLogContext()
            .Enrich.FromLogContext()
            .Enrich.WithEnvironmentUserName()
            .Enrich.WithProcessId()
            .Enrich.WithProperty("Arguments", FormatArguments(args))
            .Enrich.WithProperty("CorrelationId", Guid.NewGuid())
            .Enrich.With<ConsoleExceptionEnricher>()
            .WriteTo.Console(
                new ExpressionTemplate(consoleTemplate, CultureInfo.InvariantCulture, theme: TemplateTheme.Literate),
                levelSwitch: levelSwitch,
                standardErrorFromLevel: LogEventLevel.Verbose)
            .WriteTo.EventLog(
                new ExpressionTemplate(eventLogTemplate, CultureInfo.InvariantCulture),
                nameof(UserRights),
                manageEventSource: true,
                eventIdProvider: new EventIdProvider())
            .CreateLogger();

        var serviceProvider = new ServiceCollection()
            .AddSingleton<ILsaUserRights, LsaUserRights>()
            .AddSingleton<IUserRightsManager, UserRightsManager>()
            .AddSingleton<CliBuilder>()
            .AddLogging(logging => logging.AddSerilog())
            .BuildServiceProvider();

        await using var _ = serviceProvider.ConfigureAwait(false);

        var builder = serviceProvider.GetRequiredService<CliBuilder>();

        var rootCommand = builder.Build();

        var parseResult = rootCommand.Parse(args).ThrowIfInvalid();

        if (!string.Equals(parseResult.CommandResult.Command.Name, "list", StringComparison.Ordinal))
        {
            levelSwitch.MinimumLevel = LogEventLevel.Verbose;
        }

        return await parseResult.RunAsync().ConfigureAwait(false);
    }
}