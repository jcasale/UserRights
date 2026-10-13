namespace UserRights;

using System.Globalization;
using System.Security;
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
    // Use Coalesce to accomodate EventIds from Microsoft.Extensions.Logging and Serilog.
    private const string ConsoleTemplate =
        "[{@t:yyyy-MM-dd HH:mm:ss.fff}] " +
        "[{@l}] " +
        "[{Coalesce(EventId.Id, EventId)}] " +
        "{#if DryRun = true}[DryRun] {#end}" +
        "{@m:l}\n" +
        "{#if ConsoleException is not null}{ConsoleException}\n{#end}";

    private const string EventLogTemplate =
        "Context: {EnvironmentUserName}\n" +
        "Process Id: {ProcessId}\n" +
        "Correlation Id: {CorrelationId}\n" +
        "Arguments: {Arguments}\n\n" +
        "{@m:l}" +
        "{#if @x is not null}\n\n{@x}{#end}";

    /// <summary>
    /// Represents the programs main entry point.
    /// </summary>
    /// <param name="args">The command line arguments.</param>
    /// <returns>A value representing the operation status code.</returns>
    private static async Task<int> Main(string[] args)
    {
        // Configure a minimal console logger so failures while configuring the full logger are reported.
        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Verbose()
            .Enrich.FromLogContext()
            .Enrich.With<ConsoleExceptionEnricher>()
            .WriteTo.Console(
                new ExpressionTemplate(ConsoleTemplate, CultureInfo.InvariantCulture, theme: TemplateTheme.Literate),
                standardErrorFromLevel: LogEventLevel.Verbose)
            .CreateBootstrapLogger();

        // Wrap the execution with error handling.
        try
        {
            return await Run(args).ConfigureAwait(false);
        }
        catch (SyntaxException e)
        {
            // Log syntax errors to assist with instrumenting automation.
            using (LogContext.PushProperty("EventId", SyntaxError))
            {
                Log.Fatal("{SyntaxError}", e.Message);
            }

            return 1;
        }
        catch (Exception e)
        {
            // Log all other errors as execution failures.
            using (LogContext.PushProperty("EventId", FatalError))
            {
                Log.Fatal(e, "Execution failed.");
            }

            return 2;
        }
        finally
        {
            await Log.CloseAndFlushAsync().ConfigureAwait(false);
        }
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
    /// Configures the full logger that reconfigures the bootstrap logger.
    /// </summary>
    /// <param name="configuration">The logger configuration to populate.</param>
    /// <param name="levelSwitch">The switch that controls the minimum level of the console sink.</param>
    /// <param name="args">The command line arguments.</param>
    private static void ConfigureLogger(LoggerConfiguration configuration, LoggingLevelSwitch levelSwitch, string[] args)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(levelSwitch);
        ArgumentNullException.ThrowIfNull(args);

        configuration
            .MinimumLevel.Verbose()
            .Enrich.FromGlobalLogContext()
            .Enrich.FromLogContext()
            .Enrich.WithEnvironmentUserName()
            .Enrich.WithProcessId()
            .Enrich.WithProperty("Arguments", FormatArguments(args))
            .Enrich.WithProperty("CorrelationId", Guid.NewGuid())
            .Enrich.With<ConsoleExceptionEnricher>()
            .WriteTo.Console(
                new ExpressionTemplate(ConsoleTemplate, CultureInfo.InvariantCulture, theme: TemplateTheme.Literate),
                levelSwitch: levelSwitch,
                standardErrorFromLevel: LogEventLevel.Verbose);

        try
        {
            configuration.WriteTo.EventLog(
                new ExpressionTemplate(EventLogTemplate, CultureInfo.InvariantCulture),
                nameof(UserRights),
                manageEventSource: true,
                eventIdProvider: new EventIdProvider());
        }
        catch (Exception e) when (e is ArgumentException or InvalidOperationException or SecurityException)
        {
            // The event log sink is unavailable, so this only reaches the console through the bootstrap logger.
            using (LogContext.PushProperty("EventId", EventLogError))
            {
                Log.Warning(e, "Events will not be written to the Windows event log because it could not be configured.");
            }
        }
    }

    /// <summary>
    /// Represents the programs execution logic.
    /// </summary>
    /// <param name="args">The command line arguments.</param>
    private static async Task<int> Run(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);

        // Configure the initial logging state with the console sink only enabled for warning level.
        var levelSwitch = new LoggingLevelSwitch { MinimumLevel = LogEventLevel.Warning };

        // The logger is not disposed with the service provider, Main flushes and disposes it so errors can still be logged.
        var serviceProvider = new ServiceCollection()
            .AddSingleton<ILsaUserRights, LsaUserRights>()
            .AddSingleton<IUserRightsManager, UserRightsManager>()
            .AddSingleton<CliBuilder>()
            .AddLogging()
            .AddSerilog((_, configuration) => ConfigureLogger(configuration, levelSwitch, args))
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