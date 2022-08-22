namespace UserRights;

using System;
using System.Globalization;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Serilog;
using Serilog.Context;
using Serilog.Core;
using Serilog.Events;
using Serilog.Templates;
using UserRights.Application;
using UserRights.Cli;

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
    private static int Main(string[] args)
    {
        // Wrap the execution with error handling.
        try
        {
            Run(args);
        }
        catch (Exception e) when (e is Spectre.Console.Cli.CommandRuntimeException or SyntaxException)
        {
            // Log syntax errors to assist with instrumenting automation.
            using (LogContext.PushProperty("EventId", OperationId.SyntaxError))
            {
                Log.Fatal("Syntax error: {Message:l}", e.Message);
            }

            return 1;
        }
        catch (Exception e)
        {
            // Log all other errors as execution failures.
            using (LogContext.PushProperty("EventId", OperationId.FatalError))
            {
                Log.Fatal(e, "Execution failed.");
            }

            return 1;
        }
        finally
        {
            Log.CloseAndFlush();
        }

        return 0;
    }

    /// <summary>
    /// Formats command line arguments.
    /// </summary>
    /// <param name="args">The command line arguments.</param>
    /// <returns>A formatted string representation of the arguments.</returns>
    private static string FormatArguments(string[] args)
    {
        if (args is null)
        {
            throw new ArgumentNullException(nameof(args));
        }

        var stringBuilder = new StringBuilder();

        stringBuilder.Append('[');

        foreach (var arg in args)
        {
            stringBuilder.AppendFormat(CultureInfo.InvariantCulture, " \"{0}\"", arg);
        }

        stringBuilder.Append(" ]");

        return stringBuilder.ToString();
    }

    /// <summary>
    /// Represents the programs execution logic.
    /// </summary>
    /// <param name="args">The command line arguments.</param>
    private static void Run(string[] args)
    {
        if (args is null)
        {
            throw new ArgumentNullException(nameof(args));
        }

        // Use Coalesce to accomodate EventIds from Microsoft.Extensions.Logging and Serilog.
        const string consoleTemplate =
            "[{@t:yyyy-MM-dd HH:mm:ss.fff}] " +
            "[{@l}] " +
            "[{Coalesce(EventId.Id, EventId)}] " +
            "{#if DryRun = true}[DryRun] {#end}" +
            "{@m:l}\n" +
            "{@x}";

        const string eventLogTemplate =
            "{@m:l}\n\n" +
            "Context: {EnvironmentUserName}\n" +
            "Process Id: {ProcessId}\n" +
            "Correlation Id: {CorrelationId}\n" +
            "Arguments: {Arguments}" +
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
            .WriteTo.Console(
                new ExpressionTemplate(consoleTemplate),
                levelSwitch: levelSwitch,
                standardErrorFromLevel: LogEventLevel.Verbose)
            .WriteTo.EventLog(
                new ExpressionTemplate(eventLogTemplate),
                nameof(UserRights),
                manageEventSource: true,
                eventIdProvider: new EventIdProvider())
            .CreateLogger();

        var serviceCollection = new ServiceCollection()
            .AddSingleton<ILsaUserRights, LsaUserRights>()
            .AddSingleton<IUserRightsManager, UserRightsManager>()
            .AddLogging(logging => logging.AddSerilog());

        using var registrar = new TypeRegistrar(serviceCollection);

        var interceptor = new LogInterceptor(levelSwitch);
        var commandApp = CommandAppBuilder.Build(registrar, interceptor);

        commandApp.Run(args);
    }
}