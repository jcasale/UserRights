namespace UserRights;

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NLog.Extensions.Logging;
using UserRights.Application;
using UserRights.Cli;

/// <summary>
/// Implements the user right utility.
/// </summary>
internal static class Program
{
    private static readonly NLog.Logger Logger = NLog.LogManager.GetCurrentClassLogger();

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
            var logEvent = new NLog.LogEventInfo(
                NLog.LogLevel.Fatal,
                nameof(Program),
                CultureInfo.InvariantCulture,
                "Syntax error: {Message:l}",
                new object[] { e.Message },
                null);

            logEvent.Properties.Add(nameof(NLog.Targets.EventLogTarget.EventId), OperationId.SyntaxError);

            Logger.Log(logEvent);

            return 1;
        }
        catch (Exception e)
        {
            // Log all other errors as execution failures.
            var logEvent = new NLog.LogEventInfo(
                NLog.LogLevel.Fatal,
                nameof(Program),
                CultureInfo.InvariantCulture,
                "Execution failed.",
                Array.Empty<object>(),
                e);

            logEvent.Properties.Add(nameof(NLog.Targets.EventLogTarget.EventId), OperationId.FatalError);

            Logger.Log(logEvent);

            return 1;
        }
        finally
        {
            NLog.LogManager.Shutdown();
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
    /// Gets the initial logging configuration.
    /// </summary>
    private static NLog.Config.LoggingConfiguration GetInitialLoggingConfiguration()
    {
        var programName = AppDomain.CurrentDomain.FriendlyName;
        var eventLogSource = Path.GetFileNameWithoutExtension(programName);

        var configuration = new NLog.Config.LoggingConfiguration();

        // Create the console target and set the output to the error stream.
        var consoleTarget = new NLog.Targets.ColoredConsoleTarget(nameof(NLog.Targets.ColoredConsoleTarget))
        {
            DetectOutputRedirected = true,
            StdErr = true,
            Layout =
                "[${longDate}] " +
                "[${level}] " +
                "[${event-properties:EventId:whenEmpty=0}] " +
                "${when:when='${scopeProperty:DryRun}'==true:inner=[DRYRUN] }" +
                "${message}" +
                "${onException:${newline}${exception:format=ShortType,Message:innerFormat=ShortType,Message:maxInnerExceptionLevel=10:separator=\\: }}"
        };

        var consoleRule = new NLog.Config.LoggingRule("*", NLog.LogLevel.Warn, NLog.LogLevel.Fatal, consoleTarget)
        {
            RuleName = nameof(NLog.Targets.ColoredConsoleTarget)
        };

        configuration.LoggingRules.Add(consoleRule);

        // Create the Windows event log target.
        var eventLogTarget = new NLog.Targets.EventLogTarget(nameof(NLog.Targets.EventLogTarget))
        {
            EventId = "${event-properties:EventId:whenEmpty=0}",
            Layout =
                "${message}${newline}${newline}" +
                "Context: ${environment:USERDOMAIN}\\${environment:USERNAME}${newline}" +
                "Process Id: ${processId}${newline}" +
                "Correlation Id: ${scopeProperty:CorrelationId}${newline}" +
                "Arguments: ${scopeProperty:Arguments}" +
                "${onException:${newline}${newline}${exception:format=ToString:innerFormat=ToString:maxInnerExceptionLevel=10}}",
            Source = eventLogSource
        };

        var eventLogRule = new NLog.Config.LoggingRule("*", NLog.LogLevel.Trace, NLog.LogLevel.Fatal, eventLogTarget)
        {
            RuleName = nameof(NLog.Targets.EventLogTarget)
        };

        configuration.LoggingRules.Add(eventLogRule);

        return configuration;
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

        // Configure the initial logging state with the console target only enabled for warning level.
        var configuration = GetInitialLoggingConfiguration();

        // Update configuration and reconfigure all loggers.
        NLog.LogManager.Configuration = configuration;

        var scope = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase)
        {
            // Add a correlation id to the scope to differentiate invocations that run concurrently.
            ["CorrelationId"] = Guid.NewGuid(),

            // Add the command line arguments to the scope for instrumenting automation.
            ["Arguments"] = FormatArguments(args)
        };

        Logger.PushScopeProperties(scope);

        var serviceCollection = new ServiceCollection()
            .AddSingleton<ILsaUserRights, LsaUserRights>()
            .AddSingleton<IUserRightsManager, UserRightsManager>()
            .AddLogging(builder => builder
                .ClearProviders()
                .SetMinimumLevel(LogLevel.Trace)
                .AddNLog(configuration));

        using var registrar = new TypeRegistrar(serviceCollection);

        var interceptor = new LogInterceptor();
        var commandApp = CommandAppBuilder.Build(registrar, interceptor);

        commandApp.Run(args);
    }
}