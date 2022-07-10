namespace UserRights;

using System;
using System.Collections.Generic;
using System.Globalization;
using Spectre.Console.Cli;
using UserRights.Application;
using UserRights.Cli;

/// <summary>
/// Updates logging configuration and instruments application details before execution.
/// </summary>
public class LogInterceptor : ICommandInterceptor
{
    private static readonly NLog.Logger Logger = NLog.LogManager.GetCurrentClassLogger();

    /// <inheritdoc />
    public void Intercept(CommandContext context, CommandSettings settings)
    {
        if (settings is null)
        {
            throw new ArgumentNullException(nameof(settings));
        }

        int operationId;
        string mode;
        bool dryRun;
        switch (settings)
        {
            case ListSettings:
                operationId = OperationId.ListMode;
                mode = "list";
                dryRun = false;

                break;

            case PrincipalSettings s:
                operationId = OperationId.PrincipalMode;
                mode = "principal";
                dryRun = s.DryRun;

                UpdateLoggingConfiguration();

                break;

            case PrivilegeSettings s:
                operationId = OperationId.PrivilegeMode;
                mode = "privilege";
                dryRun = s.DryRun;

                UpdateLoggingConfiguration();

                break;

            default:
                throw new InvalidOperationException($"The command settings type was unexpected: {settings.GetType()}.");
        }

        var scope = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase) { ["DryRun"] = dryRun };

        Logger.PushScopeProperties(scope);

        var program = AppDomain.CurrentDomain.FriendlyName;
        var version = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;

        var logEvent = new NLog.LogEventInfo(
            NLog.LogLevel.Info,
            nameof(Program),
            CultureInfo.InvariantCulture,
            "{Program:l} v{Version} executing in {Mode:l} mode.",
            new object[] { program, version, mode });

        logEvent.Properties.Add(nameof(NLog.Targets.EventLogTarget.EventId), operationId);

        Logger.Log(logEvent);
    }

    /// <summary>
    /// Updates logging configuration for any non-list mode.
    /// </summary>
    private static void UpdateLoggingConfiguration()
    {
        // Get the current configuration.
        var configuration = NLog.LogManager.Configuration;

        // Update the console rule to enable all log levels.
        var rule = configuration.FindRuleByName(nameof(NLog.Targets.ColoredConsoleTarget));
        rule.EnableLoggingForLevels(NLog.LogLevel.Trace, NLog.LogLevel.Fatal);

        // Update configuration and reconfigure all loggers.
        NLog.LogManager.Configuration = configuration;
    }
}