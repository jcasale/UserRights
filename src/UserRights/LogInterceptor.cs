namespace UserRights;

using System;
using Serilog;
using Serilog.Context;
using Serilog.Core;
using Serilog.Events;
using Spectre.Console.Cli;
using UserRights.Application;
using UserRights.Cli;

/// <summary>
/// Updates logging configuration and instruments application details before execution.
/// </summary>
public class LogInterceptor : ICommandInterceptor
{
    private readonly LoggingLevelSwitch levelSwitch;

    /// <summary>
    /// Initializes a new instance of the <see cref="LogInterceptor"/> class.
    /// </summary>
    /// <param name="levelSwitch">The console sink level switch.</param>
    public LogInterceptor(LoggingLevelSwitch levelSwitch) => this.levelSwitch = levelSwitch ?? throw new ArgumentNullException(nameof(levelSwitch));

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

                this.UpdateLoggingConfiguration();

                break;

            case PrivilegeSettings s:
                operationId = OperationId.PrivilegeMode;
                mode = "privilege";
                dryRun = s.DryRun;

                this.UpdateLoggingConfiguration();

                break;

            default:
                throw new InvalidOperationException($"The command settings type was unexpected: {settings.GetType()}.");
        }

        GlobalLogContext.PushProperty("DryRun", dryRun);

        var program = AppDomain.CurrentDomain.FriendlyName;
        var version = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;

        using (LogContext.PushProperty("EventId", operationId))
        {
            Log.Information("{Program:l} v{Version} executing in {Mode:l} mode.", program, version, mode);
        }
    }

    /// <summary>
    /// Updates logging configuration for any non-list mode.
    /// </summary>
    private void UpdateLoggingConfiguration() => this.levelSwitch.MinimumLevel = LogEventLevel.Verbose;
}