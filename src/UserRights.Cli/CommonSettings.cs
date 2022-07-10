namespace UserRights.Cli;

using System.ComponentModel;
using Spectre.Console.Cli;

/// <summary>
/// Represents settings common to all command invocation modes.
/// </summary>
public class CommonSettings : CommandSettings
{
    /// <summary>
    /// Gets or sets the remote system name to execute the task on (default localhost).
    /// </summary>
    [Description("The remote system name to execute the task on (default localhost).")]
    [CommandOption("-s|--system-name")]
    public string SystemName { get; set; }
}