namespace UserRights.Cli;

using System.ComponentModel;
using Spectre.Console.Cli;

/// <summary>
/// Represents the list mode command settings.
/// </summary>
public sealed class ListSettings : CommonSettings
{
    /// <summary>
    /// Gets or sets a value indicating whether to format the output in JSON instead of CSV.
    /// </summary>
    [Description("Formats output in JSON instead of CSV.")]
    [CommandOption("-j|--json")]
    public bool Json { get; set; }

    /// <summary>
    /// Gets or sets the path to a file to write the output to instead of STDOUT.
    /// </summary>
    [Description("Writes output to the specified path instead of STDOUT.")]
    [CommandOption("-f|--path")]
    public string Path { get; set; }
}