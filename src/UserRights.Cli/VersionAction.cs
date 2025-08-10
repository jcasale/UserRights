namespace UserRights.Cli;

using System;
using System.CommandLine;
using System.CommandLine.Invocation;

/// <summary>
/// Represents an action that outputs the version of the application with a shortened git hash.
/// </summary>
public class VersionAction : SynchronousCommandLineAction
{
    /// <inheritdoc />
    public override int Invoke(ParseResult parseResult)
    {
        ArgumentNullException.ThrowIfNull(parseResult);

        // Write a more sane informational version using only part of the git hash.
        parseResult.Configuration.Output.WriteLine(ProgramInfo.InformationalVersion);

        return 0;
    }
}