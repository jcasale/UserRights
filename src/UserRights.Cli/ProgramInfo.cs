namespace UserRights.Cli;

using System;
using System.Reflection;

/// <summary>
/// Represents information about the current program.
/// </summary>
public static class ProgramInfo
{
    /// <summary>
    /// Initializes static members of the <see cref = "ProgramInfo" /> class.
    /// </summary>
    static ProgramInfo()
    {
        var assembly = Assembly.GetEntryAssembly();
        if (assembly is null)
        {
            Version = string.Empty;
            InformationalVersion = string.Empty;
        }
        else
        {
            Version = assembly.GetName().Version?.ToString() ?? string.Empty;

            var assemblyVersionAttribute = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>();
            InformationalVersion = assemblyVersionAttribute is null ? Version : assemblyVersionAttribute.InformationalVersion;
        }
    }

    /// <summary>
    /// Gets the informational version of the assembly, which includes a shortened git hash.
    /// </summary>
    public static string InformationalVersion { get; }

    /// <summary>
    /// Gets the friendly name of this application domain.
    /// </summary>
    public static string Program { get; } = AppDomain.CurrentDomain.FriendlyName;

    /// <summary>
    /// Gets the major, minor, build, and revision numbers of the assembly.
    /// </summary>
    public static string Version { get; }
}