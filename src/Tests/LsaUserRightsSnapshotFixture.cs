namespace Tests;

using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Globalization;
using System.Reflection;
using System.Security.Principal;
using System.Text;

using Microsoft.Extensions.Configuration;

using UserRights.Extensions.Security;

/// <summary>
/// Represents a test fixture for preserving the state of the local security authority (LSA) database during test execution.
/// </summary>
/// <remarks>
/// This fixture creates a temporary directory and backs up the security database when instantiated, then restores it during disposal.
/// </remarks>
public class LsaUserRightsSnapshotFixture : IDisposable
{
    private const string ExportSecurityTemplateName = "export.ini";
    private const string ExportSecurityLogName = "export.log";
    private const string RestoreSecurityDatabaseName = "restore.db";
    private const string RestoreSecurityTemplateName = "restore.ini";
    private const string RestoreSecurityLogName = "restore.log";

    private readonly string _exportSecurityArguments = string.Create(
        CultureInfo.InvariantCulture,
        $"/export /cfg {ExportSecurityTemplateName} /areas user_rights /log {ExportSecurityLogName}");

    private readonly string _restoreSecurityArguments = string.Create(
        CultureInfo.InvariantCulture,
        $"/configure /db {RestoreSecurityDatabaseName} /cfg {RestoreSecurityTemplateName} /areas user_rights /log {RestoreSecurityLogName}");

    private readonly DirectoryInfo? _directory;
    private readonly IReadOnlyDictionary<string, IReadOnlyCollection<SecurityIdentifier>> _initialState;

    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="LsaUserRightsSnapshotFixture"/> class.
    /// </summary>
    public LsaUserRightsSnapshotFixture()
    {
        _directory = CreateTempDirectory();

        try
        {
            // Create a backup to restore during disposal.
            RunSecurityEditor(_exportSecurityArguments, _directory.FullName);

            // Load the contents of the backup for use as initial state.
            _initialState = ReadSecurityDatabaseBackup(_directory.FullName);

            // Create the updated configuration file to remove assignments for any privileges that were originally empty.
            CreateRestoreTemplate(_directory.FullName, _initialState);
        }
        catch
        {
            // Prevent disposal from restoring the backup or deleting the temporary directory if initialization fails.
            _directory = null;

            throw;
        }
    }

    /// <summary>
    /// Gets the initial state of user rights assignments before they are modified through test execution.
    /// </summary>
    public IReadOnlyDictionary<string, IReadOnlyCollection<SecurityIdentifier>> InitialState
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            return _initialState;
        }
    }

    /// <summary>
    /// Gets the current state of the security database.
    /// </summary>
    /// <returns>A map of privilege to security identifiers.</returns>
    public IReadOnlyDictionary<string, IReadOnlyCollection<SecurityIdentifier>> GetCurrentState()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var directoryInfo = CreateTempDirectory();
        try
        {
            RunSecurityEditor(_exportSecurityArguments, directoryInfo.FullName);

            return ReadSecurityDatabaseBackup(directoryInfo.FullName);
        }
        finally
        {
            directoryInfo.Delete(true);
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Releases resources when they are no longer required.
    /// </summary>
    /// <param name="disposing">A value indicating whether the method call comes from a dispose method (its value is <see langword="true"/>) or from a finalizer (its value is <see langword="false"/>).</param>
    protected virtual void Dispose(bool disposing)
    {
        if (_disposed)
        {
            return;
        }

        if (disposing)
        {
            if (_directory is not null)
            {
                RunSecurityEditor(_restoreSecurityArguments, _directory.FullName);

                _directory.Delete(true);
            }
        }

        _disposed = true;
    }

    /// <summary>
    /// Creates an updated restore template.
    /// </summary>
    /// <param name="workingDirectory">The path to a directory where the backup files exist.</param>
    /// <param name="stateBackup">The map of privilege to security identifiers for the backup configuration file.</param>
    private static void CreateRestoreTemplate(string workingDirectory, IReadOnlyDictionary<string, IReadOnlyCollection<SecurityIdentifier>> stateBackup)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(workingDirectory);
        ArgumentNullException.ThrowIfNull(stateBackup);

        // Load existing assignments.
        var pathBackup = Path.Combine(workingDirectory, ExportSecurityTemplateName);

        var lines = File.ReadAllLines(pathBackup).ToList();

        // Locate the start of the assignments.
        var index = lines.IndexOf("[Privilege Rights]");
        if (index == -1)
        {
            throw new InvalidOperationException("Failed to determine index of privilege rights.");
        }

        var privileges = typeof(PrivilegeConstants)
            .GetFields(BindingFlags.Public | BindingFlags.Static)
            .Where(p => p.IsLiteral)
            .Select(p => p.Name);

        // Add an empty privilege for each unset assignment to force the removal of any new assignments for previously unset privileges.
        foreach (var privilege in privileges)
        {
            if (stateBackup.ContainsKey(privilege))
            {
                continue;
            }

            var entry = string.Create(CultureInfo.InvariantCulture, $"{privilege} =");
            lines.Insert(index + 1, entry);
        }

        // Write restore template.
        var pathRestore = Path.Combine(workingDirectory, RestoreSecurityTemplateName);

        File.WriteAllLines(pathRestore, lines, Encoding.Unicode);
    }

    /// <summary>
    /// Creates a temporary directory.
    /// </summary>
    /// <returns>The temporary directory info instance.</returns>
    private static DirectoryInfo CreateTempDirectory() => Directory.CreateTempSubdirectory("userrights-");

    /// <summary>
    /// Reads a backup of the security database.
    /// </summary>
    /// <param name="workingDirectory">The path to a directory where the backup files exist.</param>
    /// <returns>A map of privilege to security identifiers.</returns>
    private static ReadOnlyDictionary<string, IReadOnlyCollection<SecurityIdentifier>> ReadSecurityDatabaseBackup(string workingDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(workingDirectory);

        var path = Path.Combine(workingDirectory, ExportSecurityTemplateName);

        using var manager = new ConfigurationManager();
        var configuration = manager
            .AddIniFile(path)
            .Build();

        var section = configuration.GetSection("Privilege Rights");
        var children = section.GetChildren();

        var dictionary = new Dictionary<string, IReadOnlyCollection<SecurityIdentifier>>(StringComparer.Ordinal);

        foreach (var child in children)
        {
            if (string.IsNullOrWhiteSpace(child.Value))
            {
                continue;
            }

            var securityIdentifiers = new List<SecurityIdentifier>();

            var values = child.Value.Split(',');
            foreach (var value in values)
            {
                var securityIdentifier = value.StartsWith('*')
                    ? new(value.TrimStart('*'))
                    : value.ToSecurityIdentifier();

                securityIdentifiers.Add(securityIdentifier);
            }

            dictionary.Add(child.Key, securityIdentifiers.AsReadOnly());
        }

        return new(dictionary);
    }

    /// <summary>
    /// Executes the security editor utility.
    /// </summary>
    /// <param name="arguments">The command line arguments to pass to the security editor utility.</param>
    /// <param name="workingDirectory">The path to a directory where the backup files exist.</param>
    private static void RunSecurityEditor(string arguments, string workingDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(workingDirectory);
        ArgumentException.ThrowIfNullOrWhiteSpace(workingDirectory);

        var stringBuilder = new StringBuilder();

        using var process = new Process();

        process.StartInfo.FileName = "secedit.exe";
        process.StartInfo.Arguments = arguments;
        process.StartInfo.WorkingDirectory = workingDirectory;
        process.StartInfo.CreateNoWindow = true;
        process.StartInfo.UseShellExecute = false;
        process.StartInfo.RedirectStandardError = true;

        process.ErrorDataReceived += (_, args) => stringBuilder.AppendLine(args.Data);

        process.Start();

        process.BeginErrorReadLine();

        process.WaitForExit();

        if (process.ExitCode != 0)
        {
            var message = string.Create(
                CultureInfo.InvariantCulture,
                $"Failed to execute the security editor utility, exit code: {process.ExitCode}\r\n{stringBuilder}");

            throw new InvalidOperationException(message);
        }
    }
}