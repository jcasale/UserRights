namespace Tests.Application;

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Principal;
using System.Text;

using Microsoft.Extensions.Configuration;
using UserRights.Application;
using UserRights.Extensions.Security;

/// <summary>
/// Represents the test base for <see cref="LsaUserRights"/> application.
/// </summary>
public abstract class LsaUserRightsTestBase : IDisposable
{
    private const string ExportSecurityTemplateName = "export.ini";
    private const string ExportSecurityLogName = "export.log";
    private const string RestoreSecurityDatabaseName = "restore.db";
    private const string RestoreSecurityTemplateName = "restore.ini";
    private const string RestoreSecurityLogName = "restore.log";

    private readonly DirectoryInfo? _directory = CreateTempDirectory();
    private readonly IReadOnlyDictionary<string, IReadOnlyCollection<SecurityIdentifier>> _initialState;

    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="LsaUserRightsTestBase"/> class.
    /// </summary>
    protected LsaUserRightsTestBase()
    {
        try
        {
            // Create a backup to restore during disposal.
            CreateSecurityDatabaseBackup(_directory.FullName);

            // Load the contents of the backup for use as initial state.
            _initialState = ReadSecurityDatabaseBackup(_directory.FullName);

            // Create the updated configuration file to remove assignments for any privileges that were originally empty.
            CreateRestoreTemplate(_directory.FullName, _initialState);
        }
        catch
        {
            _directory = null;

            throw;
        }
    }

    /// <summary>
    /// Gets the initial state of user rights assignments before they are modified through test execution.
    /// </summary>
    protected IReadOnlyDictionary<string, IReadOnlyCollection<SecurityIdentifier>> InitialState
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            return _initialState;
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
                RestoreSecurityDatabaseBackup(_directory.FullName);

                _directory.Delete(true);
            }

            _disposed = true;
        }
    }

    /// <summary>
    /// Gets the current state of the security database.
    /// </summary>
    /// <returns>A map of privilege to security identifiers.</returns>
    protected IReadOnlyDictionary<string, IReadOnlyCollection<SecurityIdentifier>> GetCurrentState()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var directoryInfo = CreateTempDirectory();

        CreateSecurityDatabaseBackup(directoryInfo.FullName);

        var results = ReadSecurityDatabaseBackup(directoryInfo.FullName);

        directoryInfo.Delete(true);

        return results;
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

            var entry = string.Format(CultureInfo.InvariantCulture, "{0} =", privilege);
            lines.Insert(index + 1, entry);
        }

        // Write restore template.
        var pathRestore = Path.Combine(workingDirectory, RestoreSecurityTemplateName);

        File.WriteAllLines(pathRestore, lines, Encoding.Unicode);
    }

    /// <summary>
    /// Creates a backup of the security database.
    /// </summary>
    /// <param name="workingDirectory">The path to a directory where the backup files will be created.</param>
    private static void CreateSecurityDatabaseBackup(string workingDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(workingDirectory);

        var arguments = string.Format(
            CultureInfo.InvariantCulture,
            "/export /cfg {0} /areas user_rights /log {1}",
            ExportSecurityTemplateName,
            ExportSecurityLogName);

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

        process.WaitForExit(5000);

        if (process.ExitCode != 0)
        {
            var message = string.Format(
                CultureInfo.InvariantCulture,
                "Failed to export the security database, exit code: {0}\r\n{1}",
                process.ExitCode,
                stringBuilder);

            throw new InvalidOperationException(message);
        }
    }

    /// <summary>
    /// Creates a temporary directory.
    /// </summary>
    /// <returns>The temporary directory info instance.</returns>
    private static DirectoryInfo CreateTempDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        var directoryInfo = new DirectoryInfo(path);

        if (directoryInfo.Exists)
        {
            throw new InvalidOperationException("Failed to create temporary directory.");
        }

        directoryInfo.Create();

        return directoryInfo;
    }

    /// <summary>
    /// Reads a backup of the security database.
    /// </summary>
    /// <param name="workingDirectory">The path to a directory where the backup files exist.</param>
    /// <returns>A map of privilege to security identifiers.</returns>
    private static IReadOnlyDictionary<string, IReadOnlyCollection<SecurityIdentifier>> ReadSecurityDatabaseBackup(string workingDirectory)
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
                    ? new SecurityIdentifier(value.TrimStart('*'))
                    : value.ToSecurityIdentifier();

                securityIdentifiers.Add(securityIdentifier);
            }

            dictionary.Add(child.Key, securityIdentifiers.AsReadOnly());
        }

        return new ReadOnlyDictionary<string, IReadOnlyCollection<SecurityIdentifier>>(dictionary);
    }

    /// <summary>
    /// Restores a backup of the security database.
    /// </summary>
    /// <param name="workingDirectory">The path to a directory where the backup files exist.</param>
    private static void RestoreSecurityDatabaseBackup(string workingDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(workingDirectory);

        var arguments = string.Format(
            CultureInfo.InvariantCulture,
            "/configure /db {0} /cfg {1} /areas user_rights /log {2}",
            RestoreSecurityDatabaseName,
            RestoreSecurityTemplateName,
            RestoreSecurityLogName);

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

        process.WaitForExit(5000);

        if (process.ExitCode != 0)
        {
            var message = string.Format(
                CultureInfo.InvariantCulture,
                "Failed to restore the security database, exit code: {0}\r\n{1}",
                process.ExitCode,
                stringBuilder);

            throw new InvalidOperationException(message);
        }
    }
}