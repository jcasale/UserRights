namespace Tests.Application;

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
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
    private const string SecurityDatabaseName = "secedit.db";
    private const string SecurityTemplateName = "secedit.ini";
    private const string SecurityExportLogName = "export.log";
    private const string SecurityRestoreLogName = "restore.log";

    private readonly DirectoryInfo directory = CreateTempDirectory();
    private readonly IReadOnlyDictionary<string, IReadOnlyCollection<SecurityIdentifier>> initialState;

    private bool disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="LsaUserRightsTestBase"/> class.
    /// </summary>
    protected LsaUserRightsTestBase()
    {
        try
        {
            // Create a backup to restore during disposal.
            CreateSecurityDatabaseBackup(this.directory);

            // Load the contents of the backup for use as initial state.
            this.initialState = ReadSecurityDatabaseBackup(this.directory);
        }
        catch
        {
            this.directory = null;

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
            if (this.disposed)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }

            return this.initialState;
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        this.Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Releases resources when they are no longer required.
    /// </summary>
    /// <param name="disposing">A value indicating whether the method call comes from a dispose method (its value is <c>true</c>) or from a finalizer (its value is <c>false</c>).</param>
    protected virtual void Dispose(bool disposing)
    {
        if (this.disposed)
        {
            return;
        }

        if (disposing)
        {
            if (this.directory is not null)
            {
                RestoreSecurityDatabaseBackup(this.directory);

                this.directory.Delete(true);
            }

            this.disposed = true;
        }
    }

    /// <summary>
    /// Gets the current state of the security database.
    /// </summary>
    /// <returns>A map of privilege to security identifiers.</returns>
    protected IReadOnlyDictionary<string, IReadOnlyCollection<SecurityIdentifier>> GetCurrentState()
    {
        if (this.disposed)
        {
            throw new ObjectDisposedException(this.GetType().FullName);
        }

        var directoryInfo = CreateTempDirectory();

        CreateSecurityDatabaseBackup(directoryInfo);

        var results = ReadSecurityDatabaseBackup(directoryInfo);

        directoryInfo.Delete(true);

        return results;
    }

    /// <summary>
    /// Creates a backup of the security database.
    /// </summary>
    /// <param name="directory">The temporary directory to create files in.</param>
    private static void CreateSecurityDatabaseBackup(DirectoryInfo directory)
    {
        if (directory is null)
        {
            throw new ArgumentNullException(nameof(directory));
        }

        var arguments = string.Format(
            CultureInfo.InvariantCulture,
            "/export /cfg {0} /areas user_rights /log {1} /quiet",
            SecurityTemplateName,
            SecurityExportLogName);

        var stringBuilder = new StringBuilder();

        using var process = new Process();

        process.StartInfo.FileName = "secedit.exe";
        process.StartInfo.Arguments = arguments;
        process.StartInfo.WorkingDirectory = directory.FullName;
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
    /// <param name="directory">The temporary directory where the backup files reside.</param>
    /// <returns>A map of privilege to security identifiers.</returns>
    private static IReadOnlyDictionary<string, IReadOnlyCollection<SecurityIdentifier>> ReadSecurityDatabaseBackup(DirectoryInfo directory)
    {
        if (directory is null)
        {
            throw new ArgumentNullException(nameof(directory));
        }

        var path = Path.Combine(directory.FullName, SecurityTemplateName);

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
                var securityIdentifier = value.StartsWith("*", StringComparison.Ordinal)
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
    /// <param name="directory">The temporary directory where the backup files reside.</param>
    private static void RestoreSecurityDatabaseBackup(DirectoryInfo directory)
    {
        if (directory is null)
        {
            throw new ArgumentNullException(nameof(directory));
        }

        var arguments = string.Format(
            CultureInfo.InvariantCulture,
            "/configure /db {0} /cfg {1} /areas user_rights /log {2} /quiet",
            SecurityDatabaseName,
            SecurityTemplateName,
            SecurityRestoreLogName);

        var stringBuilder = new StringBuilder();

        using var process = new Process();

        process.StartInfo.FileName = "secedit.exe";
        process.StartInfo.Arguments = arguments;
        process.StartInfo.WorkingDirectory = directory.FullName;
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