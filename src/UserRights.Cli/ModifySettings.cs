namespace UserRights.Cli;

using System;
using System.ComponentModel;
using System.Linq;
using Spectre.Console;
using Spectre.Console.Cli;

/// <summary>
/// Represents the common settings for all invocation modes that modify the security database.
/// </summary>
public abstract class ModifySettings : CommonSettings
{
    /// <summary>
    /// Gets or sets the entries to grant to the implemented context.
    /// </summary>
    public abstract string[] Grants { get; set; }

    /// <summary>
    /// Gets or sets the entries to revoke from the implemented context.
    /// </summary>
    public abstract string[] Revocations { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether to enable dry-run mode.
    /// </summary>
    [Description("Enables dry-run mode.")]
    [CommandOption("-d|--dry-run")]
    public bool DryRun { get; set; }

    /// <inheritdoc />
    public override ValidationResult Validate()
    {
        // Ensure grants and revocations do not overlap or contain duplicates.
        var grants = this.Grants.ToHashSet(StringComparer.InvariantCultureIgnoreCase);
        var revocations = this.Revocations.ToHashSet(StringComparer.InvariantCultureIgnoreCase);

        if (grants.Overlaps(revocations))
        {
            return ValidationResult.Error("The grants and revocations cannot overlap.");
        }

        if (grants.Count != this.Grants.Length)
        {
            return ValidationResult.Error("The grants cannot contain duplicates.");
        }

        if (revocations.Count != this.Revocations.Length)
        {
            return ValidationResult.Error("The revocations cannot contain duplicates.");
        }

        return ValidationResult.Success();
    }
}