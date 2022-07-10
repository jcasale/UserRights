namespace UserRights.Cli;

using System;
using System.ComponentModel;
using System.Text.RegularExpressions;
using Spectre.Console;
using Spectre.Console.Cli;

/// <summary>
/// Represents the privilege mode command settings.
/// </summary>
public sealed class PrivilegeSettings : ModifySettings
{
    /// <summary>
    /// Gets or sets the privilege to modify.
    /// </summary>
    [Description("The privilege to modify.")]
    [CommandArgument(0, "<privilege>")]
    public string Privilege { get; set; }

    /// <summary>
    /// Gets or sets the principals to grant the privilege to.
    /// </summary>
    [Description("The principal to grant the privilege to.")]
    [CommandOption("-g|--grant")]
    public override string[] Grants { get; set; } = Array.Empty<string>();

    /// <summary>
    /// Gets or sets the principals to revoke the privilege from.
    /// </summary>
    [Description("The principal to revoke the privilege from.")]
    [CommandOption("-r|--revoke")]
    public override string[] Revocations { get; set; } = Array.Empty<string>();

    /// <summary>
    /// Gets or sets a value indicating whether to revoke all principals from the privilege.
    /// </summary>
    [Description("Revokes all principals from the privilege.")]
    [CommandOption("-a|--revoke-all")]
    public bool RevokeAll { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether to revoke all principals from the privilege excluding those being granted.
    /// </summary>
    [Description("Revokes all principals from the privilege excluding those being granted.")]
    [CommandOption("-o|--revoke-others")]
    public bool RevokeOthers { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether to revoke all principals whose SID matches the regular expression excluding those being granted.
    /// </summary>
    [Description("Revokes all principals whose SID matches the regular expression excluding those being granted.")]
    [CommandOption("-t|--revoke-pattern")]
    [TypeConverter(typeof(RegexTypeConverter))]
    public Regex RevokePattern { get; set; }

    /// <inheritdoc />
    public override ValidationResult Validate()
    {
        if (string.IsNullOrWhiteSpace(this.Privilege))
        {
            return ValidationResult.Error("The privilege is required.");
        }

        // Ensure "--revoke-all" is not used with any other option.
        if (this.RevokeAll && (this.Grants.Length > 0 || this.Revocations.Length > 0 || this.RevokeOthers || this.RevokePattern is not null))
        {
            return ValidationResult.Error("\"--revoke-all\" cannot be used with any other option.");
        }

        // Ensure "--revoke-others" is only used with "--grant".
        if (this.RevokeOthers && (this.Grants.Length == 0 || this.Revocations.Length > 0 || this.RevokeAll || this.RevokePattern is not null))
        {
            return ValidationResult.Error("\"--revoke-others\" is only valid with \"--grant\".");
        }

        // Ensure "--revoke-pattern" is not used with "--revoke", "--revoke-all", or "--revoke-others"
        if (this.RevokePattern is not null && (this.Revocations.Length > 0 || this.RevokeAll || this.RevokeOthers))
        {
            return ValidationResult.Error("\"--revoke-pattern\" cannot be used with \"--revoke\", \"--revoke-all\", or \"--revoke-others\".");
        }

        // Ensure privilege mode is used with at least one of "--grant", "--revoke", "--revoke-all", or "--revoke-pattern".
        if (this.Grants.Length == 0 && this.Revocations.Length == 0 && !this.RevokeAll && this.RevokePattern is null)
        {
            return ValidationResult.Error("At least one option is required.");
        }

        return base.Validate();
    }
}