namespace UserRights.Cli;

using System;
using System.ComponentModel;
using Spectre.Console;
using Spectre.Console.Cli;

/// <summary>
/// Represents the principal mode command settings.
/// </summary>
public sealed class PrincipalSettings : ModifySettings
{
    /// <summary>
    /// Gets or sets the principal to modify.
    /// </summary>
    [Description("The principal to modify.")]
    [CommandArgument(0, "<principal>")]
    public string Principal { get; set; }

    /// <summary>
    /// Gets or sets the privileges to grant to the principal.
    /// </summary>
    [Description("The privilege to grant to the principal.")]
    [CommandOption("-g|--grant")]
    public override string[] Grants { get; set; } = Array.Empty<string>();

    /// <summary>
    /// Gets or sets the privileges to revoke from the principal.
    /// </summary>
    [Description("The privilege to revoke from the principal.")]
    [CommandOption("-r|--revoke")]
    public override string[] Revocations { get; set; } = Array.Empty<string>();

    /// <summary>
    /// Gets or sets a value indicating whether to revoke all privileges from the principal.
    /// </summary>
    [Description("Revokes all privileges from the principal.")]
    [CommandOption("-a|--revoke-all")]
    public bool RevokeAll { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether to revoke all privileges from the principal excluding those being granted.
    /// </summary>
    [Description("Revokes all privileges from the principal excluding those being granted.")]
    [CommandOption("-o|--revoke-others")]
    public bool RevokeOthers { get; set; }

    /// <inheritdoc />
    public override ValidationResult Validate()
    {
        if (string.IsNullOrWhiteSpace(this.Principal))
        {
            return ValidationResult.Error("The principal is required.");
        }

        // Ensure "--revoke-all" is not used with any other option.
        if (this.RevokeAll && (this.RevokeOthers || this.Grants.Length > 0 || this.Revocations.Length > 0))
        {
            return ValidationResult.Error("\"--revoke-all\" cannot be used with any other option.");
        }

        // Ensure "--revoke-others" is only used with "--grant".
        if (this.RevokeOthers && (this.RevokeAll || this.Grants.Length == 0 || this.Revocations.Length > 0))
        {
            return ValidationResult.Error("\"--revoke-others\" is only valid with \"--grant\".");
        }

        // Ensure principal mode is used with at least one of "--grant", "--revoke", or "--revoke-all".
        if (this.Grants.Length == 0 && this.Revocations.Length == 0 && !this.RevokeAll)
        {
            return ValidationResult.Error("At least one option is required.");
        }

        return base.Validate();
    }
}