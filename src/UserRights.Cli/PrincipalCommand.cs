namespace UserRights.Cli;

using System;
using System.ComponentModel;
using Spectre.Console.Cli;
using UserRights.Application;

/// <summary>
/// Represents the principal mode command.
/// </summary>
[Description("Runs the utility in principal mode.")]
public class PrincipalCommand : Command<PrincipalSettings>
{
    private readonly ILsaUserRights policy;
    private readonly IUserRightsManager manager;

    /// <summary>
    /// Initializes a new instance of the <see cref="PrincipalCommand"/> class.
    /// </summary>
    /// <param name="policy">The connection to the local security authority.</param>
    /// <param name="manager">The the user rights application.</param>
    public PrincipalCommand(ILsaUserRights policy, IUserRightsManager manager)
    {
        this.policy = policy ?? throw new ArgumentNullException(nameof(policy));
        this.manager = manager ?? throw new ArgumentNullException(nameof(manager));
    }

    /// <inheritdoc />
    public override int Execute(CommandContext context, PrincipalSettings settings)
    {
        if (settings is null)
        {
            throw new ArgumentNullException(nameof(settings));
        }

        this.policy.Connect(settings.SystemName);

        this.manager.ModifyPrincipal(
            this.policy,
            settings.Principal,
            settings.Grants,
            settings.Revocations,
            settings.RevokeAll,
            settings.RevokeOthers,
            settings.DryRun);

        return 0;
    }
}