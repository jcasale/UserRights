namespace UserRights.Cli;

using System;
using System.ComponentModel;
using Spectre.Console.Cli;
using UserRights.Application;

/// <summary>
/// Represents the privilege mode command.
/// </summary>
[Description("Runs the utility in privilege mode.")]
public class PrivilegeCommand : Command<PrivilegeSettings>
{
    private readonly ILsaUserRights policy;
    private readonly IUserRightsManager manager;

    /// <summary>
    /// Initializes a new instance of the <see cref="PrivilegeCommand"/> class.
    /// </summary>
    /// <param name="policy">The connection to the local security authority.</param>
    /// <param name="manager">The the user rights application.</param>
    public PrivilegeCommand(ILsaUserRights policy, IUserRightsManager manager)
    {
        this.policy = policy ?? throw new ArgumentNullException(nameof(policy));
        this.manager = manager ?? throw new ArgumentNullException(nameof(manager));
    }

    /// <inheritdoc />
    public override int Execute(CommandContext context, PrivilegeSettings settings)
    {
        this.policy.Connect(settings.SystemName);

        this.manager.ModifyPrivilege(
            this.policy,
            settings.Privilege,
            settings.Grants,
            settings.Revocations,
            settings.RevokeAll,
            settings.RevokeOthers,
            settings.RevokePattern,
            settings.DryRun);

        return 0;
    }
}