namespace UserRights.Cli;

using System;
using System.ComponentModel;
using System.IO;
using System.Text;
using Spectre.Console.Cli;
using UserRights.Application;
using UserRights.Extensions.Serialization;

/// <summary>
/// Represents the list mode command.
/// </summary>
[Description("Runs the utility in list mode.")]
public class ListCommand : Command<ListSettings>
{
    private readonly ILsaUserRights policy;
    private readonly IUserRightsManager manager;

    /// <summary>
    /// Initializes a new instance of the <see cref="ListCommand"/> class.
    /// </summary>
    /// <param name="policy">The connection to the local security authority.</param>
    /// <param name="manager">The the user rights application.</param>
    public ListCommand(ILsaUserRights policy, IUserRightsManager manager)
    {
        this.policy = policy ?? throw new ArgumentNullException(nameof(policy));
        this.manager = manager ?? throw new ArgumentNullException(nameof(manager));
    }

    /// <inheritdoc />
    public override int Execute(CommandContext context, ListSettings settings)
    {
        this.policy.Connect(settings.SystemName);

        var results = this.manager.GetUserRights(this.policy);

        var serialized = settings.Json
            ? results.ToJson()
            : results.ToCsv();

        if (string.IsNullOrWhiteSpace(settings.Path))
        {
            using var streamWriter = new StreamWriter(Console.OpenStandardOutput());
            streamWriter.Write(serialized);
        }
        else
        {
            using var streamWriter = new StreamWriter(settings.Path, false, Encoding.UTF8);
            streamWriter.Write(serialized);
        }

        return 0;
    }
}