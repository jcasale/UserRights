namespace UserRights.Cli;

using System;
using System.Collections.Generic;
using System.CommandLine;
using System.CommandLine.Help;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

using Microsoft.Extensions.Logging;

using UserRights.Application;
using UserRights.Extensions.Serialization;

/// <summary>
/// Represents the command line parser builder.
/// </summary>
public class CliBuilder
{
    private readonly ILogger logger;
    private readonly ILsaUserRights policy;
    private readonly IUserRightsManager manager;

    /// <summary>
    /// Initializes a new instance of the <see cref="CliBuilder"/> class.
    /// </summary>
    /// <param name="logger">The logging instance.</param>
    /// <param name="policy">The local security authority policy instance.</param>
    /// <param name="manager">The user rights application instance.</param>
    public CliBuilder(ILogger<CliBuilder> logger, ILsaUserRights policy, IUserRightsManager manager)
    {
        this.logger = logger;
        this.policy = policy;
        this.manager = manager;
    }

    /// <summary>
    /// Builds the command line parser.
    /// </summary>
    /// <returns>A configured command line parser.</returns>
    public CommandLineConfiguration Build()
    {
        var rootCommand = new RootCommand("Windows User Rights Assignment Utility")
        {
            this.BuildListCommand(),
            this.BuildPrincipalCommand(),
            this.BuildPrivilegeCommand()
        };

        foreach (var option in rootCommand.Options)
        {
            switch (option)
            {
                // Replace the default help action with one that adds examples.
                case HelpOption helpOption:
                    helpOption.Action = new HelpExamplesAction((HelpAction)helpOption.Action!);

                    break;

                // Replace the default version action with one that produces a shorter informational version.
                case VersionOption versionOption:
                    versionOption.Action = new VersionAction();

                    break;
            }
        }

        var configuration = new CommandLineConfiguration(rootCommand)
        {
            // Disable the default exception handler to allow logging errors to the event log.
            EnableDefaultExceptionHandler = false
        };

        return configuration;
    }

    /// <summary>
    /// Builds the list command.
    /// </summary>
    /// <returns>The list command instance.</returns>
    private Command BuildListCommand()
    {
        var jsonOption = new Option<bool>("--json", "-j")
        {
            Description = "Formats output in JSON instead of CSV."
        };

        var pathOption = new Option<string>("--path", "-f")
        {
            Description = "The path to write the output to. If not specified, output is written to STDOUT."
        };

        // Ensure the path is a valid string.
        pathOption.Validators.Add(result =>
        {
            if (string.IsNullOrWhiteSpace(result.GetValue(pathOption)))
            {
                result.AddError("Path cannot be empty or whitespace.");
            }
        });

        var systemNameOption = new Option<string>("--system-name", "-s")
        {
            Description = "The name of the remote system to execute on (default localhost)."
        };

        // Ensure the system name is a valid string.
        systemNameOption.Validators.Add(result =>
        {
            if (string.IsNullOrWhiteSpace(result.GetValue(systemNameOption)))
            {
                result.AddError("System name cannot be empty or whitespace.");
            }
        });

        var command = new Command("list", "Runs the utility in list mode.");

        command.Options.Add(jsonOption);
        command.Options.Add(pathOption);
        command.Options.Add(systemNameOption);

        command.SetAction(async (parseResult, cancellationToken) =>
        {
            this.logger.LogInformation(OperationId.ListMode, "{Program:l} v{Version} executing in {Mode:l} mode.", ProgramInfo.Program, ProgramInfo.Version, command.Name);

            var json = parseResult.GetValue(jsonOption);
            var path = parseResult.GetValue(pathOption);
            var systemName = parseResult.GetValue(systemNameOption);

            this.policy.Connect(systemName);

            var results = this.manager.GetUserRights(this.policy);

            if (string.IsNullOrWhiteSpace(path))
            {
                var stream = Console.OpenStandardOutput();
                var encoding = Console.OutputEncoding;

                try
                {
                    Console.OutputEncoding = Encoding.UTF8;

                    if (json)
                    {
                        await results.ToJson(stream, cancellationToken).ConfigureAwait(false);
                    }
                    else
                    {
                        await results.ToCsv(stream, cancellationToken).ConfigureAwait(false);
                    }
                }
                finally
                {
                    Console.OutputEncoding = encoding;
                }
            }
            else
            {
                var stream = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, bufferSize: 4096, useAsync: true);
                await using (stream.ConfigureAwait(false))
                {
                    if (json)
                    {
                        await results.ToJson(stream, cancellationToken).ConfigureAwait(false);
                    }
                    else
                    {
                        await results.ToCsv(stream, cancellationToken).ConfigureAwait(false);
                    }
                }
            }
        });

        return command;
    }

    /// <summary>
    /// Builds the principal command.
    /// </summary>
    /// <returns>The principal command instance.</returns>
    private Command BuildPrincipalCommand()
    {
        var principalArgument = new Argument<string>("principal")
        {
            Description = "The principal to modify."
        };

        var grantsOption = new Option<string[]>("--grant", "-g")
        {
            Description = "The privilege to grant to the principal."
        };

        var revocationsOption = new Option<string[]>("--revoke", "-r")
        {
            Description = "The privilege to revoke from the principal."
        };

        var revokeAllOption = new Option<bool>("--revoke-all", "-a")
        {
            Description = "Revokes all privileges from the principal."
        };

        var revokeOthersOption = new Option<bool>("--revoke-others", "-o")
        {
            Description = "Revokes all privileges from the principal excluding those being granted."
        };

        var dryRunOption = new Option<bool>("--dry-run", "-d")
        {
            Description = "Enables dry-run mode."
        };

        var systemNameOption = new Option<string>("--system-name", "-s")
        {
            Description = "The name of the remote system to execute on (default localhost)."
        };

        // Ensure the principal is a valid string.
        principalArgument.Validators.Add(result =>
        {
            if (string.IsNullOrWhiteSpace(result.GetValue(principalArgument)))
            {
                result.AddError("Principal cannot be empty or whitespace.");
            }
        });

        // Ensure principal mode is used with at least one of grant, revoke, or revoke all.
        principalArgument.Validators.Add(result =>
        {
            if (result.GetValue(grantsOption) is not { Length: > 0 }
                && result.GetValue(revocationsOption) is not { Length: > 0 }
                && !result.GetValue(revokeAllOption))
            {
                result.AddError("At least one option is required.");
            }
        });

        // Ensure the grants are valid strings.
        grantsOption.Validators.Add(result =>
        {
            var grantsCollection = result.GetValue(grantsOption) ?? [];
            if (grantsCollection.Any(string.IsNullOrWhiteSpace))
            {
                result.AddError("Grants cannot be empty or whitespace.");
            }
        });

        // Ensure the grants do not overlap with revocations or contain duplicates.
        grantsOption.Validators.Add(result =>
        {
            var grantsCollection = result.GetValue(grantsOption) ?? [];
            var revocationsCollection = result.GetValue(revocationsOption) ?? [];

            var grantsSet = grantsCollection.ToHashSet(StringComparer.InvariantCultureIgnoreCase);
            var revocationsSet = revocationsCollection.ToHashSet(StringComparer.InvariantCultureIgnoreCase);

            if (grantsSet.Overlaps(revocationsSet))
            {
                result.AddError("The grants and revocations cannot overlap.");
            }
            else if (grantsSet.Count != grantsCollection.Length)
            {
                result.AddError("The grants cannot contain duplicates.");
            }
        });

        // Ensure the revocations are valid strings.
        revocationsOption.Validators.Add(result =>
        {
            if (result.Tokens.Any(p => string.IsNullOrWhiteSpace(p.Value)))
            {
                result.AddError("Revocations cannot be empty or whitespace.");
            }
        });

        // Ensure the revocations do not overlap with revocations or contain duplicates.
        revocationsOption.Validators.Add(result =>
        {
            var grantsCollection = result.GetValue(grantsOption) ?? [];
            var revocationsCollection = result.GetValue(revocationsOption) ?? [];

            var grantsSet = grantsCollection.ToHashSet(StringComparer.InvariantCultureIgnoreCase);
            var revocationsSet = revocationsCollection.ToHashSet(StringComparer.InvariantCultureIgnoreCase);

            if (grantsSet.Overlaps(revocationsSet))
            {
                result.AddError("The grants and revocations cannot overlap.");
            }
            else if (revocationsSet.Count != revocationsCollection.Length)
            {
                result.AddError("The revocations cannot contain duplicates.");
            }
        });

        // Ensure revoke all is not used with any other option.
        revokeAllOption.Validators.Add(result =>
        {
            if (result.GetValue(revokeOthersOption)
                || result.GetValue(grantsOption) is { Length: > 0 }
                || result.GetValue(revocationsOption) is { Length: > 0 })
            {
                result.AddError("Revoke all cannot be used with any other option.");
            }
        });

        // Ensure revoke others is only used with grant.
        revokeOthersOption.Validators.Add(result =>
        {
            if (result.GetValue(revokeAllOption)
                || result.GetValue(grantsOption) is not { Length: > 0 }
                || result.GetValue(revocationsOption) is { Length: > 0 })
            {
                result.AddError("Revoke others is only valid with grants.");
            }
        });

        // Ensure the system name is a valid string.
        systemNameOption.Validators.Add(result =>
        {
            if (string.IsNullOrWhiteSpace(result.GetValue(systemNameOption)))
            {
                result.AddError("System name cannot be empty or whitespace.");
            }
        });

        // Create command.
        var command = new Command("principal", "Runs the utility in principal mode.");

        command.Arguments.Add(principalArgument);
        command.Options.Add(grantsOption);
        command.Options.Add(revocationsOption);
        command.Options.Add(revokeAllOption);
        command.Options.Add(revokeOthersOption);
        command.Options.Add(dryRunOption);
        command.Options.Add(systemNameOption);

        command.SetAction(parseResult =>
        {
            var principal = parseResult.GetValue(principalArgument);
            var grants = parseResult.GetValue(grantsOption);
            var revocations = parseResult.GetValue(revocationsOption);
            var revokeAll = parseResult.GetValue(revokeAllOption);
            var revokeOthers = parseResult.GetValue(revokeOthersOption);
            var dryRun = parseResult.GetValue(dryRunOption);
            var systemName = parseResult.GetValue(systemNameOption);

            this.logger.BeginScope(new Dictionary<string, object>(StringComparer.Ordinal) { { "DryRun", dryRun } });

            this.logger.LogInformation(OperationId.PrincipalMode, "{Program:l} v{Version} executing in {Mode:l} mode.", ProgramInfo.Program, ProgramInfo.Version, command.Name);

            this.policy.Connect(systemName);

            this.manager.ModifyPrincipal(
                this.policy,
                principal!,
                grants!,
                revocations!,
                revokeAll,
                revokeOthers,
                dryRun);
            });

        return command;
    }

    /// <summary>
    /// Builds the privilege command.
    /// </summary>
    /// <returns>The privilege command instance.</returns>
    private Command BuildPrivilegeCommand()
    {
        var privilegeArgument = new Argument<string>("privilege")
        {
            Description = "The privilege to modify."
        };

        var grantsOption = new Option<string[]>("--grant", "-g")
        {
            Description = "The principal to grant the privilege to."
        };

        var revocationsOption = new Option<string[]>("--revoke", "-r")
        {
            Description = "The principal to revoke the privilege from."
        };

        var revokeAllOption = new Option<bool>("--revoke-all", "-a")
        {
            Description = "Revokes all principals from the privilege."
        };

        var revokeOthersOption = new Option<bool>("--revoke-others", "-o")
        {
            Description = "Revokes all principals from the privilege excluding those being granted."
        };

        var revokePatternOption = new Option<string>("--revoke-pattern", "-t")
        {
            Description = "Revokes all principals whose SID matches the regular expression excluding those being granted."
        };

        var dryRunOption = new Option<bool>("--dry-run", "-d")
        {
            Description = "Enables dry-run mode."
        };

        var systemNameOption = new Option<string>("--system-name", "-s")
        {
            Description = "The name of the remote system to execute on (default localhost)."
        };

        // Ensure the principal is a valid string.
        privilegeArgument.Validators.Add(result =>
        {
            if (string.IsNullOrWhiteSpace(result.GetValue(privilegeArgument)))
            {
                result.AddError("Privilege cannot be empty or whitespace.");
            }
        });

        // Ensure privilege mode is used with at least one of grant, revoke, revoke all, or revoke pattern.
        privilegeArgument.Validators.Add(result =>
        {
            if (result.GetValue(grantsOption) is not { Length: > 0 }
                && result.GetValue(revocationsOption) is not { Length: > 0 }
                && !result.GetValue(revokeAllOption)
                && result.GetValue(revokePatternOption) is null)
            {
                result.AddError("At least one option is required.");
            }
        });

        // Ensure the grants are valid strings.
        grantsOption.Validators.Add(result =>
        {
            if (result.Tokens.Any(p => string.IsNullOrWhiteSpace(p.Value)))
            {
                result.AddError("Grants cannot be empty or whitespace.");
            }
        });

        // Ensure the grants do not overlap with revocations or contain duplicates.
        grantsOption.Validators.Add(result =>
        {
            var grantsCollection = result.GetValue(grantsOption) ?? [];
            var revocationsCollection = result.GetValue(revocationsOption) ?? [];

            var grantsSet = grantsCollection.ToHashSet(StringComparer.InvariantCultureIgnoreCase);
            var revocationsSet = revocationsCollection.ToHashSet(StringComparer.InvariantCultureIgnoreCase);

            if (grantsSet.Overlaps(revocationsSet))
            {
                result.AddError("Grants and revocations cannot overlap.");
            }
            else if (grantsSet.Count != grantsCollection.Length)
            {
                result.AddError("Grants cannot contain duplicates.");
            }
        });

        // Ensure the revocations are valid strings.
        revocationsOption.Validators.Add(result =>
        {
            if (result.Tokens.Any(p => string.IsNullOrWhiteSpace(p.Value)))
            {
                result.AddError("Revocations cannot be empty or whitespace.");
            }
        });

        // Ensure the revocations do not overlap with revocations or contain duplicates.
        revocationsOption.Validators.Add(result =>
        {
            var grantsCollection = result.GetValue(grantsOption) ?? [];
            var revocationsCollection = result.GetValue(revocationsOption) ?? [];

            var grantsSet = grantsCollection.ToHashSet(StringComparer.InvariantCultureIgnoreCase);
            var revocationsSet = revocationsCollection.ToHashSet(StringComparer.InvariantCultureIgnoreCase);

            if (grantsSet.Overlaps(revocationsSet))
            {
                result.AddError("Grants and revocations cannot overlap.");
            }
            else if (revocationsSet.Count != revocationsCollection.Length)
            {
                result.AddError("Revocations cannot contain duplicates.");
            }
        });

        // Ensure revoke all is not used with any other option.
        revokeAllOption.Validators.Add(result =>
        {
            if (result.GetValue(grantsOption) is { Length: > 0 }
                || result.GetValue(revocationsOption) is { Length: > 0 }
                || result.GetValue(revokeOthersOption)
                || result.GetValue(revokePatternOption) is not null)
            {
                result.AddError("Revoke all cannot be used with any other option.");
            }
        });

        // Ensure revoke others is only used with grant.
        revokeOthersOption.Validators.Add(result =>
        {
            if (result.GetValue(grantsOption) is not { Length: > 0 }
                || result.GetValue(revocationsOption) is { Length: > 0 }
                || result.GetValue(revokeAllOption)
                || result.GetValue(revokePatternOption) is not null)
            {
                result.AddError("Revoke others is only valid when used with grants.");
            }
        });

        // Ensure the revoke pattern is a valid string.
        revokePatternOption.Validators.Add(result =>
        {
            var revokePattern = result.GetValue(revokePatternOption);
            if (string.IsNullOrWhiteSpace(revokePattern))
            {
                result.AddError("Revoke pattern cannot be empty or whitespace.");
            }
            else
            {
                try
                {
                    _ = new Regex(revokePattern, RegexOptions.None, TimeSpan.FromSeconds(1));
                }
                catch (RegexParseException e)
                {
                    result.AddError(string.Format(CultureInfo.InvariantCulture, "Revoke pattern must be a valid regular expression. {0}", e.Message));
                }
            }
        });

        // Ensure revoke pattern is not used with revoke, revoke all, or revoke others.
        revokePatternOption.Validators.Add(result =>
        {
            if (result.GetValue(revocationsOption) is { Length: > 0 }
                || result.GetValue(revokeAllOption)
                || result.GetValue(revokeOthersOption))
            {
                result.AddError("Revoke pattern is only valid when used alone or with grants.");
            }
        });

        // Ensure the system name is a valid string.
        systemNameOption.Validators.Add(result =>
        {
            if (string.IsNullOrWhiteSpace(result.GetValue(systemNameOption)))
            {
                result.AddError("System name cannot be empty or whitespace.");
            }
        });

        var command = new Command("privilege", "Runs the utility in privilege mode.");

        command.Arguments.Add(privilegeArgument);
        command.Options.Add(grantsOption);
        command.Options.Add(revocationsOption);
        command.Options.Add(revokeAllOption);
        command.Options.Add(revokeOthersOption);
        command.Options.Add(revokePatternOption);
        command.Options.Add(dryRunOption);
        command.Options.Add(systemNameOption);

        command.SetAction(parseResult =>
        {
            var privilege = parseResult.GetValue(privilegeArgument);
            var grants = parseResult.GetValue(grantsOption);
            var revocations = parseResult.GetValue(revocationsOption);
            var revokeAll = parseResult.GetValue(revokeAllOption);
            var revokeOthers = parseResult.GetValue(revokeOthersOption);
            var revokePattern = parseResult.GetValue(revokePatternOption);
            var dryRun = parseResult.GetValue(dryRunOption);
            var systemName = parseResult.GetValue(systemNameOption);

            this.logger.BeginScope(new Dictionary<string, object>(StringComparer.Ordinal) { { "DryRun", dryRun } });

            this.logger.LogInformation(OperationId.PrivilegeMode, "{Program:l} v{Version} executing in {Mode:l} mode.", ProgramInfo.Program, ProgramInfo.Version, command.Name);

            var revokeRegex = string.IsNullOrWhiteSpace(revokePattern)
                ? null
                : new Regex(revokePattern, RegexOptions.None, TimeSpan.FromSeconds(1));

            this.policy.Connect(systemName);

            this.manager.ModifyPrivilege(
                this.policy,
                privilege!,
                grants!,
                revocations!,
                revokeAll,
                revokeOthers,
                revokeRegex,
                dryRun);
        });

        return command;
    }
}