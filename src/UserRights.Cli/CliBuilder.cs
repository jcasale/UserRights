namespace UserRights.Cli;

using System.CommandLine;
using System.CommandLine.Help;
using System.Text;

using Microsoft.Extensions.Logging;

using UserRights.Application;
using UserRights.Extensions.Serialization;

using static UserRights.Application.OptionsValidator;
using static UserRights.Logging.OperationId;

/// <summary>
/// Represents the command line parser builder.
/// </summary>
public class CliBuilder
{
    private readonly ILogger _logger;
    private readonly ILsaUserRights _policy;
    private readonly IUserRightsManager _manager;

    /// <summary>
    /// Initializes a new instance of the <see cref="CliBuilder"/> class.
    /// </summary>
    /// <param name="logger">The logging instance.</param>
    /// <param name="policy">The local security authority policy instance.</param>
    /// <param name="manager">The user rights application instance.</param>
    public CliBuilder(ILogger<CliBuilder> logger, ILsaUserRights policy, IUserRightsManager manager)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _policy = policy ?? throw new ArgumentNullException(nameof(policy));
        _manager = manager ?? throw new ArgumentNullException(nameof(manager));
    }

    /// <summary>
    /// Builds the command line parser root command.
    /// </summary>
    /// <returns>A configured command line parser root command.</returns>
    public RootCommand Build()
    {
        var rootCommand = new RootCommand("Windows User Rights Assignment Utility")
        {
            BuildListCommand(),
            BuildPrincipalCommand(),
            BuildPrivilegeCommand()
        };

        foreach (var option in rootCommand.Options)
        {
            // Replace the default help action with one that adds examples.
            if (option is HelpOption helpOption)
            {
                helpOption.Action = new HelpExamplesAction((HelpAction)helpOption.Action!);

                break;
            }
        }

        return rootCommand;
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
            var path = result.GetValue(pathOption);

            if (string.IsNullOrWhiteSpace(path))
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
            var systemName = result.GetValue(systemNameOption);

            if (string.IsNullOrWhiteSpace(systemName))
            {
                result.AddError("The system name cannot be empty or whitespace.");
            }
        });

        var command = new Command("list", "Runs the utility in list mode.");

        command.Options.Add(jsonOption);
        command.Options.Add(pathOption);
        command.Options.Add(systemNameOption);

        command.SetAction(async (parseResult, cancellationToken) =>
        {
            _logger.LogInformation(ListMode, "{Program:l} v{Version} executing in {Mode:l} mode.", ProgramInfo.Program, ProgramInfo.InformationalVersion, command.Name);

            var json = parseResult.GetValue(jsonOption);
            var path = parseResult.GetValue(pathOption);
            var systemName = parseResult.GetValue(systemNameOption);

            _policy.Connect(systemName);

            var results = _manager.GetUserRights(_policy);

            Func<Stream, CancellationToken, Task> writeAsync = json ? results.ToJson : results.ToCsv;

            if (string.IsNullOrWhiteSpace(path))
            {
                // The invocation configuration's output stream in the parse result is unusable because its encoding cannot be changed.
                var stream = Console.OpenStandardOutput();
                var encoding = Console.OutputEncoding;

                try
                {
                    Console.OutputEncoding = Encoding.UTF8;

                    await writeAsync(stream, cancellationToken).ConfigureAwait(false);
                }
                finally
                {
                    Console.OutputEncoding = encoding;
                }
            }
            else
            {
                var stream = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, 4096, useAsync: true);
                await using (stream.ConfigureAwait(false))
                {
                    await writeAsync(stream, cancellationToken).ConfigureAwait(false);
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

        // Validate principal mode options.
        principalArgument.Validators.Add(result =>
        {
            var principal = result.GetValue(principalArgument);
            var grants = result.GetValue(grantsOption);
            var revocations = result.GetValue(revocationsOption);
            var revokeAll = result.GetValue(revokeAllOption);
            var revokeOthers = result.GetValue(revokeOthersOption);

            var errors = ValidatePrincipalOptions(principal, grants, revocations, revokeAll, revokeOthers);
            foreach (var error in errors)
            {
                result.AddError(error);
            }
        });

        // Ensure the system name is a valid string.
        systemNameOption.Validators.Add(result =>
        {
            var systemName = result.GetValue(systemNameOption);

            if (string.IsNullOrWhiteSpace(systemName))
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

            _logger.BeginScope(new Dictionary<string, object>(StringComparer.Ordinal) { { "DryRun", dryRun } });

            _logger.LogInformation(PrincipalMode, "{Program:l} v{Version} executing in {Mode:l} mode.", ProgramInfo.Program, ProgramInfo.InformationalVersion, command.Name);

            _policy.Connect(systemName);

            _manager.ModifyPrincipal(
                _policy,
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

        // Validate privilege mode options.
        privilegeArgument.Validators.Add(result =>
        {
            var privilege = result.GetValue(privilegeArgument);
            var grants = result.GetValue(grantsOption);
            var revocations = result.GetValue(revocationsOption);
            var revokeAll = result.GetValue(revokeAllOption);
            var revokeOthers = result.GetValue(revokeOthersOption);
            var revokePattern = result.GetValue(revokePatternOption);

            var errors = ValidatePrivilegeOptions(privilege, grants, revocations, revokeAll, revokeOthers, revokePattern);
            foreach (var error in errors)
            {
                result.AddError(error);
            }
        });

        // Ensure the system name is a valid string.
        systemNameOption.Validators.Add(result =>
        {
            var systemName = result.GetValue(systemNameOption);

            if (string.IsNullOrWhiteSpace(systemName))
            {
                result.AddError("The system name cannot be empty or whitespace.");
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

            _logger.BeginScope(new Dictionary<string, object>(StringComparer.Ordinal) { { "DryRun", dryRun } });

            _logger.LogInformation(PrivilegeMode, "{Program:l} v{Version} executing in {Mode:l} mode.", ProgramInfo.Program, ProgramInfo.InformationalVersion, command.Name);

            _policy.Connect(systemName);

            _manager.ModifyPrivilege(
                _policy,
                privilege!,
                grants!,
                revocations!,
                revokeAll,
                revokeOthers,
                revokePattern,
                dryRun);
        });

        return command;
    }
}