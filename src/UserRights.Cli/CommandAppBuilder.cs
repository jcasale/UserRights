namespace UserRights.Cli;

using System;
using Spectre.Console.Cli;

/// <summary>
/// Represents methods for building <see cref="CommandApp"/> instances.
/// </summary>
public static class CommandAppBuilder
{
    /// <summary>
    /// Builds a configured instance of a <see cref="CommandApp"/>.
    /// </summary>
    /// <param name="registrar">The type register to add.</param>
    /// <param name="interceptors">A sequence of optional command interceptors.</param>
    /// <returns>A <see cref="CommandApp"/> instance.</returns>
    public static CommandApp Build(ITypeRegistrar registrar, params ICommandInterceptor[] interceptors)
    {
        if (registrar is null)
        {
            throw new ArgumentNullException(nameof(registrar));
        }

        if (interceptors is null)
        {
            throw new ArgumentNullException(nameof(interceptors));
        }

        var app = new CommandApp(registrar);
        app.Configure(config =>
        {
            foreach (var interceptor in interceptors)
            {
                config.SetInterceptor(interceptor);
            }

            config.AddExample(new[] { "principal", "DOMAIN\\UserOrGroup", "--grant", "SeDenyServiceLogonRight" });
            config.AddExample(new[] { "privilege", "SeServiceLogonRight", "--grant", "DOMAIN\\UserOrGroup" });
            config.AddExample(new[] { "list", "--json" });

            config.AddCommand<PrincipalCommand>("principal")
                .WithExample(new[] { "principal", "DOMAIN\\UserOrGroup", "--grant", "SeDenyServiceLogonRight" })
                .WithExample(new[] { "principal", "DOMAIN\\UserOrGroup", "--revoke", "SeDenyServiceLogonRight" })
                .WithExample(new[] { "principal", "DOMAIN\\UserOrGroup", "--grant", "SeServiceLogonRight", "--revoke", "SeDenyServiceLogonRight" })
                .WithExample(new[] { "principal", "DOMAIN\\UserOrGroup", "--grant", "SeServiceLogonRight", "--grant", "SeInteractiveLogonRight", "--revoke-others" });

            config.AddCommand<PrivilegeCommand>("privilege")
                .WithExample(new[] { "privilege", "SeServiceLogonRight", "--grant", "DOMAIN\\UserOrGroup", "--revoke", "DOMAIN\\Group" })
                .WithExample(new[] { "privilege", "SeServiceLogonRight", "--revoke", "DOMAIN\\UserOrGroup" })
                .WithExample(new[] { "privilege", "SeServiceLogonRight", "--grant", "DOMAIN\\UserOrGroup", "--revoke-pattern", "^S-1-5-21-" })
                .WithExample(new[] { "privilege", "SeServiceLogonRight", "--revoke-pattern", "^S-1-5-21-" })
                .WithExample(new[] { "privilege", "SeServiceLogonRight", "--revoke-all" });

            config.AddCommand<ListCommand>("list")
                .WithExample(new[] { "list" })
                .WithExample(new[] { "list", "--json" })
                .WithExample(new[] { "list", "--path", "x:\\path\\file.csv" });

            config.PropagateExceptions();
            config.UseStrictParsing();

#if DEBUG
            config.ValidateExamples();
#endif
        });

        return app;
    }
}