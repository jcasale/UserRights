namespace Tests;

using System.Security.Principal;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

using UserRights.Application;
using UserRights.Cli;

/// <summary>
/// Represents a test fixture with a <see cref="CliBuilder"/> implementation for testing the CLI.
/// </summary>
public class CliBuilderFixture : IDisposable
{
    private readonly ServiceProvider _serviceProvider;

    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="CliBuilderFixture"/> class.
    /// </summary>
    /// <remarks>
    /// Creates a fixture with an empty, mock <see cref="ILsaUserRights"/> implementation, and a mock <see cref="IUserRightsManager"/> implementation.
    /// </remarks>
    public CliBuilderFixture()
    {
        var serviceCollection = new ServiceCollection()
            .AddLogging(builder => builder
                .ClearProviders()
                .SetMinimumLevel(LogLevel.Trace)
                .AddDebug());

        serviceCollection.AddSingleton<ILsaUserRights, MockLsaUserRights>();
        serviceCollection.AddSingleton<IUserRightsManager, MockUserRightsManager>();
        serviceCollection.AddSingleton<CliBuilder>();

        _serviceProvider = serviceCollection.BuildServiceProvider();
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CliBuilderFixture"/> class.
    /// </summary>
    /// <param name="policy">The existing LSA user rights implementation.</param>
    /// <remarks>
    /// Creates a fixture with a user-supplied <see cref="ILsaUserRights"/> implementation, and a complete instance of a <see cref="IUserRightsManager"/> implementation.
    /// </remarks>
    public CliBuilderFixture(ILsaUserRights policy)
    {
        ArgumentNullException.ThrowIfNull(policy);

        var serviceCollection = new ServiceCollection()
            .AddLogging(builder => builder
                .ClearProviders()
                .SetMinimumLevel(LogLevel.Trace)
                .AddDebug());

        serviceCollection.AddSingleton(policy);
        serviceCollection.AddSingleton<IUserRightsManager, UserRightsManager>();
        serviceCollection.AddSingleton<CliBuilder>();

        _serviceProvider = serviceCollection.BuildServiceProvider();
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CliBuilderFixture"/> class.
    /// </summary>
    /// <param name="database">The entries to include in the mock policy database.</param>
    /// <param name="systemName">The remote system name to execute the task on (default localhost).</param>
    /// <remarks>
    /// Creates a fixture with user-supplied, existing policy entries, and mock instances of a <see cref="ILsaUserRights"/> and <see cref="IUserRightsManager"/> implementations.
    /// </remarks>
    public CliBuilderFixture(IDictionary<string, ICollection<SecurityIdentifier>> database, string? systemName = null)
    {
        ArgumentNullException.ThrowIfNull(database);

        var serviceCollection = new ServiceCollection()
            .AddLogging(builder => builder
                .ClearProviders()
                .SetMinimumLevel(LogLevel.Trace)
                .AddDebug());

        var policy = new MockLsaUserRights(database);
        policy.Connect(systemName);

        serviceCollection.AddSingleton<ILsaUserRights>(policy);
        serviceCollection.AddSingleton<IUserRightsManager, UserRightsManager>();
        serviceCollection.AddSingleton<CliBuilder>();

        _serviceProvider = serviceCollection.BuildServiceProvider();
    }

    /// <summary>
    /// Gets a CLI builder with a mock implementation of <see cref="ILsaUserRights"/>.
    /// </summary>
    public CliBuilder CliBuilder =>
        _disposed
            ? throw new ObjectDisposedException(GetType().FullName)
            : _serviceProvider.GetRequiredService<CliBuilder>();

    /// <inheritdoc />
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Releases resources when they are no longer required.
    /// </summary>
    /// <param name="disposing">A value indicating whether the method call comes from a dispose method (its value is <see langword="true"/>) or from a finalizer (its value is <see langword="false"/>).</param>
    protected virtual void Dispose(bool disposing)
    {
        if (_disposed)
        {
            return;
        }

        if (disposing)
        {
            _serviceProvider.Dispose();
        }

        _disposed = true;
    }
}