namespace Tests;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

using Moq;

using UserRights.Application;
using UserRights.Cli;

/// <summary>
/// Represents a test fixture with a <see cref="CliBuilder"/> implementation for testing the CLI.
/// </summary>
public class CliMockBuilder : IDisposable
{
    private readonly ServiceProvider _serviceProvider;

    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="CliMockBuilder"/> class.
    /// </summary>
    /// <remarks>
    /// Creates a CLI with an empty, mock <see cref="ILsaUserRights"/> implementation, and a mock <see cref="IUserRightsManager"/> implementation.
    /// </remarks>
    public CliMockBuilder()
    {
        var repository = new MockRepository(MockBehavior.Strict);

        // Mock the LSA user rights interface.
        var lsaUserRights = repository.Create<ILsaUserRights>();

        // Only calls to Connect are expected.
        lsaUserRights.Setup(x => x.Connect(It.IsAny<string>()));

        // Mock the user rights manager interface.
        var userRightsManager = repository.Create<IUserRightsManager>();
        userRightsManager
            .Setup(x => x.GetUserRights(It.IsAny<IUserRights>()))
            .Returns([]);

        userRightsManager
            .Setup(x => x.ModifyPrincipal(
                It.IsAny<IUserRights>(),
                It.IsAny<string>(),
                It.IsAny<string[]>(),
                It.IsAny<string[]>(),
                It.IsAny<bool>(),
                It.IsAny<bool>(),
                It.IsAny<bool>()));

        userRightsManager
            .Setup(x => x.ModifyPrivilege(
                It.IsAny<IUserRights>(),
                It.IsAny<string>(),
                It.IsAny<string[]>(),
                It.IsAny<string[]>(),
                It.IsAny<bool>(),
                It.IsAny<bool>(),
                It.IsAny<string?>(),
                It.IsAny<bool>()));

        var serviceCollection = new ServiceCollection()
            .AddLogging(builder => builder
                .ClearProviders()
                .SetMinimumLevel(LogLevel.Trace)
                .AddDebug());

        serviceCollection.AddSingleton(lsaUserRights.Object);
        serviceCollection.AddSingleton(userRightsManager.Object);
        serviceCollection.AddSingleton<CliBuilder>();

        _serviceProvider = serviceCollection.BuildServiceProvider();
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CliMockBuilder"/> class.
    /// </summary>
    /// <param name="policy">The existing LSA user rights implementation.</param>
    /// <remarks>
    /// Creates a CLI with a user-supplied <see cref="ILsaUserRights"/> implementation, and a complete instance of a <see cref="IUserRightsManager"/> implementation.
    /// </remarks>
    public CliMockBuilder(ILsaUserRights policy)
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