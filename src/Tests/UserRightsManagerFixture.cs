namespace Tests;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

using UserRights.Application;

/// <summary>
/// Represents a test fixture with the <see cref="IUserRightsManager"/> implementation.
/// </summary>
public class UserRightsManagerFixture : IDisposable
{
    private readonly ServiceProvider _serviceProvider;

    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="UserRightsManagerFixture"/> class.
    /// </summary>
    public UserRightsManagerFixture()
    {
        var serviceCollection = new ServiceCollection()
            .AddLogging(builder => builder
                .ClearProviders()
                .SetMinimumLevel(LogLevel.Trace)
                .AddDebug());

        serviceCollection.AddSingleton<IUserRightsManager, UserRightsManager>();

        _serviceProvider = serviceCollection.BuildServiceProvider();
    }

    /// <summary>
    /// Gets an instance of a <see cref="IUserRightsManager"/> implementation.
    /// </summary>
    public IUserRightsManager UserRightsManager =>
        _disposed
            ? throw new ObjectDisposedException(GetType().FullName)
            : _serviceProvider.GetRequiredService<IUserRightsManager>();

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