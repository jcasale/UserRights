namespace Tests.Application;

using System;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using UserRights.Application;

/// <summary>
/// Represents the test base for <see cref="UserRightsManager"/> application.
/// </summary>
public abstract class UserRightsManagerTestBase : IDisposable
{
    private readonly IServiceCollection _serviceCollection;
    private readonly Lazy<ServiceProvider> _serviceProvider;

    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="UserRightsManagerTestBase"/> class.
    /// </summary>
    protected UserRightsManagerTestBase()
    {
        _serviceCollection = new ServiceCollection()
            .AddSingleton<IUserRightsManager, UserRightsManager>()
            .AddLogging(builder => builder
                .ClearProviders()
                .SetMinimumLevel(LogLevel.Trace)
                .AddDebug());

        // Defer the creation until the instance is accessed to allow inheritors to modify the service collection.
        _serviceProvider = new(_serviceCollection.BuildServiceProvider);
    }

    /// <summary>
    /// Gets the service collection.
    /// </summary>
    protected IServiceCollection ServiceCollection
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            return _serviceCollection;
        }
    }

    /// <summary>
    /// Gets the service provider.
    /// </summary>
    protected ServiceProvider ServiceProvider
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            return _serviceProvider.Value;
        }
    }

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
            if (_serviceProvider.IsValueCreated)
            {
                _serviceProvider.Value.Dispose();
            }

            _disposed = true;
        }
    }
}