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
    private readonly IServiceCollection serviceCollection;
    private readonly Lazy<ServiceProvider> serviceProvider;

    private bool disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="UserRightsManagerTestBase"/> class.
    /// </summary>
    protected UserRightsManagerTestBase()
    {
        serviceCollection = new ServiceCollection()
            .AddSingleton<IUserRightsManager, UserRightsManager>()
            .AddLogging(builder => builder
                .ClearProviders()
                .SetMinimumLevel(LogLevel.Trace)
                .AddDebug());

        // Defer the creation until the instance is accessed to allow inheritors to modify the service collection.
        serviceProvider = new Lazy<ServiceProvider>(serviceCollection.BuildServiceProvider);
    }

    /// <summary>
    /// Gets the service collection.
    /// </summary>
    protected IServiceCollection ServiceCollection
    {
        get
        {
            ObjectDisposedException.ThrowIf(disposed, this);

            return serviceCollection;
        }
    }

    /// <summary>
    /// Gets the service provider.
    /// </summary>
    protected ServiceProvider ServiceProvider
    {
        get
        {
            ObjectDisposedException.ThrowIf(disposed, this);

            return serviceProvider.Value;
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
        if (disposed)
        {
            return;
        }

        if (disposing)
        {
            if (serviceProvider.IsValueCreated)
            {
                serviceProvider.Value.Dispose();
            }

            disposed = true;
        }
    }
}