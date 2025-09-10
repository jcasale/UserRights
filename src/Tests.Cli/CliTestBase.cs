namespace Tests.Cli;

using System;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

/// <summary>
/// Represents a test configuration that provides command line infrastructure.
/// </summary>
public abstract class CliTestBase : IDisposable
{
    private readonly IServiceCollection serviceCollection;
    private readonly Lazy<ServiceProvider> serviceProvider;

    private bool disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="CliTestBase"/> class.
    /// </summary>
    protected CliTestBase()
    {
        serviceCollection = new ServiceCollection()
            .AddLogging(builder => builder
                .ClearProviders()
                .SetMinimumLevel(LogLevel.Trace)
                .AddDebug());

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
            serviceProvider.Value.Dispose();
            disposed = true;
        }
    }
}