namespace Tests.Cli;

using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Spectre.Console.Cli;
using UserRights.Cli;

/// <summary>
/// Represents a test configuration that provides command line infrastructure.
/// </summary>
public abstract class CliTestBase : IDisposable
{
    private readonly TypeRegistrar registrar;
    private readonly CommandApp commandApp;

    private bool disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="CliTestBase"/> class.
    /// </summary>
    protected CliTestBase()
    {
        var serviceCollection = new ServiceCollection()
            .AddLogging(builder => builder
                .ClearProviders()
                .SetMinimumLevel(LogLevel.Trace)
                .AddDebug());

        this.registrar = new TypeRegistrar(serviceCollection);

        this.commandApp = CommandAppBuilder.Build(this.registrar);
    }

    /// <summary>
    /// Gets the command line application.
    /// </summary>
    protected CommandApp CommandApp
    {
        get
        {
            if (this.disposed)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }

            return this.commandApp;
        }
    }

    /// <summary>
    /// Gets the type registrar.
    /// </summary>
    protected TypeRegistrar Registrar
    {
        get
        {
            if (this.disposed)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }

            return this.registrar;
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        this.Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Releases resources when they are no longer required.
    /// </summary>
    /// <param name="disposing">A value indicating whether the method call comes from a dispose method (its value is <c>true</c>) or from a finalizer (its value is <c>false</c>).</param>
    protected virtual void Dispose(bool disposing)
    {
        if (this.disposed)
        {
            return;
        }

        if (disposing)
        {
            this.registrar?.Dispose();
            this.disposed = true;
        }
    }
}