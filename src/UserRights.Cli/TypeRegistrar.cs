namespace UserRights.Cli;

using System;
using Microsoft.Extensions.DependencyInjection;
using Spectre.Console.Cli;

/// <summary>
/// Allows types to be registered for dependency injection.
/// </summary>
public class TypeRegistrar : ITypeRegistrar, IDisposable
{
    private readonly IServiceCollection collection;

    private ServiceProvider serviceProvider;
    private bool disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="TypeRegistrar"/> class.
    /// </summary>
    /// <param name="collection">The collection of services.</param>
    public TypeRegistrar(IServiceCollection collection)
        => this.collection = collection ?? throw new ArgumentNullException(nameof(collection));

    /// <inheritdoc />
    public ITypeResolver Build()
    {
        if (this.disposed)
        {
            throw new ObjectDisposedException(this.GetType().FullName);
        }

        this.serviceProvider ??= this.collection.BuildServiceProvider();

        return new TypeResolver(this.serviceProvider);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        this.Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <inheritdoc />
    public void Register(Type service, Type implementation)
    {
        if (this.disposed)
        {
            throw new ObjectDisposedException(this.GetType().FullName);
        }

        if (service is null)
        {
            throw new ArgumentNullException(nameof(service));
        }

        if (implementation is null)
        {
            throw new ArgumentNullException(nameof(implementation));
        }

        this.collection.AddSingleton(service, implementation);
    }

    /// <inheritdoc />
    public void RegisterInstance(Type service, object implementation)
    {
        if (this.disposed)
        {
            throw new ObjectDisposedException(this.GetType().FullName);
        }

        if (service is null)
        {
            throw new ArgumentNullException(nameof(service));
        }

        if (implementation is null)
        {
            throw new ArgumentNullException(nameof(implementation));
        }

        this.collection.AddSingleton(service, implementation);
    }

    /// <inheritdoc />
    public void RegisterLazy(Type service, Func<object> factory)
    {
        if (this.disposed)
        {
            throw new ObjectDisposedException(this.GetType().FullName);
        }

        if (service is null)
        {
            throw new ArgumentNullException(nameof(service));
        }

        if (factory is null)
        {
            throw new ArgumentNullException(nameof(factory));
        }

        this.collection.AddSingleton(service, _ => factory());
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
            this.serviceProvider?.Dispose();
            this.disposed = true;
        }
    }
}