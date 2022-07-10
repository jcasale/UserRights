namespace UserRights.Cli;

using System;
using Spectre.Console.Cli;

/// <summary>
/// Allows types to be resolved from dependency injection.
/// </summary>
public class TypeResolver : ITypeResolver
{
    private readonly IServiceProvider provider;

    /// <summary>
    /// Initializes a new instance of the <see cref="TypeResolver"/> class.
    /// </summary>
    /// <param name="provider">The service provider.</param>
    public TypeResolver(IServiceProvider provider)
        => this.provider = provider ?? throw new ArgumentNullException(nameof(provider));

    /// <inheritdoc />
    public object Resolve(Type type)
    {
        if (type is null)
        {
            return null;
        }

        // The Spectre.Console.Cli library requires the non strict retrieval implementation.
        return this.provider.GetService(type);
    }
}