namespace UserRights.Extensions.Collections;

using System;
using System.Collections.Generic;

/// <summary>
/// Represents extensions for working with collections.
/// </summary>
public static class CollectionExtensions
{
    /// <summary>
    /// Creates a hashset from the specified collection.
    /// </summary>
    /// <typeparam name="T">The type of item in the collection.</typeparam>
    /// <param name="collection">The input collection.</param>
    /// <returns>A hashset.</returns>
    public static ISet<T> ToHashSet<T>(this IEnumerable<T> collection)
    {
        if (collection is null)
        {
            throw new ArgumentNullException(nameof(collection));
        }

        return new HashSet<T>(collection);
    }

    /// <summary>
    /// Creates a hashset from the specified collection.
    /// </summary>
    /// <typeparam name="T">The type of item in the collection.</typeparam>
    /// <param name="collection">The input collection.</param>
    /// <param name="comparer">The equality comparer.</param>
    /// <returns>A hashset.</returns>
    public static ISet<T> ToHashSet<T>(this IEnumerable<T> collection, IEqualityComparer<T> comparer)
    {
        if (collection is null)
        {
            throw new ArgumentNullException(nameof(collection));
        }

        return new HashSet<T>(collection, comparer);
    }
}