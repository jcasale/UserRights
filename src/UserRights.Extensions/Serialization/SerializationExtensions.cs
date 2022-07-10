namespace UserRights.Extensions.Serialization;

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using CsvHelper;
using CsvHelper.Configuration;
using Newtonsoft.Json;

/// <summary>
/// Represents extensions for converting and serializing objects.
/// </summary>
public static class SerializationExtensions
{
    /// <summary>
    /// Serializes data to a string in CSV format.
    /// </summary>
    /// <typeparam name="T">The type of data.</typeparam>
    /// <param name="data">The data to serialize.</param>
    /// <returns>The serialized data.</returns>
    public static string ToCsv<T>(this IEnumerable<T> data)
    {
        if (data is null)
        {
            throw new ArgumentNullException(nameof(data));
        }

        var csvConfiguration = new CsvConfiguration(CultureInfo.InvariantCulture)
        {
            ShouldQuote = _ => true
        };

        try
        {
            using var stringWriter = new StringWriter(CultureInfo.InvariantCulture);
            using var csvWriter = new CsvWriter(stringWriter, csvConfiguration);
            csvWriter.WriteRecords(data);

            return stringWriter.ToString();
        }
        catch (Exception e)
        {
            throw new SerializationException("Failed to serialize the data to a string in CSV format.", e);
        }
    }

    /// <summary>
    /// Serializes data to a string in JSON format.
    /// </summary>
    /// <typeparam name="T">The type of data.</typeparam>
    /// <param name="data">The data to serialize.</param>
    /// <returns>The serialized data.</returns>
    public static string ToJson<T>(this T data)
    {
        if (data is null)
        {
            throw new ArgumentNullException(nameof(data));
        }

        var serializer = new JsonSerializer
        {
            Culture = CultureInfo.InvariantCulture,
            Formatting = Formatting.Indented,
            NullValueHandling = NullValueHandling.Include
        };

        try
        {
            using var stringWriter = new StringWriter(CultureInfo.InvariantCulture);
            using var jsonTextWriter = new JsonTextWriter(stringWriter);
            serializer.Serialize(jsonTextWriter, data);

            return stringWriter.ToString();
        }
        catch (Exception e)
        {
            throw new SerializationException("Failed to serialize the data to a string in JSON format.", e);
        }
    }
}