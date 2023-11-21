namespace UserRights.Extensions.Serialization;

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

using CsvHelper;
using CsvHelper.Configuration;

/// <summary>
/// Represents extensions for converting and serializing objects.
/// </summary>
public static class SerializationExtensions
{
    /// <summary>
    /// Configures the JSON serializer options to format output as indented.
    /// </summary>
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true
    };

    /// <summary>
    /// Serializes data to a string in CSV format.
    /// </summary>
    /// <typeparam name="T">The type of data.</typeparam>
    /// <param name="data">The data to serialize.</param>
    /// <param name="stream">The UTF-8 stream to write to.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to cancel the write operation.</param>
    /// <returns>A task that represents the asynchronous write operation.</returns>
    public static async Task ToCsv<T>(this IEnumerable<T> data, Stream stream, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(stream);

        var csvConfiguration = new CsvConfiguration(CultureInfo.InvariantCulture)
        {
            ShouldQuote = _ => true
        };

        try
        {
            using var writer = new StreamWriter(stream, new UTF8Encoding(false), leaveOpen: true);
            using var csv = new CsvWriter(writer, csvConfiguration, leaveOpen: true);
            await csv.WriteRecordsAsync(data, cancellationToken).ConfigureAwait(false);
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
    /// <param name="stream">The UTF-8 stream to write to.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to cancel the write operation.</param>
    /// <returns>A task that represents the asynchronous write operation.</returns>
    public static async Task ToJson<T>(this T data, Stream stream, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(stream);

        try
        {
            await JsonSerializer.SerializeAsync(stream, data, Options, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception e)
        {
            throw new SerializationException("Failed to serialize the data to a string in JSON format.", e);
        }
    }
}