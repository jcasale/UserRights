namespace UserRights.Extensions.Serialization;

using System.Text.Json;

using CsvHelper;

/// <summary>
/// Represents extensions for converting and serializing objects.
/// </summary>
public static class SerializationExtensions
{
    /// <summary>
    /// Configures the CSV serializer options to always quote output and escape it when necessary.
    /// </summary>
    private static readonly CsvWriterOptions CsvOptions = new()
    {
        Injection = CsvInjection.Escape,
        Quoting = CsvQuoting.Always
    };

    /// <summary>
    /// Configures the JSON serializer options to format output as indented.
    /// </summary>
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    /// <summary>
    /// Serializes data to a stream in CSV format.
    /// </summary>
    /// <typeparam name="T">The type of data.</typeparam>
    /// <param name="data">The data to serialize.</param>
    /// <param name="stream">The UTF-8 stream to write to.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to cancel the write operation.</param>
    /// <returns>A task that represents the asynchronous write operation.</returns>
    /// <remarks>
    /// The type <typeparamref name="T"/> must be a partial type marked with <see cref="CsvRecordAttribute"/>, as the CSV serializer uses source-generated mapping code and does not support other types.
    /// </remarks>
    /// <exception cref="SerializationException">
    /// Thrown when <typeparamref name="T"/> is not marked with <see cref="CsvRecordAttribute"/>, or when the data cannot be written.
    /// </exception>
    public static async Task ToCsv<T>(this IEnumerable<T> data, Stream stream, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(stream);

        try
        {
            await using var writer = CsvWriter.Create(stream, CsvOptions, true);
            await writer.WriteRecordsAsync(data, cancellationToken);
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            throw new SerializationException("Failed to serialize the data to a stream in CSV format.", e);
        }
    }

    /// <summary>
    /// Serializes data to a stream in JSON format.
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
            await JsonSerializer.SerializeAsync(stream, data, JsonOptions, cancellationToken);
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            throw new SerializationException("Failed to serialize the data to a stream in JSON format.", e);
        }
    }
}