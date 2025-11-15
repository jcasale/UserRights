namespace UserRights;

using System.Globalization;

using Serilog.Events;
using Serilog.Sinks.EventLog;

/// <summary>
/// Extracts the event id from the log properties.
/// </summary>
public class EventIdProvider : IEventIdProvider
{
    /// <inheritdoc/>
    public ushort ComputeEventId(LogEvent logEvent)
    {
        ArgumentNullException.ThrowIfNull(logEvent);

        if (!logEvent.Properties.TryGetValue("EventId", out var property))
        {
            return 0;
        }

        var id = property switch
        {
            // The EventId property was provided by Serilog directly.
            ScalarValue scalar => scalar.ToString("G", NumberFormatInfo.InvariantInfo),

            // The EventId property was provided by Microsoft.Extensions.Logging.
            StructureValue structure => structure.Properties.FirstOrDefault(p => string.Equals("Id", p.Name, StringComparison.OrdinalIgnoreCase))?.Value.ToString("G", NumberFormatInfo.InvariantInfo),

            _ => null
        };

        if (short.TryParse(id, NumberStyles.Any, CultureInfo.InvariantCulture, out var result))
        {
            return (ushort)result;
        }

        return 0;
    }
}