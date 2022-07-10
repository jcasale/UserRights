namespace UserRights.Cli;

using System;
using System.ComponentModel;
using System.Globalization;
using System.Text.RegularExpressions;

/// <summary>
/// Converts a <see cref="string"/> to an instance of a <see cref="Regex"/>.
/// </summary>
public class RegexTypeConverter : TypeConverter
{
    /// <inheritdoc />
    public override bool CanConvertFrom(ITypeDescriptorContext context, Type sourceType)
    {
        if (sourceType == typeof(string))
        {
            return true;
        }

        return base.CanConvertFrom(context, sourceType);
    }

    /// <inheritdoc />
    public override object ConvertFrom(ITypeDescriptorContext context, CultureInfo culture, object value)
    {
        if (value is string s)
        {
            try
            {
                return new Regex(s, RegexOptions.None, TimeSpan.FromSeconds(1));
            }
            catch (Exception e)
            {
                var message = string.Format(CultureInfo.InvariantCulture, "Invalid regular expression, error {0}", e.Message);

                throw new SyntaxException(message, e);
            }
        }

        return base.ConvertFrom(context, culture, value);
    }
}