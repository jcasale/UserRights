namespace UserRights.Extensions.Tests;

using System.Text;

using UserRights.Application;
using UserRights.Extensions.Serialization;

using static UserRights.Testing.TestData;

/// <summary>
/// Represents tests for the serialization extensions.
/// </summary>
[TestClass]
public class SerializationExtensionsTests
{
    /// <summary>
    /// The expected CSV header, derived from the property names of <see cref="UserRightEntry"/>.
    /// </summary>
    private const string ExpectedHeader = $"\"{nameof(UserRightEntry.Privilege)}\",\"{nameof(UserRightEntry.SecurityId)}\",\"{nameof(UserRightEntry.AccountName)}\"\r\n";

    /// <summary>
    /// The account name containing non-ASCII characters.
    /// </summary>
    private const string NonAsciiAccountName = "AUTORITÉ NT\\Système";

    /// <summary>
    /// Gets the unit test context.
    /// </summary>
    public required TestContext TestContext { get; init; }

    /// <summary>
    /// Verifies fields beginning with a spreadsheet formula character are escaped.
    /// </summary>
    /// <param name="privilege">The privilege that begins with a formula character.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    [TestMethod]
    [DataRow("=1+1")]
    [DataRow("+x")]
    [DataRow("-x")]
    [DataRow("@x")]
    public async Task ToCsv_WithInjectionCharacters_EscapesFields(string privilege)
    {
        // Arrange.
        UserRightEntry[] entries = [new(privilege, PrincipalSid1.Value, PrincipalName1)];

        // Act.
        var text = await WriteCsv(entries);

        // Assert.
        Assert.Contains(privilege, text, StringComparison.Ordinal);
        Assert.DoesNotContain($"\"{privilege}\"", text, StringComparison.Ordinal);
    }

    /// <summary>
    /// Verifies ordinary fields are written unchanged.
    /// </summary>
    /// <returns>A task representing the asynchronous operation.</returns>
    [TestMethod]
    public async Task ToCsv_WithOrdinaryValues_DoesNotModifyFields()
    {
        // Arrange.
        UserRightEntry[] entries = [new(Privilege1, PrincipalSid1.Value, PrincipalName1)];

        // Act.
        var text = await WriteCsv(entries);

        // Assert.
        Assert.Contains($"\"{Privilege1}\"", text, StringComparison.Ordinal);
        Assert.Contains($"\"{PrincipalSid1.Value}\"", text, StringComparison.Ordinal);
        Assert.Contains($"\"{PrincipalName1}\"", text, StringComparison.Ordinal);
    }

    /// <summary>
    /// Verifies the header uses the exact property names, in order and quoted.
    /// </summary>
    /// <returns>A task representing the asynchronous operation.</returns>
    [TestMethod]
    public async Task ToCsv_WritesExpectedHeader()
    {
        // Arrange.
        UserRightEntry[] entries = [new(Privilege1, PrincipalSid1.Value, PrincipalName1)];

        // Act.
        var text = await WriteCsv(entries);

        // Assert.
        Assert.StartsWith(ExpectedHeader, text, StringComparison.Ordinal);
    }

    /// <summary>
    /// Verifies the output does not begin with a UTF-8 byte order mark.
    /// </summary>
    /// <returns>A task representing the asynchronous operation.</returns>
    [TestMethod]
    public async Task ToCsv_DoesNotWriteByteOrderMark()
    {
        // Arrange.
        UserRightEntry[] entries = [new(Privilege1, PrincipalSid1.Value, PrincipalName1)];

        // Act.
        var bytes = await WriteCsvBytes(entries);

        // Assert.
        Assert.IsFalse(bytes.AsSpan().StartsWith(Encoding.UTF8.Preamble));
        Assert.AreEqual((byte)'"', bytes[0]);
    }

    /// <summary>
    /// Verifies non-ASCII characters are written as UTF-8.
    /// </summary>
    /// <returns>A task representing the asynchronous operation.</returns>
    [TestMethod]
    public async Task ToCsv_WithNonAsciiAccountName_WritesUtf8()
    {
        // Arrange.
        UserRightEntry[] entries = [new(Privilege1, PrincipalSid1.Value, NonAsciiAccountName)];
        var expected = Encoding.UTF8.GetBytes($"\"{NonAsciiAccountName}\"");

        // Act.
        var bytes = await WriteCsvBytes(entries);

        // Assert.
        Assert.AreNotEqual(-1, bytes.AsSpan().IndexOf(expected));
    }

    /// <summary>
    /// Verifies a null account name is written as a quoted empty field.
    /// </summary>
    /// <returns>A task representing the asynchronous operation.</returns>
    [TestMethod]
    public async Task ToCsv_WithNullAccountName_WritesQuotedEmptyField()
    {
        // Arrange.
        UserRightEntry[] entries = [new(Privilege1, PrincipalSid1.Value, null)];

        // Act.
        var text = await WriteCsv(entries);

        // Assert.
        Assert.EndsWith(",\"\"\r\n", text, StringComparison.Ordinal);
    }

    /// <summary>
    /// Writes entries as CSV and returns the text.
    /// </summary>
    /// <param name="entries">The entries to write.</param>
    /// <returns>A task whose result is the CSV text.</returns>
    private async Task<string> WriteCsv(UserRightEntry[] entries) => Encoding.UTF8.GetString(await WriteCsvBytes(entries));

    /// <summary>
    /// Writes entries as CSV and returns the raw bytes.
    /// </summary>
    /// <param name="entries">The entries to write.</param>
    /// <returns>A task whose result is the CSV bytes.</returns>
    private async Task<byte[]> WriteCsvBytes(UserRightEntry[] entries)
    {
        await using var stream = new MemoryStream();
        await entries.ToCsv(stream, TestContext.CancellationToken);

        return stream.ToArray();
    }
}