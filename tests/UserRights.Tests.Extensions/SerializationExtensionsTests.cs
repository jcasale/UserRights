namespace UserRights.Tests.Extensions;

using System.Text;

using UserRights.Application;
using UserRights.Extensions.Serialization;

using static UserRights.Tests.TestData;

/// <summary>
/// Represents tests for the serialization extensions.
/// </summary>
[TestClass]
public class SerializationExtensionsTests
{
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
        var text = await WriteCsv(entries).ConfigureAwait(false);

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
        var text = await WriteCsv(entries).ConfigureAwait(false);

        // Assert.
        Assert.Contains($"\"{Privilege1}\"", text, StringComparison.Ordinal);
        Assert.Contains($"\"{PrincipalSid1.Value}\"", text, StringComparison.Ordinal);
        Assert.Contains($"\"{PrincipalName1}\"", text, StringComparison.Ordinal);
    }

    /// <summary>
    /// Writes entries as CSV and returns the text.
    /// </summary>
    /// <param name="entries">The entries to write.</param>
    /// <returns>A task whose result is the CSV text.</returns>
    private async Task<string> WriteCsv(UserRightEntry[] entries)
    {
        var stream = new MemoryStream();
        await using (stream.ConfigureAwait(false))
        {
            await entries.ToCsv(stream, TestContext.CancellationToken).ConfigureAwait(false);

            return Encoding.UTF8.GetString(stream.ToArray());
        }
    }
}