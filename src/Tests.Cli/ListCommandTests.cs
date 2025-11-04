namespace Tests.Cli;

using System.Globalization;
using System.Security.Principal;
using System.Text.Json;

using CsvHelper;
using CsvHelper.Configuration;

using UserRights.Application;
using UserRights.Cli;
using UserRights.Extensions.Security;

using static Tests.TestData;

/// <summary>
/// Represents integration tests for list functionality.
/// </summary>
[TestClass]
public class ListCommandTests
{
    /// <summary>
    /// Gets or sets the unit test context.
    /// </summary>
    public required TestContext TestContext { get; set; }

    /// <summary>
    /// Verifies listing user rights to a JSON file.
    /// </summary>
    /// <returns>A task representing the asynchronous operation.</returns>
    [TestMethod]
    public async Task PathAndJsonShouldWork()
    {
        // Arrange.
        var principals1 = new List<SecurityIdentifier>
        {
            PrincipalSid1,
            PrincipalSid2
        };

        var principals2 = new List<SecurityIdentifier>
        {
            PrincipalSid1,
            PrincipalSid2
        };

        var database = new Dictionary<string, ICollection<SecurityIdentifier>>(StringComparer.Ordinal)
        {
            { Privilege1, principals1 },
            { Privilege2, principals2 }
        };

        var expected = database
            .SelectMany(kvp => kvp.Value.Select(p => new UserRightEntry(kvp.Key, p.Value, p.ToAccount().Value)))
            .OrderBy(p => p.Privilege, StringComparer.OrdinalIgnoreCase)
            .ThenBy(p => p.SecurityId, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var policy = new MockLsaUserRights(database);

        using var fixture = new CliBuilderFixture(policy);

        var rootCommand = fixture.CliBuilder.Build();

        var file = Path.GetTempFileName();
        var args = new[] { "list", "--json", "--path", file };

        // Act.
        int rc;
        UserRightEntry[] actual;
        try
        {
            rc = await rootCommand.Parse(args).ThrowIfInvalid().RunAsync(TestContext.CancellationToken).ConfigureAwait(false);

            var stream = File.OpenRead(file);
            await using (stream.ConfigureAwait(false))
            {
                var results = await JsonSerializer.DeserializeAsync<UserRightEntry[]>(stream, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
                actual = results
                    ?.OrderBy(p => p.Privilege, StringComparer.OrdinalIgnoreCase)
                    .ThenBy(p => p.SecurityId, StringComparer.OrdinalIgnoreCase)
                    .ToArray() ?? [];
            }
        }
        finally
        {
            File.Delete(file);
        }

        // Assert.
        Assert.AreEqual(0, rc);
        CollectionAssert.AreEqual(expected, actual);
    }

    /// <summary>
    /// Verifies listing user rights to a CSV file.
    /// </summary>
    /// <returns>A task representing the asynchronous operation.</returns>
    [TestMethod]
    public async Task PathShouldWork()
    {
        // Arrange.
        var principals1 = new List<SecurityIdentifier>
        {
            PrincipalSid1,
            PrincipalSid2
        };
        var principals2 = new List<SecurityIdentifier>
        {
            PrincipalSid1,
            PrincipalSid2
        };

        var database = new Dictionary<string, ICollection<SecurityIdentifier>>(StringComparer.Ordinal)
        {
            { Privilege1, principals1 },
            { Privilege2, principals2 }
        };

        var policy = new MockLsaUserRights(database);

        var expected = database
            .SelectMany(kvp => kvp.Value.Select(p => new UserRightEntry(kvp.Key, p.Value, p.ToAccount().Value)))
            .OrderBy(p => p.Privilege, StringComparer.OrdinalIgnoreCase)
            .ThenBy(p => p.SecurityId, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        using var fixture = new CliBuilderFixture(policy);

        var rootCommand = fixture.CliBuilder.Build();

        var file = Path.GetTempFileName();
        var args = new[] { "list", "--path", file };

        // Act.
        int rc;
        UserRightEntry[] actual;
        try
        {
            rc = await rootCommand.Parse(args).ThrowIfInvalid().RunAsync(TestContext.CancellationToken).ConfigureAwait(false);

            var csvConfiguration = new CsvConfiguration(CultureInfo.InvariantCulture)
            {
                PrepareHeaderForMatch = a => a.Header.ToUpperInvariant() ?? throw new InvalidOperationException()
            };

            using var streamReader = new StreamReader(file);
            using var csvReader = new CsvReader(streamReader, csvConfiguration);

            actual = await csvReader.GetRecordsAsync<UserRightEntry>(TestContext.CancellationToken)
                .OrderBy(p => p.Privilege, StringComparer.OrdinalIgnoreCase)
                .ThenBy(p => p.SecurityId, StringComparer.OrdinalIgnoreCase)
                .ToArrayAsync(TestContext.CancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            File.Delete(file);
        }

        // Assert.
        Assert.AreEqual(0, rc);
        CollectionAssert.AreEqual(expected, actual);
    }
}