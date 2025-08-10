namespace Tests.Cli;

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Text.Json;
using System.Threading.Tasks;

using CsvHelper;
using CsvHelper.Configuration;
using Microsoft.Extensions.DependencyInjection;
using UserRights.Application;
using UserRights.Cli;
using UserRights.Extensions.Security;
using Xunit;

using static Tests.TestData;

/// <summary>
/// Represents integration tests for list functionality.
/// </summary>
public sealed class ListCommandTests : CliTestBase
{
    /// <summary>
    /// Verifies listing user rights to a JSON file.
    /// </summary>
    /// <returns>A task representing the asynchronous operation.</returns>
    [Fact]
    public async Task PathAndJsonShouldWork()
    {
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

        this.ServiceCollection.AddSingleton<ILsaUserRights>(policy);
        this.ServiceCollection.AddSingleton<IUserRightsManager, UserRightsManager>();
        this.ServiceCollection.AddSingleton<CliBuilder>();

        var builder = this.ServiceProvider.GetRequiredService<CliBuilder>();

        var configuration = builder.Build();

        var file = Path.GetTempFileName();
        var args = new[]
        {
            "list",
            "--json",
            "--path",
            file
        };

        int rc;
        UserRightEntry[] actual;
        try
        {
            rc = await configuration.Parse(args).Validate().InvokeAsync();

            await using var stream = File.OpenRead(file);

            var results = await JsonSerializer.DeserializeAsync<UserRightEntry[]>(stream);
            actual = results
                ?.OrderBy(p => p.Privilege, StringComparer.OrdinalIgnoreCase)
                .ThenBy(p => p.SecurityId, StringComparer.OrdinalIgnoreCase)
                .ToArray() ?? [];
        }
        finally
        {
            File.Delete(file);
        }

        Assert.Equal(0, rc);
        Assert.Equal(expected, actual, new UserRightEntryEqualityComparer());
    }

    /// <summary>
    /// Verifies listing user rights to a CSV file.
    /// </summary>
    /// <returns>A task representing the asynchronous operation.</returns>
    [Fact]
    public async Task PathShouldWork()
    {
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

        this.ServiceCollection.AddSingleton<ILsaUserRights>(policy);
        this.ServiceCollection.AddSingleton<IUserRightsManager, UserRightsManager>();
        this.ServiceCollection.AddSingleton<CliBuilder>();

        var builder = this.ServiceProvider.GetRequiredService<CliBuilder>();

        var configuration = builder.Build();

        var file = Path.GetTempFileName();
        var args = new[]
        {
            "list",
            "--path",
            file
        };

        int rc;
        UserRightEntry[] actual;
        try
        {
            rc = await configuration.Parse(args).Validate().InvokeAsync();

            var csvConfiguration = new CsvConfiguration(CultureInfo.InvariantCulture)
            {
                PrepareHeaderForMatch = a => a.Header.ToUpperInvariant() ?? throw new InvalidOperationException()
            };

            using var streamReader = new StreamReader(file);
            using var csvReader = new CsvReader(streamReader, csvConfiguration);

            actual = await csvReader.GetRecordsAsync<UserRightEntry>()
                .OrderBy(p => p.Privilege, StringComparer.OrdinalIgnoreCase)
                .ThenBy(p => p.SecurityId, StringComparer.OrdinalIgnoreCase)
                .ToArrayAsync();
        }
        finally
        {
            File.Delete(file);
        }

        Assert.Equal(0, rc);
        Assert.Equal(expected, actual, new UserRightEntryEqualityComparer());
    }
}