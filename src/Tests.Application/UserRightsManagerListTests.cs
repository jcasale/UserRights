namespace Tests.Application;

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

using CsvHelper;
using CsvHelper.Configuration;
using Microsoft.Extensions.DependencyInjection;
using UserRights.Application;
using UserRights.Extensions.Security;
using UserRights.Extensions.Serialization;
using Xunit;

using static Tests.TestData;

/// <summary>
/// Represents tests for <see cref="IUserRightsManager"/> list functionality.
/// </summary>
public sealed class UserRightsManagerListTests : UserRightsManagerTestBase
{
    /// <summary>
    /// Verifies invalid arguments throw an instance of <see cref="ArgumentException"/>.
    /// </summary>
    [Fact]
    public void InvalidArgumentsThrowsException()
    {
        var manager = this.ServiceProvider.GetRequiredService<IUserRightsManager>();

        Assert.ThrowsAny<ArgumentException>(() => manager.GetUserRights(null!));
    }

    /// <summary>
    /// Verifies listing user rights and serializing the output to a CSV.
    /// </summary>
    /// <returns>A task that represents the asynchronous write operation.</returns>
    [Fact]
    public async Task SerializingToCsvShouldWork()
    {
        var principals1 = new HashSet<SecurityIdentifier>
        {
            PrincipalSid1,
            PrincipalSid2
        };

        var principals2 = new HashSet<SecurityIdentifier>
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
        policy.Connect("SystemName");

        Assert.Equal(new[] { PrincipalSid1, PrincipalSid2 }, policy.LsaEnumerateAccountsWithUserRight().OrderBy(p => p));
        Assert.Equal(new[] { Privilege1, Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid1));
        Assert.Equal(new[] { Privilege1, Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid2));

        var manager = this.ServiceProvider.GetRequiredService<IUserRightsManager>();
        var userRights = manager.GetUserRights(policy).ToArray();

        Assert.Equal(expected, userRights, new UserRightEntryEqualityComparer());

        using var stream = new MemoryStream();
        await userRights.ToCsv(stream).ConfigureAwait(false);
        stream.Position = 0;
        using var reader = new StreamReader(stream, Encoding.UTF8);
        var serialized = await reader.ReadToEndAsync().ConfigureAwait(false);

        var configuration = new CsvConfiguration(CultureInfo.InvariantCulture)
        {
            PrepareHeaderForMatch = a => a.Header.ToUpperInvariant()
        };

        using var stringReader = new StringReader(serialized);
        using var csvReader = new CsvReader(stringReader, configuration);

        var actual = csvReader.GetRecords<UserRightEntry>()
            .OrderBy(p => p.Privilege, StringComparer.OrdinalIgnoreCase)
            .ThenBy(p => p.SecurityId, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        Assert.Equal(expected, actual, new UserRightEntryEqualityComparer());
    }

    /// <summary>
    /// Verifies listing user rights and serializing the output to a JSON.
    /// </summary>
    /// <returns>A task that represents the asynchronous write operation.</returns>
    [Fact]
    public async Task SerializingToJsonShouldWork()
    {
        var principals1 = new HashSet<SecurityIdentifier>
        {
            PrincipalSid1,
            PrincipalSid2
        };

        var principals2 = new HashSet<SecurityIdentifier>
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
        policy.Connect("SystemName");

        Assert.Equal(new[] { PrincipalSid1, PrincipalSid2 }, policy.LsaEnumerateAccountsWithUserRight().OrderBy(p => p));
        Assert.Equal(new[] { Privilege1, Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid1));
        Assert.Equal(new[] { Privilege1, Privilege2 }, policy.LsaEnumerateAccountRights(PrincipalSid2));

        var manager = this.ServiceProvider.GetRequiredService<IUserRightsManager>();
        var userRights = manager.GetUserRights(policy).ToArray();

        Assert.Equal(expected, userRights, new UserRightEntryEqualityComparer());

        using var stream = new MemoryStream();
        await userRights.ToJson(stream).ConfigureAwait(false);
        stream.Position = 0;
        using var reader = new StreamReader(stream, Encoding.UTF8);
        var serialized = await reader.ReadToEndAsync().ConfigureAwait(false);

        var actual = JsonSerializer.Deserialize<UserRightEntry[]>(serialized)
            ?.OrderBy(p => p.Privilege, StringComparer.OrdinalIgnoreCase)
            .ThenBy(p => p.SecurityId, StringComparer.OrdinalIgnoreCase)
            .ToArray() ?? Array.Empty<UserRightEntry>();

        Assert.Equal(expected, actual, new UserRightEntryEqualityComparer());
    }
}