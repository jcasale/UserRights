namespace Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;

using UserRights.Application;

using Xunit.Abstractions;

/// <summary>
/// Represents a mock <see cref="ILsaUserRights"/> implementation.
/// </summary>
public sealed class MockLsaUserRights : ILsaUserRights, IUserRightsSerializable
{
    private readonly IDictionary<string, ICollection<SecurityIdentifier>> database = new Dictionary<string, ICollection<SecurityIdentifier>>(StringComparer.InvariantCultureIgnoreCase);
    private bool connected;

    /// <summary>
    /// Initializes a new instance of the <see cref="MockLsaUserRights"/> class.
    /// </summary>
    public MockLsaUserRights()
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="MockLsaUserRights"/> class.
    /// </summary>
    /// <param name="database">A map of privilege to assigned principals.</param>
    public MockLsaUserRights(IDictionary<string, ICollection<SecurityIdentifier>> database)
    {
        ArgumentNullException.ThrowIfNull(database);

        foreach (var kvp in database)
        {
            this.database.Add(kvp.Key, kvp.Value);
        }
    }

    /// <inheritdoc />
    public void Connect(string? systemName = default)
    {
        if (this.connected)
        {
            throw new InvalidOperationException("A connection to the policy database already exists.");
        }

        this.connected = true;
    }

    /// <inheritdoc />
    public void LsaAddAccountRights(SecurityIdentifier accountSid, params string[] userRights)
    {
        ArgumentNullException.ThrowIfNull(accountSid);
        ArgumentNullException.ThrowIfNull(userRights);

        if (userRights.Length == 0)
        {
            throw new ArgumentException("Value cannot be an empty collection.", nameof(userRights));
        }

        if (!this.connected)
        {
            throw new InvalidOperationException("A connection to the policy database is required.");
        }

        foreach (var userRight in userRights)
        {
            if (this.database.TryGetValue(userRight, out var accountSids))
            {
                if (!accountSids.Contains(accountSid))
                {
                    accountSids.Add(accountSid);
                }
            }
            else
            {
                accountSids = [accountSid];

                this.database.Add(userRight, accountSids);
            }
        }
    }

    /// <inheritdoc />
    public string[] LsaEnumerateAccountRights(SecurityIdentifier accountSid)
    {
        ArgumentNullException.ThrowIfNull(accountSid);

        if (!this.connected)
        {
            throw new InvalidOperationException("A connection to the policy database is required.");
        }

        return this.database
            .Where(p => p.Value.Contains(accountSid))
            .Select(p => p.Key)
            .ToArray();
    }

    /// <inheritdoc />
    public SecurityIdentifier[] LsaEnumerateAccountsWithUserRight(string? userRight = default)
    {
        if (!this.connected)
        {
            throw new InvalidOperationException("A connection to the policy database is required.");
        }

        if (string.IsNullOrWhiteSpace(userRight))
        {
            return this.database.Values.SelectMany(p => p).Distinct().ToArray();
        }

        if (this.database.TryGetValue(userRight, out var accountSids))
        {
            return [.. accountSids];
        }

        return [];
    }

    /// <inheritdoc />
    public void LsaRemoveAccountRights(SecurityIdentifier accountSid, params string[] userRights)
    {
        ArgumentNullException.ThrowIfNull(accountSid);
        ArgumentNullException.ThrowIfNull(userRights);

        if (userRights.Length == 0)
        {
            throw new ArgumentException("Value cannot be an empty collection.", nameof(userRights));
        }

        if (!this.connected)
        {
            throw new InvalidOperationException("A connection to the policy database is required.");
        }

        foreach (var userRight in userRights)
        {
            if (this.database.TryGetValue(userRight, out var principals) && principals.Contains(accountSid))
            {
                principals.Remove(accountSid);
            }
        }
    }

    /// <summary>
    /// Allow a test to assert the policy database before manipulating it.
    /// </summary>
    public void ResetConnection() => this.connected = false;

    /// <inheritdoc/>
    public void Deserialize(IXunitSerializationInfo info)
    {
        ArgumentNullException.ThrowIfNull(info);

        var items = info.GetValue<string[][]>(nameof(this.database));
        foreach (var item in items)
        {
            this.database.Add(item[0], item[1..].Select(p => new SecurityIdentifier(p)).ToArray());
        }
    }

    /// <inheritdoc/>
    public void Serialize(IXunitSerializationInfo info)
    {
        ArgumentNullException.ThrowIfNull(info);

        // Flatten the map into an array of arrays composed of the principal and their security ids.
        var data = this.database.Select(p =>
        {
            string[] items = [p.Key, ..p.Value.Select(x => x.Value)];
            return items;
        }).ToArray();

        info.AddValue(nameof(this.database), data);
    }

    /// <inheritdoc/>
    public override string ToString() => $"{string.Join(" | ", this.database.Select(p => $"{p.Key}: {string.Join(',', p.Value)}"))}";
}