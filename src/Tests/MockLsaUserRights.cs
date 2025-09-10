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
    private readonly IDictionary<string, ICollection<SecurityIdentifier>> _database = new Dictionary<string, ICollection<SecurityIdentifier>>(StringComparer.InvariantCultureIgnoreCase);
    private bool _connected;

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
            _database.Add(kvp.Key, kvp.Value);
        }
    }

    /// <inheritdoc />
    public void Connect(string? systemName = default)
    {
        if (_connected)
        {
            throw new InvalidOperationException("A connection to the policy database already exists.");
        }

        _connected = true;
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

        if (!_connected)
        {
            throw new InvalidOperationException("A connection to the policy database is required.");
        }

        foreach (var userRight in userRights)
        {
            if (_database.TryGetValue(userRight, out var accountSids))
            {
                if (!accountSids.Contains(accountSid))
                {
                    accountSids.Add(accountSid);
                }
            }
            else
            {
                accountSids = [accountSid];

                _database.Add(userRight, accountSids);
            }
        }
    }

    /// <inheritdoc />
    public string[] LsaEnumerateAccountRights(SecurityIdentifier accountSid)
    {
        ArgumentNullException.ThrowIfNull(accountSid);

        if (!_connected)
        {
            throw new InvalidOperationException("A connection to the policy database is required.");
        }

        return _database
            .Where(p => p.Value.Contains(accountSid))
            .Select(p => p.Key)
            .ToArray();
    }

    /// <inheritdoc />
    public SecurityIdentifier[] LsaEnumerateAccountsWithUserRight(string? userRight = default)
    {
        if (!_connected)
        {
            throw new InvalidOperationException("A connection to the policy database is required.");
        }

        if (string.IsNullOrWhiteSpace(userRight))
        {
            return _database.Values.SelectMany(p => p).Distinct().ToArray();
        }

        if (_database.TryGetValue(userRight, out var accountSids))
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

        if (!_connected)
        {
            throw new InvalidOperationException("A connection to the policy database is required.");
        }

        foreach (var userRight in userRights)
        {
            if (_database.TryGetValue(userRight, out var principals) && principals.Contains(accountSid))
            {
                principals.Remove(accountSid);
            }
        }
    }

    /// <summary>
    /// Allow a test to assert the policy database before manipulating it.
    /// </summary>
    public void ResetConnection() => _connected = false;

    /// <inheritdoc/>
    public void Deserialize(IXunitSerializationInfo info)
    {
        ArgumentNullException.ThrowIfNull(info);

        var items = info.GetValue<string[][]>(nameof(_database));
        foreach (var item in items)
        {
            _database.Add(item[0], item[1..].Select(p => new SecurityIdentifier(p)).ToArray());
        }
    }

    /// <inheritdoc/>
    public void Serialize(IXunitSerializationInfo info)
    {
        ArgumentNullException.ThrowIfNull(info);

        // Flatten the map into an array of arrays composed of the principal and their security ids.
        var data = _database.Select(p =>
        {
            string[] items = [p.Key, ..p.Value.Select(x => x.Value)];
            return items;
        }).ToArray();

        info.AddValue(nameof(_database), data);
    }

    /// <inheritdoc/>
    public override string ToString() => $"{string.Join(" | ", _database.Select(p => $"{p.Key}: {string.Join(',', p.Value)}"))}";
}