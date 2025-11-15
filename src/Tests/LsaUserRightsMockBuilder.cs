namespace Tests;

using System.Collections.Immutable;
using System.Security.Principal;

using Moq;

using UserRights.Application;

/// <summary>
/// Represents a builder for creating mocks of the <see cref="ILsaUserRights"/> interface for testing purposes.
/// </summary>
public sealed class LsaUserRightsMockBuilder
{
    private readonly Dictionary<SecurityIdentifier, HashSet<string>> _database = [];
    private string? _systemName;

    /// <summary>
    /// Prevents a default instance of the <see cref="LsaUserRightsMockBuilder"/> class from being created.
    /// </summary>
    private LsaUserRightsMockBuilder()
    {
    }

    /// <summary>
    /// Gets an immutable copy of the internal database of user rights assignments.
    /// </summary>
    public ImmutableDictionary<SecurityIdentifier, ImmutableList<string>> Database
        => _database
            .Where(kvp => kvp.Value.Count > 0)
            .ToImmutableDictionary(kvp => kvp.Key, kvp => kvp.Value.ToImmutableList());

    /// <summary>
    /// Creates a new instance of the <see cref="LsaUserRightsMockBuilder"/> class.
    /// </summary>
    /// <returns>An instance of the <see cref="LsaUserRightsMockBuilder"/> class.</returns>
    public static LsaUserRightsMockBuilder CreateBuilder() => new();

    /// <summary>
    /// Builds and returns a mock of the <see cref="ILsaUserRights"/> interface.
    /// </summary>
    /// <returns>A mock instance of <see cref="ILsaUserRights"/> interface.</returns>
    public Mock<ILsaUserRights> Build()
    {
        var mock = new Mock<ILsaUserRights>(MockBehavior.Strict);

        // Configure the mock to handle the Connect(string) method.
        if (string.IsNullOrWhiteSpace(_systemName))
        {
            mock.Setup(x => x.Connect(It.IsAny<string?>()));
        }
        else
        {
            mock.Setup(x => x.Connect(It.Is<string?>(s => string.Equals(s, _systemName, StringComparison.Ordinal))));
        }

        // Configure the mock to handle the LsaAddAccountRights(SecurityIdentifier, string[]) method.
        mock.Setup(x => x.LsaAddAccountRights(It.IsAny<SecurityIdentifier>(), It.IsAny<string[]>())).Callback((SecurityIdentifier accountSid, string[] userRights) =>
        {
            if (_database.TryGetValue(accountSid, out var assignments))
            {
                assignments.UnionWith(userRights);
            }
            else
            {
                _database[accountSid] = new(userRights, StringComparer.OrdinalIgnoreCase);
            }
        });

        // Configure the mock to handle the LsaEnumerateAccountRights(SecurityIdentifier) method.
        mock.Setup(x => x.LsaEnumerateAccountRights(It.IsAny<SecurityIdentifier>())).Returns((SecurityIdentifier accountSid) =>
        {
            if (_database.TryGetValue(accountSid, out var assignments))
            {
                return [.. assignments];
            }

            return [];
        });

        // Configure the mock to handle the LsaEnumerateAccountsWithUserRight(string?) method.
        mock.Setup(x => x.LsaEnumerateAccountsWithUserRight(It.IsAny<string?>())).Returns((string? userRight) =>
        {
            if (string.IsNullOrWhiteSpace(userRight))
            {
                return [.. _database.Keys];
            }

            return [.. _database.Where(kvp => kvp.Value.Contains(userRight)).Select(kvp => kvp.Key)];
        });

        // Configure the mock to handle the LsaRemoveAccountRights(SecurityIdentifier, string[]) method.
        mock.Setup(x => x.LsaRemoveAccountRights(It.IsAny<SecurityIdentifier>(), It.IsAny<string[]>())).Callback((SecurityIdentifier accountSid, string[] userRights) =>
        {
            if (_database.TryGetValue(accountSid, out var assignments))
            {
                assignments.ExceptWith(userRights);
            }
        });

        return mock;
    }

    /// <summary>
    /// Sets the system name to be used for the call to <see cref="ILsaUserRights.Connect(string)"/>.
    /// </summary>
    /// <param name="systemName">The remote system name to execute the task on (default localhost).</param>
    /// <returns>The current instance of <see cref="LsaUserRightsMockBuilder"/> with the updated system name.</returns>
    public LsaUserRightsMockBuilder WithSystemName(string systemName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(systemName);

        _systemName = systemName;

        return this;
    }

    /// <summary>
    /// Adds a principal and associated right to the existing collection of assignments.
    /// </summary>
    /// <param name="accountSid">The principal that should be assigned the rights.</param>
    /// <param name="userRights">The privileges that the principal should possess.</param>
    /// <returns>The current instance of <see cref="LsaUserRightsMockBuilder"/> with the updated system name.</returns>
    public LsaUserRightsMockBuilder WithGrant(SecurityIdentifier accountSid, params string[] userRights)
    {
        ArgumentNullException.ThrowIfNull(accountSid);
        ArgumentNullException.ThrowIfNull(userRights);
        ArgumentOutOfRangeException.ThrowIfZero(userRights.Length, nameof(userRights));

        if (_database.TryGetValue(accountSid, out var assignments))
        {
            assignments.ExceptWith(userRights);
        }
        else
        {
            _database[accountSid] = new(userRights, StringComparer.OrdinalIgnoreCase);
        }

        return this;
    }

    /// <summary>
    /// Adds a principal and associated right to the existing collection of assignments.
    /// </summary>
    /// <param name="entries">The principal and privilege sequence to assign.</param>
    /// <returns>The current instance of <see cref="LsaUserRightsMockBuilder"/> with the updated system name.</returns>
    public LsaUserRightsMockBuilder WithGrant(params UserRightEntry[] entries)
    {
        ArgumentNullException.ThrowIfNull(entries);
        ArgumentOutOfRangeException.ThrowIfZero(entries.Length, nameof(entries));

        foreach (var entry in entries)
        {
            var accountSid = new SecurityIdentifier(entry.SecurityId);
            if (_database.TryGetValue(accountSid, out var assignments))
            {
                assignments.Add(entry.Privilege);
            }
            else
            {
                _database[accountSid] = new(StringComparer.OrdinalIgnoreCase) { entry.Privilege };
            }
        }

        return this;
    }
}