namespace Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using UserRights.Application;

/// <summary>
/// Represents a mock <see cref="ILsaUserRights"/> implementation.
/// </summary>
public class MockLsaUserRights : ILsaUserRights
{
    private readonly IDictionary<string, ICollection<SecurityIdentifier>> database;
    private bool connected;

    /// <summary>
    /// Initializes a new instance of the <see cref="MockLsaUserRights"/> class.
    /// </summary>
    public MockLsaUserRights() => this.database = new Dictionary<string, ICollection<SecurityIdentifier>>(StringComparer.InvariantCultureIgnoreCase);

    /// <summary>
    /// Initializes a new instance of the <see cref="MockLsaUserRights"/> class.
    /// </summary>
    /// <param name="database">A map of privilege to assigned principals.</param>
    public MockLsaUserRights(IDictionary<string, ICollection<SecurityIdentifier>> database)
        => this.database = database ?? throw new ArgumentNullException(nameof(database));

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
    public SecurityIdentifier[] GetPrincipals()
    {
        if (!this.connected)
        {
            throw new InvalidOperationException("A connection to the policy database is required.");
        }

        return this.database.Values.SelectMany(p => p).Distinct().ToArray();
    }

    /// <inheritdoc />
    public SecurityIdentifier[] GetPrincipals(string privilege)
    {
        if (string.IsNullOrWhiteSpace(privilege))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(privilege));
        }

        if (!this.connected)
        {
            throw new InvalidOperationException("A connection to the policy database is required.");
        }

        if (this.database.TryGetValue(privilege, out var principals))
        {
            return principals.ToArray();
        }

        return Array.Empty<SecurityIdentifier>();
    }

    /// <inheritdoc />
    public string[] GetPrivileges(SecurityIdentifier principal)
    {
        if (principal is null)
        {
            throw new ArgumentNullException(nameof(principal));
        }

        if (!this.connected)
        {
            throw new InvalidOperationException("A connection to the policy database is required.");
        }

        return this.database
            .Where(p => p.Value.Contains(principal))
            .Select(p => p.Key)
            .ToArray();
    }

    /// <inheritdoc />
    public void GrantPrivilege(SecurityIdentifier principal, string privilege)
    {
        if (principal is null)
        {
            throw new ArgumentNullException(nameof(principal));
        }

        if (string.IsNullOrWhiteSpace(privilege))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(privilege));
        }

        if (!this.connected)
        {
            throw new InvalidOperationException("A connection to the policy database is required.");
        }

        if (this.database.TryGetValue(privilege, out var principals))
        {
            if (!principals.Contains(principal))
            {
                principals.Add(principal);
            }
        }
        else
        {
            principals = new HashSet<SecurityIdentifier>
            {
                principal
            };

            this.database.Add(privilege, principals);
        }
    }

    /// <summary>
    /// Allow a test to assert the policy database before manipulating it.
    /// </summary>
    public void ResetConnection() => this.connected = false;

    /// <inheritdoc />
    public void RevokePrivilege(SecurityIdentifier principal, string privilege)
    {
        if (principal is null)
        {
            throw new ArgumentNullException(nameof(principal));
        }

        if (string.IsNullOrWhiteSpace(privilege))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(privilege));
        }

        if (!this.connected)
        {
            throw new InvalidOperationException("A connection to the policy database is required.");
        }

        if (this.database.TryGetValue(privilege, out var principals) && principals.Contains(principal))
        {
            principals.Remove(principal);
        }
    }
}