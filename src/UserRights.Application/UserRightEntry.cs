namespace UserRights.Application;

using System;

/// <summary>
/// Represents an entry in the local security database.
/// </summary>
public record UserRightEntry : IUserRightEntry
{
    /// <summary>
    /// Initializes a new instance of the <see cref="UserRightEntry"/> class.
    /// </summary>
    /// <param name="privilege">The privilege assigned to the principal.</param>
    /// <param name="securityId">The security id of the principal.</param>
    /// <param name="accountName">The account name of the principal.</param>
    public UserRightEntry(string privilege, string securityId, string accountName)
    {
        if (string.IsNullOrWhiteSpace(privilege))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(privilege));
        }

        if (string.IsNullOrWhiteSpace(securityId))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(securityId));
        }

        this.Privilege = privilege;
        this.SecurityId = securityId;
        this.AccountName = string.IsNullOrWhiteSpace(accountName) ? string.Empty : accountName;
    }

    /// <summary>
    /// Gets the privilege assigned to the principal.
    /// </summary>
    public string Privilege { get; }

    /// <summary>
    /// Gets the security id of the principal.
    /// </summary>
    public string SecurityId { get; }

    /// <summary>
    /// Gets the account name of the principal.
    /// </summary>
    /// <remarks>
    /// The account name may be empty if the query was performed remotely due to the translation possibly not working.
    /// </remarks>
    public string AccountName { get; }
}