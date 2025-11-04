namespace UserRights.Application;

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
    public UserRightEntry(string privilege, string securityId, string? accountName)
    {
        ArgumentException.ThrowIfNullOrEmpty(privilege);
        ArgumentException.ThrowIfNullOrEmpty(securityId);

        Privilege = privilege;
        SecurityId = securityId;
        AccountName = string.IsNullOrWhiteSpace(accountName) ? null : accountName;
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
    public string? AccountName { get; }

    /// <inheritdoc />
    public virtual bool Equals(UserRightEntry? other)
    {
        if (other is null)
        {
            return false;
        }

        if (ReferenceEquals(this, other))
        {
            return true;
        }

        return string.Equals(Privilege, other.Privilege, StringComparison.Ordinal)
               && string.Equals(SecurityId, other.SecurityId, StringComparison.Ordinal)
               && string.Equals(AccountName, other.AccountName, StringComparison.Ordinal);
    }

    /// <inheritdoc />
    public override int GetHashCode() => HashCode.Combine(Privilege, SecurityId, AccountName);
}