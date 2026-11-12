namespace UserRights.Application;

using CsvHelper;

/// <summary>
/// Represents an entry in the local security database.
/// </summary>
[CsvRecord]
public sealed partial record UserRightEntry
{
    /// <summary>
    /// Initializes a new instance of the <see cref="UserRightEntry"/> class.
    /// </summary>
    /// <param name="privilege">The privilege assigned to the principal.</param>
    /// <param name="securityId">The security id of the principal.</param>
    /// <param name="accountName">The account name of the principal.</param>
    public UserRightEntry(string privilege, string securityId, string? accountName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(privilege);
        ArgumentException.ThrowIfNullOrWhiteSpace(securityId);

        Privilege = privilege;
        SecurityId = securityId;
        AccountName = string.IsNullOrWhiteSpace(accountName) ? null : accountName;
    }

    /// <summary>
    /// Gets the privilege assigned to the principal.
    /// </summary>
    [CsvColumn(nameof(Privilege))]
    public string Privilege { get; }

    /// <summary>
    /// Gets the security id of the principal.
    /// </summary>
    [CsvColumn(nameof(SecurityId))]
    public string SecurityId { get; }

    /// <summary>
    /// Gets the account name of the principal.
    /// </summary>
    /// <remarks>
    /// The account name may be empty if the security identifier cannot be translated, as the account may be unknown locally, or it may have been deleted.
    /// </remarks>
    [CsvColumn(nameof(AccountName))]
    public string? AccountName { get; }
}