namespace UserRights.Extensions.Security;

using System.Security.Principal;

/// <summary>
/// Represents LSA user right and security extensions.
/// </summary>
public static class SecurityExtensions
{
    /// <summary>
    /// Gets the security identifier (SID) for specified account name.
    /// </summary>
    /// <param name="accountName">The account name to translate.</param>
    /// <returns>The security identifier (SID).</returns>
    public static SecurityIdentifier ToSecurityIdentifier(this string accountName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(accountName);

        try
        {
            var account = new NTAccount(accountName);

            return (SecurityIdentifier)account.Translate(typeof(SecurityIdentifier));
        }
        catch (Exception e)
        {
            throw new SecurityTranslationException($"Error translating account name {accountName} to a security identifier (SID), the account may be unknown on the host.", e);
        }
    }

    /// <summary>
    /// Gets the account for the specified security identifier (SID).
    /// </summary>
    /// <param name="securityIdentifier">The security identifier (SID) to translate.</param>
    /// <returns>The account.</returns>
    public static NTAccount ToAccount(this SecurityIdentifier securityIdentifier)
    {
        ArgumentNullException.ThrowIfNull(securityIdentifier);

        try
        {
            return (NTAccount)securityIdentifier.Translate(typeof(NTAccount));
        }
        catch (Exception e)
        {
            throw new SecurityTranslationException($"Error translating security identifier (SID) {securityIdentifier.Value} to an account name, the SID may be unknown on the host.", e);
        }
    }
}