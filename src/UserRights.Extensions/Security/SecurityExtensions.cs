namespace UserRights.Extensions.Security;

using System.Security.Principal;

/// <summary>
/// Represents LSA user right and security extensions.
/// </summary>
public static class SecurityExtensions
{
    /// <summary>
    /// The prefix that identifies a value as a security identifier (SID) instead of an account name.
    /// </summary>
    private const char SecurityIdentifierPrefix = '*';

    /// <summary>
    /// Gets the security identifier (SID) for specified account name or prefixed SID.
    /// </summary>
    /// <param name="accountName">The account name to translate, or a security identifier (SID) prefixed with an asterisk, for example <c>*S-1-5-32-544</c>.</param>
    /// <returns>The security identifier (SID).</returns>
    /// <exception cref="SecurityTranslationException">Thrown when the value cannot be translated or parsed.</exception>
    public static SecurityIdentifier ToSecurityIdentifier(this string accountName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(accountName);

        if (accountName[0] == SecurityIdentifierPrefix)
        {
            var value = accountName[1..];

            // The SecurityIdentifier constructor also accepts SDDL aliases such as BA, so require the SID string form.
            if (!value.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase))
            {
                throw new SecurityTranslationException($"Error parsing {accountName} as a security identifier (SID), the value after {SecurityIdentifierPrefix} must be a SID such as S-1-5-32-544.");
            }

            try
            {
                return new(value);
            }
            catch (ArgumentException e)
            {
                throw new SecurityTranslationException($"Error parsing {accountName} as a security identifier (SID), the value after {SecurityIdentifierPrefix} is not a valid SID.", e);
            }
        }

        try
        {
            var account = new NTAccount(accountName);

            return (SecurityIdentifier)account.Translate(typeof(SecurityIdentifier));
        }
        catch (Exception e)
        {
            var message = $"Error translating account name {accountName} to a security identifier (SID), the account may be unknown on the host.";

            if (accountName.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase))
            {
                message += $" To specify a security identifier (SID), prefix it with {SecurityIdentifierPrefix}.";
            }

            throw new SecurityTranslationException(message, e);
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