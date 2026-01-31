namespace UserRights.Application;

using System.Security.Principal;
using System.Text.RegularExpressions;

using Microsoft.Extensions.Logging;
using UserRights.Extensions.Security;

using static OptionsValidator;
using static UserRights.Logging.OperationId;

/// <summary>
/// Represents the applications logic.
/// </summary>
public class UserRightsManager : IUserRightsManager
{
    private readonly ILogger _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="UserRightsManager"/> class.
    /// </summary>
    /// <param name="logger">The logging instance.</param>
    public UserRightsManager(ILogger<UserRightsManager> logger) => _logger = logger ?? throw new ArgumentNullException(nameof(logger));

    /// <inheritdoc />
    public IEnumerable<IUserRightEntry> GetUserRights(IUserRights policy)
    {
        ArgumentNullException.ThrowIfNull(policy);

        // Enumerate the principals with privileges.
        var principals = policy.LsaEnumerateAccountsWithUserRight();

        // Enumerate the privileges for each principal.
        var entries = new List<UserRightEntry>();
        foreach (var principal in principals)
        {
            string? accountName = null;
            try
            {
                accountName = principal.ToAccount().Value;
            }
            catch (SecurityTranslationException)
            {
                // Account may be unknown locally if querying a remote host, or it may have been deleted.
            }

            var privileges = policy.LsaEnumerateAccountRights(principal);
            foreach (var privilege in privileges)
            {
                var record = new UserRightEntry(privilege, principal.Value, accountName);
                entries.Add(record);
            }
        }

        // Sort the data.
        var sorted = entries
            .OrderBy(p => p.Privilege, StringComparer.OrdinalIgnoreCase)
            .ThenBy(p => p.SecurityId, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return sorted;
    }

    /// <inheritdoc />
    public void ModifyPrincipal(IUserRights policy, string principal, string[] grants, string[] revocations, bool revokeAll, bool revokeOthers, bool dryRun)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentException.ThrowIfNullOrWhiteSpace(principal);
        ArgumentNullException.ThrowIfNull(grants);
        ArgumentNullException.ThrowIfNull(revocations);

        ValidatePrincipalOptions(
            principal,
            message => throw new ArgumentException(message, nameof(principal)),
            grants,
            message => throw new ArgumentException(message, nameof(grants)),
            revocations,
            message => throw new ArgumentException(message, nameof(revocations)),
            revokeAll,
            message => throw new ArgumentException(message, nameof(revokeAll)),
            revokeOthers,
            message => throw new ArgumentException(message, nameof(revokeOthers)));

        // Convert the principal to a security identifier.
        var securityIdentifier = principal.ToSecurityIdentifier();

        // Convert the grants to a set.
        var grantSet = grants.ToHashSet(StringComparer.InvariantCultureIgnoreCase);

        // Convert the revocations to a set.
        var revocationSet = revocations.ToHashSet(StringComparer.InvariantCultureIgnoreCase);

        // Get the privileges currently assigned to the principal.
        var privileges = policy.LsaEnumerateAccountRights(securityIdentifier).ToHashSet(StringComparer.InvariantCultureIgnoreCase);

        // Perform a full revocation of all privileges if required.
        if (revokeAll)
        {
            foreach (var privilege in privileges)
            {
                RevokePrivilege(policy, securityIdentifier, privilege, dryRun);
            }

            // Ignore any further processing.
            return;
        }

        // Determine the deficit grants.
        var deficit = grantSet.Where(p => !privileges.Contains(p));

        // Determine the surplus grants.
        var surplus = revocationSet.Where(privileges.Contains);

        // Perform a revocation of all privileges except those being granted if required.
        if (revokeOthers)
        {
            var others = privileges.Where(p => !grantSet.Contains(p));
            foreach (var privilege in others)
            {
                RevokePrivilege(policy, securityIdentifier, privilege, dryRun);
            }
        }

        // Grant any deficit privileges.
        foreach (var privilege in deficit)
        {
            GrantPrivilege(policy, securityIdentifier, privilege, dryRun);
        }

        // Revoke any surplus privileges.
        foreach (var privilege in surplus)
        {
            RevokePrivilege(policy, securityIdentifier, privilege, dryRun);
        }
    }

    /// <inheritdoc />
    public void ModifyPrivilege(IUserRights policy, string privilege, string[] grants, string[] revocations, bool revokeAll, bool revokeOthers, string? revokePattern, bool dryRun)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentException.ThrowIfNullOrWhiteSpace(privilege);
        ArgumentNullException.ThrowIfNull(grants);
        ArgumentNullException.ThrowIfNull(revocations);

        ValidatePrivilegeOptions(
            privilege,
            message => throw new ArgumentException(message, nameof(privilege)),
            grants,
            message => throw new ArgumentException(message, nameof(grants)),
            revocations,
            message => throw new ArgumentException(message, nameof(revocations)),
            revokeAll,
            message => throw new ArgumentException(message, nameof(revokeAll)),
            revokeOthers,
            message => throw new ArgumentException(message, nameof(revokeOthers)),
            revokePattern,
            message => throw new ArgumentException(message, nameof(revokePattern)));

        // Translate the principal for each grant to a security identifier.
        var grantSet = grants.Select(p => p.ToSecurityIdentifier()).ToHashSet();

        // Translate the principal for each revocation to a security identifier.
        var revocationSet = revocations.Select(p => p.ToSecurityIdentifier()).ToHashSet();

        // Get the principals with the privilege currently assigned.
        var principals = policy.LsaEnumerateAccountsWithUserRight(privilege).ToHashSet();

        // Perform a full revocation of the privilege from each principal if required.
        if (revokeAll)
        {
            foreach (var principal in principals)
            {
                RevokePrivilege(policy, principal, privilege, dryRun);
            }

            // Ignore any further processing.
            return;
        }

        // Determine the deficit grants.
        var deficit = grantSet.Where(p => !principals.Contains(p));

        // Determine the surplus grants.
        var surplus = revocationSet.Where(principals.Contains);

        // Perform a revocation of the privilege from each principal except those being granted if required.
        if (revokeOthers)
        {
            var others = principals.Where(p => !grantSet.Contains(p));
            foreach (var principal in others)
            {
                RevokePrivilege(policy, principal, privilege, dryRun);
            }
        }

        // Perform a revocation of the privilege from each principal matching the regex pattern if required.
        if (revokePattern is not null)
        {
            var regex = new Regex(revokePattern, RegexOptions.None, TimeSpan.FromSeconds(1));
            var matches = principals.Where(p => !grantSet.Contains(p) && regex.IsMatch(p.Value));
            foreach (var principal in matches)
            {
                RevokePrivilege(policy, principal, privilege, dryRun);
            }
        }

        // Grant any deficit principals.
        foreach (var sid in deficit)
        {
            GrantPrivilege(policy, sid, privilege, dryRun);
        }

        // Revoke any surplus principals.
        foreach (var sid in surplus)
        {
            RevokePrivilege(policy, sid, privilege, dryRun);
        }
    }

    /// <summary>
    /// Grants a privilege to a principal.
    /// </summary>
    /// <param name="policy">A connection to the local security authority.</param>
    /// <param name="principal">The principal to grant the privilege to.</param>
    /// <param name="privilege">The privilege to grant.</param>
    /// <param name="dryRun">A value indicating whether to process the action or just instrument it.</param>
    private void GrantPrivilege(IUserRights policy, SecurityIdentifier principal, string privilege, bool dryRun)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentException.ThrowIfNullOrWhiteSpace(privilege);

        if (dryRun)
        {
            _logger.LogInformation(PrivilegeGrantDryrun, "Granting {Privilege:l} to {Principal}.", privilege, principal);

            return;
        }

        try
        {
            policy.LsaAddAccountRights(principal, privilege);
        }
        catch
        {
            _logger.LogError(PrivilegeGrantFailure, "Failed to grant {Privilege:l} to {Principal}.", privilege, principal);

            throw;
        }

        _logger.LogInformation(PrivilegeGrantSuccess, "Successfully granted {Privilege:l} to {Principal}.", privilege, principal);
    }

    /// <summary>
    /// Revokes a privilege from a principal.
    /// </summary>
    /// <param name="policy">A connection to the local security authority.</param>
    /// <param name="principal">The principal to revoke the privilege from.</param>
    /// <param name="privilege">The privilege to revoke.</param>
    /// <param name="dryRun">A value indicating whether to process the action or just instrument it.</param>
    private void RevokePrivilege(IUserRights policy, SecurityIdentifier principal, string privilege, bool dryRun)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentException.ThrowIfNullOrWhiteSpace(privilege);

        if (dryRun)
        {
            _logger.LogInformation(PrivilegeRevokeDryrun, "Revoking {Privilege:l} from {Principal}.", privilege, principal);

            return;
        }

        try
        {
            policy.LsaRemoveAccountRights(principal, privilege);
        }
        catch
        {
            _logger.LogError(PrivilegeRevokeFailure, "Failed to revoke {Privilege:l} from {Principal}.", privilege, principal);

            throw;
        }

        _logger.LogInformation(PrivilegeRevokeSuccess, "Successfully revoked {Privilege:l} from {Principal}.", privilege, principal);
    }
}