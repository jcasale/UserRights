namespace UserRights.Application;

using System.Security.Principal;

/// <summary>
/// Represents the interface to the local security authority user right functions.
/// </summary>
public interface IUserRights
{
    /// <summary>
    /// Gets all principals with privileges in the policy database.
    /// </summary>
    /// <returns>All principals with privileges.</returns>
    SecurityIdentifier[] GetPrincipals();

    /// <summary>
    /// Gets all principals with the specified privilege in the policy database.
    /// </summary>
    /// <param name="privilege">The privilege to filter the result set with.</param>
    /// <returns>All principals with specified privilege.</returns>
    SecurityIdentifier[] GetPrincipals(string privilege);

    /// <summary>
    /// Gets the privileges for the specified principal in the policy database.
    /// </summary>
    /// <param name="principal">The security identifier of the principal.</param>
    /// <returns>All privileges for the specified principal.</returns>
    string[] GetPrivileges(SecurityIdentifier principal);

    /// <summary>
    /// Grants a privilege to a principal.
    /// </summary>
    /// <param name="principal">The principal to grant the privilege to.</param>
    /// <param name="privilege">The privilege to grant.</param>
    void GrantPrivilege(SecurityIdentifier principal, string privilege);

    /// <summary>
    /// Revokes a privilege from a principal.
    /// </summary>
    /// <param name="principal">The principal to revoke the privilege from.</param>
    /// <param name="privilege">The privilege to revoke.</param>
    void RevokePrivilege(SecurityIdentifier principal, string privilege);
}