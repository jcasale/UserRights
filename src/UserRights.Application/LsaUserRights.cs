namespace UserRights.Application;

using System;
using System.Linq;
using System.Security.Principal;
using Vanara.Extensions;
using Vanara.PInvoke;
using Vanara.Security.AccessControl;
using static Vanara.PInvoke.AdvApi32;

/// <summary>
/// Represents a managed wrapper around the local security authority user right functions.
/// </summary>
public class LsaUserRights : ILsaUserRights, IDisposable
{
    private bool disposed;
    private SafeLSA_HANDLE policy;

    /// <inheritdoc />
    public void Connect(string systemName)
    {
        if (this.disposed)
        {
            throw new ObjectDisposedException(this.GetType().FullName);
        }

        if (this.policy != null)
        {
            throw new InvalidOperationException("A connection to the policy database already exists.");
        }

        try
        {
            this.policy = LsaOpenPolicy(LsaPolicyRights.POLICY_ALL_ACCESS, systemName);
        }
        catch (Exception e)
        {
            throw new LsaUserRightsException("Error opening policy object.", e);
        }
    }

    /// <inheritdoc />
    public SecurityIdentifier[] GetPrincipals()
    {
        if (this.disposed)
        {
            throw new ObjectDisposedException(this.GetType().FullName);
        }

        if (this.policy is null)
        {
            throw new InvalidOperationException("A connection to the policy database is required.");
        }

        return this.GetPrincipalsWithPrivilege(null);
    }

    /// <inheritdoc />
    public SecurityIdentifier[] GetPrincipals(string privilege)
    {
        if (this.disposed)
        {
            throw new ObjectDisposedException(this.GetType().FullName);
        }

        if (this.policy is null)
        {
            throw new InvalidOperationException("A connection to the policy database is required.");
        }

        if (string.IsNullOrWhiteSpace(privilege))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(privilege));
        }

        return this.GetPrincipalsWithPrivilege(privilege);
    }

    /// <inheritdoc />
    public string[] GetPrivileges(SecurityIdentifier principal)
    {
        if (this.disposed)
        {
            throw new ObjectDisposedException(this.GetType().FullName);
        }

        if (this.policy is null)
        {
            throw new InvalidOperationException("A connection to the policy database is required.");
        }

        if (principal is null)
        {
            throw new ArgumentNullException(nameof(principal));
        }

        try
        {
            return LsaEnumerateAccountRights(this.policy, principal.GetPSID()).ToArray();
        }
        catch (Exception e)
        {
            throw new LsaUserRightsException($"Error enumerating privileges for {principal.Value}.", e);
        }
    }

    /// <inheritdoc />
    public void GrantPrivilege(SecurityIdentifier principal, string privilege)
    {
        if (this.disposed)
        {
            throw new ObjectDisposedException(this.GetType().FullName);
        }

        if (this.policy is null)
        {
            throw new InvalidOperationException("A connection to the policy database is required.");
        }

        if (principal is null)
        {
            throw new ArgumentNullException(nameof(principal));
        }

        if (string.IsNullOrWhiteSpace(privilege))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(privilege));
        }

        var privileges = new[] { privilege };

        try
        {
            var status = LsaAddAccountRights(this.policy, principal.GetPSID(), privileges, (uint)privileges.Length);

            LsaNtStatusToWinError(status).ThrowIfFailed();
        }
        catch (Exception e)
        {
            throw new LsaUserRightsException($"Error granting privileges to {principal.Value}.", e);
        }
    }

    /// <inheritdoc />
    public void RevokePrivilege(SecurityIdentifier principal, string privilege)
    {
        if (this.disposed)
        {
            throw new ObjectDisposedException(this.GetType().FullName);
        }

        if (this.policy is null)
        {
            throw new InvalidOperationException("A connection to the policy database is required.");
        }

        if (principal is null)
        {
            throw new ArgumentNullException(nameof(principal));
        }

        if (string.IsNullOrWhiteSpace(privilege))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(privilege));
        }

        var privileges = new[] { privilege };

        try
        {
            var status = LsaRemoveAccountRights(this.policy, principal.GetPSID(), false, privileges, (uint)privileges.Length);

            LsaNtStatusToWinError(status).ThrowIfFailed();
        }
        catch (Exception e)
        {
            throw new LsaUserRightsException($"Error revoking privilege from {principal.Value}.", e);
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        this.Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Releases resources when they are no longer required.
    /// </summary>
    /// <param name="disposing">A value indicating whether the method call comes from a dispose method (its value is <c>true</c>) or from a finalizer (its value is <c>false</c>).</param>
    protected virtual void Dispose(bool disposing)
    {
        if (this.disposed)
        {
            return;
        }

        if (disposing)
        {
            this.policy?.Dispose();
            this.disposed = true;
        }
    }

    /// <summary>
    /// Gets all principals with privileges in the policy database.
    /// </summary>
    /// <param name="privilege">The optional privilege to filter the result set with.</param>
    /// <returns>All principals with privileges.</returns>
    private SecurityIdentifier[] GetPrincipalsWithPrivilege(string privilege)
    {
        if (this.disposed)
        {
            throw new ObjectDisposedException(this.GetType().FullName);
        }

        if (this.policy is null)
        {
            throw new InvalidOperationException("A connection to the policy database is required.");
        }

        // Enumerate all accounts in the policy database.
        SafeLsaMemoryHandle buffer = default;
        try
        {
            var status = LsaEnumerateAccountsWithUserRight(this.policy, privilege, out buffer, out var count);
            if (status == NTStatus.STATUS_NO_MORE_ENTRIES)
            {
                return Array.Empty<SecurityIdentifier>();
            }

            LsaNtStatusToWinError(status).ThrowIfFailed();

            return buffer.DangerousGetHandle()
                .ToIEnum<LSA_ENUMERATION_INFORMATION>(count)
                .Select(a => new SecurityIdentifier((nint)a.Sid))
                .ToArray();
        }
        catch (Exception e)
        {
            throw new LsaUserRightsException("Error enumerating accounts in the policy database.", e);
        }
        finally
        {
            buffer?.Dispose();
        }
    }
}