namespace UserRights.Application;

using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.Security.Authentication.Identity;
using Windows.Win32.Storage.FileSystem;
using Windows.Win32.System.WindowsProgramming;

/// <summary>
/// Represents a managed wrapper around the local security authority user right functions.
/// </summary>
public class LsaUserRights : ILsaUserRights, IDisposable
{
    private bool disposed;
    private LsaCloseSafeHandle? handle;

    /// <inheritdoc />
    public void Connect(string? systemName = default)
    {
        if (this.disposed)
        {
            throw new ObjectDisposedException(this.GetType().FullName);
        }

        if (this.handle != null)
        {
            throw new InvalidOperationException("A connection to the policy database already exists.");
        }

        OBJECT_ATTRIBUTES objectAttributes = default;

        const uint desiredAccess = (uint)FILE_ACCESS_FLAGS.STANDARD_RIGHTS_REQUIRED |
            PInvoke.POLICY_VIEW_LOCAL_INFORMATION |
            PInvoke.POLICY_VIEW_AUDIT_INFORMATION |
            PInvoke.POLICY_GET_PRIVATE_INFORMATION |
            PInvoke.POLICY_TRUST_ADMIN |
            PInvoke.POLICY_CREATE_ACCOUNT |
            PInvoke.POLICY_CREATE_SECRET |
            PInvoke.POLICY_CREATE_PRIVILEGE |
            PInvoke.POLICY_SET_DEFAULT_QUOTA_LIMITS |
            PInvoke.POLICY_SET_AUDIT_REQUIREMENTS |
            PInvoke.POLICY_AUDIT_LOG_ADMIN |
            PInvoke.POLICY_SERVER_ADMIN |
            PInvoke.POLICY_LOOKUP_NAMES;

        try
        {
            this.handle = this.LsaOpenPolicy(ref objectAttributes, desiredAccess, systemName);
        }
        catch (Exception e)
        {
            throw new LsaUserRightsException("Error opening policy database.", e);
        }
    }

    /// <inheritdoc />
    public SecurityIdentifier[] GetPrincipals()
    {
        if (this.disposed)
        {
            throw new ObjectDisposedException(this.GetType().FullName);
        }

        if (this.handle is null)
        {
            throw new InvalidOperationException("A connection to the policy database is required.");
        }

        try
        {
            return this.LsaEnumerateAccountsWithUserRight();
        }
        catch (Exception e)
        {
            throw new LsaUserRightsException("Error enumerating accounts.", e);
        }
    }

    /// <inheritdoc />
    public SecurityIdentifier[] GetPrincipals(string privilege)
    {
        if (this.disposed)
        {
            throw new ObjectDisposedException(this.GetType().FullName);
        }

        if (this.handle is null)
        {
            throw new InvalidOperationException("A connection to the policy database is required.");
        }

        ArgumentException.ThrowIfNullOrEmpty(privilege);

        try
        {
            return this.LsaEnumerateAccountsWithUserRight(privilege);
        }
        catch (Exception e)
        {
            throw new LsaUserRightsException($"Error enumerating accounts with privilege \"{privilege}\".", e);
        }
    }

    /// <inheritdoc />
    public string[] GetPrivileges(SecurityIdentifier principal)
    {
        if (this.disposed)
        {
            throw new ObjectDisposedException(this.GetType().FullName);
        }

        if (this.handle is null)
        {
            throw new InvalidOperationException("A connection to the policy database is required.");
        }

        ArgumentNullException.ThrowIfNull(principal);

        try
        {
            return this.LsaEnumerateAccountRights(principal);
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

        if (this.handle is null)
        {
            throw new InvalidOperationException("A connection to the policy database is required.");
        }

        ArgumentNullException.ThrowIfNull(principal);
        ArgumentException.ThrowIfNullOrEmpty(privilege);

        var privileges = new[] { privilege };

        try
        {
            this.LsaAddAccountRights(principal, privileges);
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

        if (this.handle is null)
        {
            throw new InvalidOperationException("A connection to the policy database is required.");
        }

        ArgumentNullException.ThrowIfNull(principal);
        ArgumentException.ThrowIfNullOrEmpty(privilege);

        var privileges = new[] { privilege };

        try
        {
            this.LsaRemoveAccountRights(principal, privileges);
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
            this.handle?.Dispose();
            this.disposed = true;
        }
    }

    /// <summary>
    /// Assigns one or more privileges to an account.
    /// </summary>
    /// <param name="securityIdentifier">The SID of the account to which the function assigns privileges.</param>
    /// <param name="privileges">The names of the privileges to be added to the account.</param>
    private unsafe void LsaAddAccountRights(SecurityIdentifier securityIdentifier, string[] privileges)
    {
        if (this.disposed)
        {
            throw new ObjectDisposedException(this.GetType().FullName);
        }

        if (this.handle is null)
        {
            throw new InvalidOperationException("A connection to the policy database is required.");
        }

        ArgumentNullException.ThrowIfNull(securityIdentifier);
        ArgumentNullException.ThrowIfNull(privileges);

        if (privileges.Length == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(privileges), "Value cannot be an empty collection.");
        }

        var bytes = new byte[securityIdentifier.BinaryLength];
        securityIdentifier.GetBinaryForm(bytes, 0);
        PSID accountSid;
        fixed (byte* b = bytes)
        {
            accountSid = new PSID(b);
        }

        Span<UNICODE_STRING> userRights = stackalloc UNICODE_STRING[privileges.Length];
        for (var i = 0; i < privileges.Length; i++)
        {
            var privilege = privileges[i];

            fixed (char* p = privilege)
            {
                var length = checked((ushort)(privilege.Length * sizeof(char)));

                userRights[i] = new UNICODE_STRING
                {
                    Length = length,
                    MaximumLength = length,
                    Buffer = p
                };
            }
        }

        var status = PInvoke.LsaAddAccountRights(this.handle, accountSid, userRights);
        var error = PInvoke.LsaNtStatusToWinError(status);

        if ((WIN32_ERROR)error != WIN32_ERROR.ERROR_SUCCESS)
        {
            throw new Win32Exception((int)error);
        }
    }

    /// <summary>
    /// Gets the privileges assigned to an account.
    /// </summary>
    /// <param name="securityIdentifier">The SID of the account for which to enumerate privileges.</param>
    /// <returns>The names of the assigned privileges.</returns>
    private unsafe string[] LsaEnumerateAccountRights(SecurityIdentifier securityIdentifier)
    {
        if (this.disposed)
        {
            throw new ObjectDisposedException(this.GetType().FullName);
        }

        if (this.handle is null)
        {
            throw new InvalidOperationException("A connection to the policy database is required.");
        }

        ArgumentNullException.ThrowIfNull(securityIdentifier);

        var bytes = new byte[securityIdentifier.BinaryLength];
        securityIdentifier.GetBinaryForm(bytes, 0);
        PSID accountSid;
        fixed (byte* b = bytes)
        {
            accountSid = new PSID(b);
        }

        UNICODE_STRING* userRights = default;
        try
        {
            var status = PInvoke.LsaEnumerateAccountRights(this.handle, accountSid, out userRights, out var count);
            var error = (WIN32_ERROR)PInvoke.LsaNtStatusToWinError(status);

            if (error != WIN32_ERROR.ERROR_SUCCESS)
            {
                throw new Win32Exception((int)error);
            }

            var results = new string[count];

            for (var i = 0; i < count; i++)
            {
                var offset = Marshal.SizeOf(typeof(UNICODE_STRING)) * i;
                var ptr = nint.Add((nint)userRights, offset);
                var result = Marshal.PtrToStructure(ptr, typeof(UNICODE_STRING)) ?? throw new InvalidOperationException();
                var unicodeString = (UNICODE_STRING)result;

                results[i] = new string(unicodeString.Buffer.Value);
            }

            return results;
        }
        finally
        {
            if (userRights is not null)
            {
                PInvoke.LsaFreeMemory(userRights);
            }
        }
    }

    /// <summary>
    /// Gets the accounts in the database of a Local Security Authority (LSA) Policy object that hold a specified privilege.
    /// </summary>
    /// <param name="userRight">The name of a privilege.</param>
    /// <returns>A collection of security identifiers.</returns>
    private unsafe SecurityIdentifier[] LsaEnumerateAccountsWithUserRight(string? userRight = default)
    {
        if (this.disposed)
        {
            throw new ObjectDisposedException(this.GetType().FullName);
        }

        if (this.handle is null)
        {
            throw new InvalidOperationException("A connection to the policy database is required.");
        }

        UNICODE_STRING userRightUnicode = default;
        if (userRight is not null)
        {
            fixed (char* c = userRight)
            {
                var length = checked((ushort)(userRight.Length * sizeof(char)));

                userRightUnicode.Length = length;
                userRightUnicode.MaximumLength = length;
                userRightUnicode.Buffer = c;
            }
        }

        void* buffer = default;
        try
        {
            var status = PInvoke.LsaEnumerateAccountsWithUserRight(this.handle, userRightUnicode, out buffer, out var count);
            var error = (WIN32_ERROR)PInvoke.LsaNtStatusToWinError(status);

            if (error == WIN32_ERROR.ERROR_NO_MORE_ITEMS)
            {
                return Array.Empty<SecurityIdentifier>();
            }

            if (error != WIN32_ERROR.ERROR_SUCCESS)
            {
                throw new Win32Exception((int)error);
            }

            var results = new SecurityIdentifier[count];

            for (var i = 0; i < count; i++)
            {
                var offset = Marshal.SizeOf(typeof(LSA_ENUMERATION_INFORMATION)) * i;
                var result = Marshal.PtrToStructure(nint.Add((nint)buffer, offset), typeof(LSA_ENUMERATION_INFORMATION)) ?? throw new InvalidOperationException();
                var sid = ((LSA_ENUMERATION_INFORMATION)result).Sid;

                results[i] = new SecurityIdentifier((nint)sid.Value);
            }

            return results;
        }
        finally
        {
            if (buffer is not null)
            {
                PInvoke.LsaFreeMemory(buffer);
            }
        }
    }

    /// <summary>
    /// Removes one or more privileges from an account.
    /// </summary>
    /// <param name="securityIdentifier">The security identifier (SID) of the account from which the privileges are removed.</param>
    /// <param name="privileges">The names of the privileges to be removed from the account.</param>
    private unsafe void LsaRemoveAccountRights(SecurityIdentifier securityIdentifier, params string[] privileges)
    {
        if (this.disposed)
        {
            throw new ObjectDisposedException(this.GetType().FullName);
        }

        if (this.handle is null)
        {
            throw new InvalidOperationException("A connection to the policy database is required.");
        }

        ArgumentNullException.ThrowIfNull(securityIdentifier);
        ArgumentNullException.ThrowIfNull(privileges);

        if (privileges.Length == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(privileges), "Value cannot be an empty collection.");
        }

        var bytes = new byte[securityIdentifier.BinaryLength];
        securityIdentifier.GetBinaryForm(bytes, 0);
        PSID accountSid;
        fixed (byte* b = bytes)
        {
            accountSid = new PSID(b);
        }

        Span<UNICODE_STRING> userRights = stackalloc UNICODE_STRING[privileges.Length];
        for (var i = 0; i < privileges.Length; i++)
        {
            var privilege = privileges[i];

            fixed (char* p = privilege)
            {
                var length = checked((ushort)(privilege.Length * sizeof(char)));

                userRights[i] = new UNICODE_STRING
                {
                    Length = length,
                    MaximumLength = length,
                    Buffer = p
                };
            }
        }

        var status = PInvoke.LsaRemoveAccountRights(this.handle, accountSid, false, userRights);
        var error = PInvoke.LsaNtStatusToWinError(status);

        if ((WIN32_ERROR)error != WIN32_ERROR.ERROR_SUCCESS)
        {
            throw new Win32Exception((int)error);
        }
    }

    /// <summary>
    /// Opens a handle to the Policy object on a local or remote system.
    /// </summary>
    /// <param name="objectAttributes">The connection attributes.</param>
    /// <param name="desiredAccess">The requested access rights.</param>
    /// <param name="systemName">The name of the target system.</param>
    /// <returns>A handle to the Policy object.</returns>
    private unsafe LsaCloseSafeHandle LsaOpenPolicy(ref OBJECT_ATTRIBUTES objectAttributes, uint desiredAccess, string? systemName = default)
    {
        if (this.disposed)
        {
            throw new ObjectDisposedException(this.GetType().FullName);
        }

        if (this.handle is not null)
        {
            throw new InvalidOperationException("A connection to the policy database already exists.");
        }

        UNICODE_STRING systemNameUnicode = default;
        if (systemName is not null)
        {
            fixed (char* c = systemName)
            {
                var length = checked((ushort)(systemName.Length * sizeof(char)));

                systemNameUnicode.Length = length;
                systemNameUnicode.MaximumLength = length;
                systemNameUnicode.Buffer = c;
            }
        }

        var status = PInvoke.LsaOpenPolicy(systemNameUnicode, objectAttributes, desiredAccess, out var policyHandle);
        var error = PInvoke.LsaNtStatusToWinError(status);

        if ((WIN32_ERROR)error != WIN32_ERROR.ERROR_SUCCESS)
        {
            throw new Win32Exception((int)error);
        }

        return policyHandle;
    }
}