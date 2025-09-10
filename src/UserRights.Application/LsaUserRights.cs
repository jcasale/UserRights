namespace UserRights.Application;

using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.Security;
using Windows.Win32.Security.Authentication.Identity;

/// <summary>
/// Represents a managed wrapper around the local security authority user right functions.
/// </summary>
public class LsaUserRights : ILsaUserRights, IDisposable
{
    private bool _disposed;
    private LsaCloseSafeHandle? _handle;

    /// <inheritdoc />
    public void Connect(string? systemName = null)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_handle is not null)
        {
            throw new InvalidOperationException("A connection to the policy database already exists.");
        }

        LSA_OBJECT_ATTRIBUTES objectAttributes = default;

        const uint desiredAccess = PInvoke.POLICY_CREATE_ACCOUNT |
            PInvoke.POLICY_LOOKUP_NAMES |
            PInvoke.POLICY_VIEW_LOCAL_INFORMATION;

        _handle = LsaOpenPolicy(ref objectAttributes, desiredAccess, systemName);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <inheritdoc />
    public unsafe void LsaAddAccountRights(SecurityIdentifier accountSid, params string[] userRights)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_handle is null)
        {
            throw new InvalidOperationException("A connection to the policy database is required.");
        }

        ArgumentNullException.ThrowIfNull(accountSid);
        ArgumentNullException.ThrowIfNull(userRights);

        if (userRights.Length == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(userRights), "Value cannot be an empty collection.");
        }

        var bytes = new byte[accountSid.BinaryLength];
        accountSid.GetBinaryForm(bytes, 0);
        fixed (byte* b = bytes)
        {
            var psid = new PSID(b);
            using var ssid = new LsaCloseSafeHandle(psid);

            Span<LSA_UNICODE_STRING> rights = stackalloc LSA_UNICODE_STRING[userRights.Length];
            for (var i = 0; i < userRights.Length; i++)
            {
                var privilege = userRights[i];

                fixed (char* p = privilege)
                {
                    var length = checked((ushort)(privilege.Length * sizeof(char)));

                    rights[i] = new()
                    {
                        Length = length,
                        MaximumLength = length,
                        Buffer = p
                    };
                }
            }

            var status = PInvoke.LsaAddAccountRights(_handle, ssid, rights);
            var error = PInvoke.LsaNtStatusToWinError(status);

            if ((WIN32_ERROR)error != WIN32_ERROR.ERROR_SUCCESS)
            {
                throw new Win32Exception((int)error);
            }
        }
    }

    /// <inheritdoc />
    public unsafe string[] LsaEnumerateAccountRights(SecurityIdentifier accountSid)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_handle is null)
        {
            throw new InvalidOperationException("A connection to the policy database is required.");
        }

        ArgumentNullException.ThrowIfNull(accountSid);

        var bytes = new byte[accountSid.BinaryLength];
        accountSid.GetBinaryForm(bytes, 0);
        fixed (byte* b = bytes)
        {
            var psid = new PSID(b);
            using var ssid = new LsaCloseSafeHandle(psid);

            LSA_UNICODE_STRING* userRights = null;
            try
            {
                var status = PInvoke.LsaEnumerateAccountRights(_handle, ssid, out userRights, out var count);
                var error = (WIN32_ERROR)PInvoke.LsaNtStatusToWinError(status);

                if (error != WIN32_ERROR.ERROR_SUCCESS)
                {
                    throw new Win32Exception((int)error);
                }

                var results = new string[count];

                for (var i = 0; i < count; i++)
                {
                    var offset = Marshal.SizeOf<LSA_UNICODE_STRING>() * i;
                    var ptr = nint.Add((nint)userRights, offset);
                    var result = Marshal.PtrToStructure<LSA_UNICODE_STRING>(ptr);

                    results[i] = new(result.Buffer.Value);
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
    }

    /// <inheritdoc />
    public unsafe SecurityIdentifier[] LsaEnumerateAccountsWithUserRight(string? userRight = null)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_handle is null)
        {
            throw new InvalidOperationException("A connection to the policy database is required.");
        }

        LSA_UNICODE_STRING userRightUnicode = default;

        if (userRight is null)
        {
            return Method(userRightUnicode);
        }

        fixed (char* c = userRight)
        {
            var length = checked((ushort)(userRight.Length * sizeof(char)));

            userRightUnicode.Length = length;
            userRightUnicode.MaximumLength = length;
            userRightUnicode.Buffer = c;

            return Method(userRightUnicode);
        }

        SecurityIdentifier[] Method(LSA_UNICODE_STRING right)
        {
            void* buffer = null;
            try
            {
                var status = PInvoke.LsaEnumerateAccountsWithUserRight(_handle, right, out buffer, out var count);
                var error = (WIN32_ERROR)PInvoke.LsaNtStatusToWinError(status);

                if (error == WIN32_ERROR.ERROR_NO_MORE_ITEMS)
                {
                    return [];
                }

                if (error != WIN32_ERROR.ERROR_SUCCESS)
                {
                    throw new Win32Exception((int)error);
                }

                var results = new SecurityIdentifier[count];

                for (var i = 0; i < count; i++)
                {
                    var offset = Marshal.SizeOf<LSA_ENUMERATION_INFORMATION>() * i;
                    var result = Marshal.PtrToStructure<LSA_ENUMERATION_INFORMATION>(nint.Add((nint)buffer, offset));
                    var sid = result.Sid;

                    results[i] = new((nint)sid.Value);
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
    }

    /// <inheritdoc />
    public unsafe void LsaRemoveAccountRights(SecurityIdentifier accountSid, params string[] userRights)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_handle is null)
        {
            throw new InvalidOperationException("A connection to the policy database is required.");
        }

        ArgumentNullException.ThrowIfNull(accountSid);
        ArgumentNullException.ThrowIfNull(userRights);

        if (userRights.Length == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(userRights), "Value cannot be an empty collection.");
        }

        var bytes = new byte[accountSid.BinaryLength];
        accountSid.GetBinaryForm(bytes, 0);
        fixed (byte* b = bytes)
        {
            var psid = new PSID(b);
            using var ssid = new LsaCloseSafeHandle(psid);

            Span<LSA_UNICODE_STRING> rights = stackalloc LSA_UNICODE_STRING[userRights.Length];
            for (var i = 0; i < userRights.Length; i++)
            {
                var privilege = userRights[i];

                fixed (char* p = privilege)
                {
                    var length = checked((ushort)(privilege.Length * sizeof(char)));

                    rights[i] = new()
                    {
                        Length = length,
                        MaximumLength = length,
                        Buffer = p
                    };
                }
            }

            var status = PInvoke.LsaRemoveAccountRights(_handle, ssid, false, rights);
            var error = PInvoke.LsaNtStatusToWinError(status);

            if ((WIN32_ERROR)error != WIN32_ERROR.ERROR_SUCCESS)
            {
                throw new Win32Exception((int)error);
            }
        }
    }

    /// <summary>
    /// Releases resources when they are no longer required.
    /// </summary>
    /// <param name="disposing">A value indicating whether the method call comes from a dispose method (its value is <see langword="true"/>) or from a finalizer (its value is <see langword="false"/>).</param>
    protected virtual void Dispose(bool disposing)
    {
        if (_disposed)
        {
            return;
        }

        if (disposing)
        {
            _handle?.Dispose();
            _disposed = true;
        }
    }

    /// <summary>
    /// Opens a handle to the Policy object on a local or remote system.
    /// </summary>
    /// <param name="objectAttributes">The connection attributes.</param>
    /// <param name="desiredAccess">The requested access rights.</param>
    /// <param name="systemName">The name of the target system.</param>
    /// <returns>A handle to the Policy object.</returns>
    private unsafe LsaCloseSafeHandle LsaOpenPolicy(ref LSA_OBJECT_ATTRIBUTES objectAttributes, uint desiredAccess, string? systemName = null)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_handle is not null)
        {
            throw new InvalidOperationException("A connection to the policy database already exists.");
        }

        LSA_UNICODE_STRING systemNameUnicode = default;

        if (systemName is null)
        {
            return Method(systemNameUnicode, ref objectAttributes, desiredAccess);
        }

        fixed (char* c = systemName)
        {
            var length = checked((ushort)(systemName.Length * sizeof(char)));

            systemNameUnicode.Length = length;
            systemNameUnicode.MaximumLength = length;
            systemNameUnicode.Buffer = c;

            return Method(systemNameUnicode, ref objectAttributes, desiredAccess);
        }

        static LsaCloseSafeHandle Method(LSA_UNICODE_STRING name, ref LSA_OBJECT_ATTRIBUTES attributes, uint access)
        {
            var status = PInvoke.LsaOpenPolicy(name, attributes, access, out var policyHandle);
            var error = PInvoke.LsaNtStatusToWinError(status);

            if ((WIN32_ERROR)error != WIN32_ERROR.ERROR_SUCCESS)
            {
                throw new Win32Exception((int)error);
            }

            return policyHandle;
        }
    }
}