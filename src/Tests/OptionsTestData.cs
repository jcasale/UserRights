namespace Tests;

using static TestData;

/// <summary>
/// Represents test data for validation scenarios.
/// </summary>
public static class OptionsTestData
{
    /// <summary>
    /// Gets invalid method arguments for principal option validation.
    /// </summary>
    public static IEnumerable<(string? Principal, string[]? Grants, string[]? Revocations, bool RevokeAll, bool RevokeOthers, string Message)> PrincipalInvalidArgumentData =>
    [
        // Verify null or empty principal.
        (null, [Privilege1], [], false, false, "Null principal should fail."),
        (string.Empty, [Privilege1], [], false, false, "Empty principal should fail."),
        (" ", [Privilege1], [], false, false, "Whitespace principal should fail."),

        // Verify empty or whitespace values in grants.
        (PrincipalName1, [string.Empty], [], false, false, "Empty grant value should fail."),
        (PrincipalName1, [" "], [], false, false, "Whitespace grant value should fail."),

        // Verify empty or whitespace values in revocations.
        (PrincipalName1, [], [string.Empty], false, false, "Empty revocation value should fail."),
        (PrincipalName1, [], [" "], false, false, "Whitespace revocation value should fail."),

        // Verify RevokeAll requirements.
        (PrincipalName1, [Privilege1], [], true, false, "RevokeAll with grants should fail."),
        (PrincipalName1, [], [Privilege1], true, false, "RevokeAll with revocations should fail."),
        (PrincipalName1, [], [], true, true, "RevokeAll with RevokeOthers should fail."),

        // Verify RevokeOthers requirements.
        (PrincipalName1, [Privilege1], [], true, true, "RevokeOthers with RevokeAll should fail."),
        (PrincipalName1, [], [], false, true, "RevokeOthers without grants should fail."),
        (PrincipalName1, [Privilege1], [Privilege2], false, true, "RevokeOthers with revocations should fail."),

        // Verify remaining requirements.
        (PrincipalName1, [], [], false, false, "No action specified should fail."),

        // Verify grant and revocation set restrictions.
        (PrincipalName1, [Privilege1], [Privilege1], false, false, "Overlapping grants and revocations should fail."),
        (PrincipalName1, [Privilege1, Privilege1], [], false, false, "Duplicate grants should fail."),
        (PrincipalName1, [], [Privilege1, Privilege1], false, false, "Duplicate revocations should fail.")
    ];

    /// <summary>
    /// Gets valid method arguments for principal option validation.
    /// </summary>
    public static IEnumerable<(string Principal, string[] Grants, string[] Revocations, bool RevokeAll, bool RevokeOthers, string Message)> PrincipalValidArgumentData =>
    [
        // Grant only.
        (PrincipalName1, [Privilege1], [], false, false, "Single grant should pass."),
        (PrincipalName1, [Privilege1, Privilege2], [], false, false, "Multiple grants should pass."),

        // Revoke only.
        (PrincipalName1, [], [Privilege1], false, false, "Single revoke should pass."),
        (PrincipalName1, [], [Privilege1, Privilege2], false, false, "Multiple revokes should pass."),

        // Grant and revoke (no overlap).
        (PrincipalName1, [Privilege1], [Privilege2], false, false, "Grant and revoke without overlap should pass."),

        // RevokeAll alone.
        (PrincipalName1, [], [], true, false, "RevokeAll alone should pass."),

        // RevokeOthers with grants.
        (PrincipalName1, [Privilege1], [], false, true, "RevokeOthers with grants should pass."),
        (PrincipalName1, [Privilege1, Privilege2], [], false, true, "RevokeOthers with multiple grants should pass.")
    ];

    /// <summary>
    /// Gets invalid method arguments for privilege option validation.
    /// </summary>
    public static IEnumerable<(string? Privilege, string[]? Grants, string[]? Revocations, bool RevokeAll, bool RevokeOthers, string? RevokePattern, string Message)> PrivilegeInvalidArgumentData
    {
        get
        {
            const string pattern = ".*";

            return
            [
                // Verify null or empty privilege.
                (null, [PrincipalName1], [], false, false, null, "Null privilege should fail."),
                (string.Empty, [PrincipalName1], [], false, false, null, "Empty privilege should fail."),
                (" ", [PrincipalName1], [], false, false, null, "Whitespace privilege should fail."),

                // Verify empty or whitespace values in grants.
                (Privilege1, [string.Empty], [], false, false, null, "Empty grant value should fail."),
                (Privilege1, [" "], [], false, false, null, "Whitespace grant value should fail."),

                // Verify empty or whitespace values in revocations.
                (Privilege1, [], [string.Empty], false, false, null, "Empty revocation value should fail."),
                (Privilege1, [], [" "], false, false, null, "Whitespace revocation value should fail."),

                // Verify RevokeAll requirements.
                (Privilege1, [PrincipalName1], [], true, false, null, "RevokeAll with grants should fail."),
                (Privilege1, [], [PrincipalName1], true, false, null, "RevokeAll with revocations should fail."),
                (Privilege1, [], [], true, true, null, "RevokeAll with RevokeOthers should fail."),
                (Privilege1, [], [], true, false, pattern, "RevokeAll with RevokePattern should fail."),

                // Verify RevokeOthers requirements.
                (Privilege1, [], [], false, true, null, "RevokeOthers without grants should fail."),
                (Privilege1, [PrincipalName1], [PrincipalName2], false, true, null, "RevokeOthers with revocations should fail."),
                (Privilege2, [], [], true, true, null, "RevokeOthers with RevokeAll should fail."),
                (Privilege1, [], [], false, true, pattern, "RevokeOthers with RevokePattern should fail."),

                // Verify RevokePattern requirements.
                (Privilege1, [], [PrincipalName1], false, false, pattern, "RevokePattern with revocations should fail."),
                (Privilege2, [], [], true, false, pattern, "RevokePattern with RevokeAll should fail."),
                (Privilege2, [], [], false, true, pattern, "RevokePattern with RevokeOthers should fail."),

                // Verify remaining requirements.
                (Privilege1, [], [], false, false, null, "No action specified should fail."),

                // Verify grant and revocation set restrictions.
                (Privilege1, [PrincipalName1], [PrincipalName1], false, false, null, "Overlapping grants and revocations should fail."),
                (Privilege1, [PrincipalName1, PrincipalName1], [], false, false, null, "Duplicate grants should fail."),
                (Privilege1, [], [PrincipalName1, PrincipalName1], false, false, null, "Duplicate revocations should fail.")
            ];
        }
    }

    /// <summary>
    /// Gets valid method arguments for privilege option validation.
    /// </summary>
    public static IEnumerable<(string Privilege, string[] Grants, string[] Revocations, bool RevokeAll, bool RevokeOthers, string? RevokePattern, string Message)> PrivilegeValidArgumentData =>
    [
        // Grant only.
        (Privilege1, [PrincipalName1], [], false, false, null, "Single grant should pass."),
        (Privilege1, [PrincipalName1, PrincipalName2], [], false, false, null, "Multiple grants should pass."),

        // Revoke only.
        (Privilege1, [], [PrincipalName1], false, false, null, "Single revoke should pass."),
        (Privilege1, [], [PrincipalName1, PrincipalName2], false, false, null, "Multiple revokes should pass."),

        // Grant and revoke (no overlap).
        (Privilege1, [PrincipalName1], [PrincipalName2], false, false, null, "Grant and revoke without overlap should pass."),

        // RevokeAll alone.
        (Privilege1, [], [], true, false, null, "RevokeAll alone should pass."),

        // RevokeOthers with grants.
        (Privilege1, [PrincipalName1], [], false, true, null, "RevokeOthers with grants should pass."),

        // RevokePattern alone.
        (Privilege1, [], [], false, false, "^S-1-5-21", "RevokePattern alone should pass."),

        // RevokePattern with grants.
        (Privilege1, [PrincipalName1], [], false, false, "^S-1-5-21", "RevokePattern with grants should pass.")
    ];
}