namespace Tests.Cli;

using UserRights.Cli;

/// <summary>
/// Represents CLI syntax tests.
/// </summary>
[TestClass]
public class CliSyntaxTests
{
    /// <summary>
    /// Gets invalid method arguments for the list mode CLI syntax tests.
    /// </summary>
    public static IEnumerable<string?[]> ListModeInvalidArgumentData
    {
        get
        {
            // Invalid path value (empty/whitespace), with variations of json and system-name.
            var message = "Expected invalid path value to fail.";
            yield return [message, "list", "--path", string.Empty];
            yield return [message, "list", "--path", " "];
            yield return [message, "list", "--json", "--path", string.Empty];
            yield return [message, "list", "--json", "--path", " "];
            yield return [message, "list", "--path", string.Empty, "--system-name", "host.example.com"];
            yield return [message, "list", "--path", " ", "--system-name", "host.example.com"];
            yield return [message, "list", "--json", "--path", string.Empty, "--system-name", "host.example.com"];
            yield return [message, "list", "--json", "--path", " ", "--system-name", "host.example.com"];
            yield return [message, "list", "-f", string.Empty];
            yield return [message, "list", "-f", " "];
            yield return [message, "list", "-j", "-f", string.Empty];
            yield return [message, "list", "-j", "-f", " "];
            yield return [message, "list", "-f", string.Empty, "-s", "host.example.com"];
            yield return [message, "list", "-f", " ", "-s", "host.example.com"];
            yield return [message, "list", "-j", "-f", string.Empty, "-s", "host.example.com"];
            yield return [message, "list", "-j", "-f", " ", "-s", "host.example.com"];

            // Invalid system-name value (empty/whitespace), with/without json, with valid/absent path.
            message = "Expected invalid system-name value to fail.";
            yield return [message, "list", "--system-name", string.Empty];
            yield return [message, "list", "--system-name", " "];
            yield return [message, "list", "--json", "--system-name", string.Empty];
            yield return [message, "list", "--json", "--system-name", " "];
            yield return [message, "list", "--path", $"{Guid.NewGuid()}.csv", "--system-name", string.Empty];
            yield return [message, "list", "--path", $"{Guid.NewGuid()}.csv", "--system-name", " "];
            yield return [message, "list", "--json", "--path", $"{Guid.NewGuid()}.csv", "--system-name", string.Empty];
            yield return [message, "list", "--json", "--path", $"{Guid.NewGuid()}.csv", "--system-name", " "];
            yield return [message, "list", "-s", string.Empty];
            yield return [message, "list", "-s", " "];
            yield return [message, "list", "-j", "-s", string.Empty];
            yield return [message, "list", "-j", "-s", " "];
            yield return [message, "list", "-f", $"{Guid.NewGuid()}.csv", "-s", string.Empty];
            yield return [message, "list", "-f", $"{Guid.NewGuid()}.csv", "-s", " "];
            yield return [message, "list", "-j", "-f", $"{Guid.NewGuid()}.csv", "-s", string.Empty];
            yield return [message, "list", "-j", "-f", $"{Guid.NewGuid()}.csv", "-s", " "];

            // Both path and system-name invalid simultaneously.
            message = "Expected invalid path and system-name to fail.";
            yield return [message, "list", "--path", string.Empty, "--system-name", string.Empty];
            yield return [message, "list", "--path", string.Empty, "--system-name", " "];
            yield return [message, "list", "--path", " ", "--system-name", string.Empty];
            yield return [message, "list", "--path", " ", "--system-name", " "];
            yield return [message, "list", "--json", "--path", string.Empty, "--system-name", string.Empty];
            yield return [message, "list", "--json", "--path", string.Empty, "--system-name", " "];
            yield return [message, "list", "--json", "--path", " ", "--system-name", string.Empty];
            yield return [message, "list", "--json", "--path", " ", "--system-name", " "];
            yield return [message, "list", "-f", string.Empty, "-s", string.Empty];
            yield return [message, "list", "-f", " ", "-s", " "];
            yield return [message, "list", "-j", "-f", string.Empty, "-s", " "];
            yield return [message, "list", "-j", "-f", " ", "-s", string.Empty];
        }
    }

    /// <summary>
    /// Gets valid method arguments for the list mode CLI syntax tests.
    /// </summary>
    public static IEnumerable<string?[]> ListModeValidArgumentData
    {
        get
        {
            // CSV mode.
            var message = "Expected valid CSV output options to pass.";
            yield return [message, "list"];
            yield return [message, "list", "--path", $"{Guid.NewGuid()}.csv"];
            yield return [message, "list", "-f", $"{Guid.NewGuid()}.csv"];
            yield return [message, "list", "--system-name", "host.example.com"];
            yield return [message, "list", "-s", "host.example.com"];
            yield return [message, "list", "--path", $"{Guid.NewGuid()}.csv", "--system-name", "host.example.com"];
            yield return [message, "list", "-f", $"{Guid.NewGuid()}.csv", "-s", "host.example.com"];

            // JSON mode.
            message = "Expected valid JSON output options to pass.";
            yield return [message, "list", "--json"];
            yield return [message, "list", "-j"];
            yield return [message, "list", "--json", "--path", $"{Guid.NewGuid()}.json"];
            yield return [message, "list", "-j", "-f", $"{Guid.NewGuid()}.json"];
            yield return [message, "list", "--json", "--system-name", "host.example.com"];
            yield return [message, "list", "-j", "-s", "host.example.com"];
            yield return [message, "list", "--json", "--path", $"{Guid.NewGuid()}.json", "--system-name", "host.example.com"];
            yield return [message, "list", "-j", "-f", $"{Guid.NewGuid()}.json", "-s", "host.example.com"];
        }
    }

    /// <summary>
    /// Gets invalid method arguments for the principal mode CLI syntax tests.
    /// </summary>
    public static IEnumerable<string?[]> PrincipalModeInvalidArgumentData
    {
        get
        {
            // Missing required options (no grant/revoke/revoke-all).
            var message = "Expected missing required options (no grant/revoke/revoke-all) to fail.";
            yield return [message, "principal", "DOMAIN\\UserOrGroup"];
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "--dry-run"];
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "--system-name", "host.example.com"];
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "-d", "-s", "host.example.com"];

            // Overlap between grants and revocations.
            message = "Expected overlap between grants and revocations to fail.";
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "--grant", "SeServiceLogonRight", "--revoke", "SeServiceLogonRight"];
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "-g", "SeServiceLogonRight", "-r", "SeServiceLogonRight"];

            // Duplicate grants.
            message = "Expected duplicate grants to fail.";
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "--grant", "SeServiceLogonRight", "--grant", "SeServiceLogonRight"];
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "-g", "SeBatchLogonRight", "-g", "SeBatchLogonRight"];

            // Duplicate revocations.
            message = "Expected duplicate revocations to fail.";
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "--revoke", "SeServiceLogonRight", "--revoke", "SeServiceLogonRight"];
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "-r", "SeBatchLogonRight", "-r", "SeBatchLogonRight"];

            // --revoke-all combined with any other option (disallowed).
            message = "Expected revoke-all combined with any other option to fail.";
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "--revoke-all", "--grant", "SeServiceLogonRight"];
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "--revoke-all", "--revoke", "SeBatchLogonRight"];
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "--revoke-all", "--revoke-others"];
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "-a", "-g", "SeServiceLogonRight"];
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "-a", "-r", "SeBatchLogonRight"];
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "-a", "-o"];

            // Invalid usages of --revoke-others (must be used only with grants, and without revoke/revoke-all).
            message = "Expected invalid usages of revoke-others to fail.";
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "--revoke-others"];
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "--revoke-others", "--revoke", "SeBatchLogonRight"];
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "--revoke-others", "--revoke-all"];
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "-o"];
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "-o", "-r", "SeBatchLogonRight"];
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "-o", "-a"];

            // Empty or whitespace values for --system-name.
            message = "Expected empty or whitespace values for system-name to fail.";
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "--grant", "SeServiceLogonRight", "--system-name", string.Empty];
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "--grant", "SeServiceLogonRight", "--system-name", " "];
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "-g", "SeBatchLogonRight", "-s", string.Empty];
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "-g", "SeBatchLogonRight", "-s", " "];

            // Empty or whitespace values for --grant.
            message = "Expected empty or whitespace values for grant to fail.";
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "--grant", string.Empty];
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "--grant", " "];
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "-g", string.Empty];
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "-g", " "];

            // Empty or whitespace values for --revoke.
            message = "Expected empty or whitespace values for revoke to fail.";
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "--revoke", string.Empty];
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "--revoke", " "];
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "-r", string.Empty];
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "-r", " "];

            // Empty or whitespace principal value.
            message = "Expected empty or whitespace principal value to fail.";
            yield return [message, "principal", string.Empty, "--grant", "SeServiceLogonRight"];
            yield return [message, "principal", " ", "--grant", "SeServiceLogonRight"];
            yield return [message, "principal", string.Empty, "--revoke", "SeBatchLogonRight"];
            yield return [message, "principal", " ", "--revoke", "SeBatchLogonRight"];
            yield return [message, "principal", string.Empty, "--revoke-all"];
            yield return [message, "principal", " ", "--revoke-all"];
        }
    }

    /// <summary>
    /// Gets valid method arguments for the principal mode CLI syntax tests.
    /// </summary>
    public static IEnumerable<string?[]> PrincipalModeValidArgumentData
    {
        get
        {
            // Single grant.
            var message = "Expected single grant to pass.";
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "--grant", "SeServiceLogonRight"];
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "-g", "SeBatchLogonRight"];

            // Multiple grants (no duplicates).
            message = "Expected multiple grants to pass.";
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "--grant", "SeServiceLogonRight", "--grant", "SeBatchLogonRight"];
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "-g", "SeInteractiveLogonRight", "-g", "SeRemoteInteractiveLogonRight"];

            // Single revoke.
            message = "Expected single revoke to pass.";
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "--revoke", "SeServiceLogonRight"];
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "-r", "SeBatchLogonRight"];

            // Multiple revokes (no duplicates).
            message = "Expected multiple revokes to pass.";
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "--revoke", "SeServiceLogonRight", "--revoke", "SeBatchLogonRight"];
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "-r", "SeInteractiveLogonRight", "-r", "SeRemoteInteractiveLogonRight"];

            // Grant(s) plus revoke(s) (no overlaps between sets).
            message = "Expected grant(s) plus revoke(s) to pass.";
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "--grant", "SeServiceLogonRight", "--revoke", "SeBatchLogonRight"];
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "-g", "SeInteractiveLogonRight", "-g", "SeCreateGlobalPrivilege", "-r", "SeRemoteInteractiveLogonRight"];

            // Revoke-all (must be alone with respect to grant/revoke/others options).
            message = "Expected revoke-all to pass.";
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "--revoke-all"];
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "-a"];

            // Revoke-others with grants (and without revoke/revoke-all).
            message = "Expected revoke-others with grants to pass.";
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "--grant", "SeServiceLogonRight", "--revoke-others"];
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "-g", "SeBatchLogonRight", "-g", "SeInteractiveLogonRight", "-o"];

            // Using system-name (non-empty) and/or dry-run.
            message = "Expected a valid system-name and/or dry-run to pass.";
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "--grant", "SeServiceLogonRight", "--system-name", "host.example.com"];
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "--revoke", "SeBatchLogonRight", "--system-name", "host.example.com"];
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "--revoke-all", "--system-name", "host.example.com"];
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "--grant", "SeServiceLogonRight", "--revoke-others", "--dry-run"];
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "-g", "SeInteractiveLogonRight", "-r", "SeRemoteInteractiveLogonRight", "-d", "-s", "host.example.com"];

            // Mixed long/short forms while staying valid.
            message = "Expected mixed long/short form arguments to pass.";
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "-g", "SeServiceLogonRight", "--revoke", "SeBatchLogonRight"];
            yield return [message, "principal", "DOMAIN\\UserOrGroup", "--grant", "SeInteractiveLogonRight", "-o", "--dry-run"];
        }
    }

    /// <summary>
    /// Gets invalid method arguments for the privilege mode CLI syntax tests.
    /// </summary>
    public static IEnumerable<string?[]> PrivilegeModeInvalidArgumentData
    {
        get
        {
            // Missing required option(s): no grant/revoke/revoke-all/revoke-pattern.
            var message = "Expected missing required option(s) to fail.";
            yield return [message, "privilege", "SeServiceLogonRight"];
            yield return [message, "privilege", "SeBatchLogonRight", "--dry-run"];
            yield return [message, "privilege", "SeServiceLogonRight", "--system-name", "host.example.com"];
            yield return [message, "privilege", "SeBatchLogonRight", "-d", "-s", "host.example.com"];

            // Invalid privilege argument (empty or whitespace).
            message = "Expected invalid privilege argument to fail.";
            yield return [message, "privilege", string.Empty, "--grant", "DOMAIN\\UserOrGroup"];
            yield return [message, "privilege", " ", "--revoke", "DOMAIN\\UserOrGroup"];

            // Invalid grant values (empty or whitespace principal).
            message = "Expected invalid grant values to fail.";
            yield return [message, "privilege", "SeServiceLogonRight", "--grant", string.Empty];
            yield return [message, "privilege", "SeServiceLogonRight", "--grant", " "];
            yield return [message, "privilege", "SeBatchLogonRight", "-g", string.Empty];
            yield return [message, "privilege", "SeBatchLogonRight", "-g", " "];

            // Invalid revoke values (empty or whitespace principal).
            message = "Expected invalid revoke values to fail.";
            yield return [message, "privilege", "SeServiceLogonRight", "--revoke", string.Empty];
            yield return [message, "privilege", "SeServiceLogonRight", "--revoke", " "];
            yield return [message, "privilege", "SeBatchLogonRight", "-r", string.Empty];
            yield return [message, "privilege", "SeBatchLogonRight", "-r", " "];

            // Overlap between grants and revocations (same principal in both sets).
            message = "Expected overlap between grants and revocations to fail.";
            yield return [message, "privilege", "SeServiceLogonRight", "--grant", "DOMAIN\\UserOrGroup", "--revoke", "DOMAIN\\UserOrGroup"];
            yield return [message, "privilege", "SeBatchLogonRight", "-g", "DOMAIN\\UserOrGroup", "-r", "DOMAIN\\UserOrGroup"];

            // Duplicate grants.
            message = "Expected duplicate grants to fail.";
            yield return [message, "privilege", "SeServiceLogonRight", "--grant", "DOMAIN\\UserOrGroup", "--grant", "DOMAIN\\UserOrGroup"];
            yield return [message, "privilege", "SeBatchLogonRight", "-g", "DOMAIN\\UserOrGroup", "-g", "DOMAIN\\UserOrGroup"];

            // Duplicate revocations.
            message = "Expected duplicate revocations to fail.";
            yield return [message, "privilege", "SeServiceLogonRight", "--revoke", "DOMAIN\\UserOrGroup", "--revoke", "DOMAIN\\UserOrGroup"];
            yield return [message, "privilege", "SeBatchLogonRight", "-r", "DOMAIN\\UserOrGroup", "-r", "DOMAIN\\UserOrGroup"];

            // Invalid usages of --revoke-all.
            message = "Expected invalid usages of revoke-all to fail.";
            yield return [message, "privilege", "SeServiceLogonRight", "--revoke-all", "--grant", "DOMAIN\\UserOrGroup"];
            yield return [message, "privilege", "SeServiceLogonRight", "--revoke-all", "--revoke", "DOMAIN\\UserOrGroup"];
            yield return [message, "privilege", "SeBatchLogonRight", "--revoke-all", "--revoke-others"];
            yield return [message, "privilege", "SeBatchLogonRight", "--revoke-all", "--revoke-pattern", ".*"];
            yield return [message, "privilege", "SeBatchLogonRight", "-a", "-g", "DOMAIN\\UserOrGroup"];
            yield return [message, "privilege", "SeBatchLogonRight", "-a", "-r", "DOMAIN\\UserOrGroup"];
            yield return [message, "privilege", "SeBatchLogonRight", "-a", "-o"];
            yield return [message, "privilege", "SeBatchLogonRight", "-a", "-t", ".*"];

            // Invalid usages of --revoke-others.
            message = "Expected invalid usages of revoke-others to fail.";
            yield return [message, "privilege", "SeServiceLogonRight", "--revoke-others"];
            yield return [message, "privilege", "SeServiceLogonRight", "--revoke-others", "--revoke", "DOMAIN\\UserOrGroup"];
            yield return [message, "privilege", "SeServiceLogonRight", "--revoke-others", "--revoke-all"];
            yield return [message, "privilege", "SeServiceLogonRight", "--revoke-others", "--revoke-pattern", ".*"];
            yield return [message, "privilege", "SeBatchLogonRight", "-o"];
            yield return [message, "privilege", "SeBatchLogonRight", "-o", "-r", "DOMAIN\\UserOrGroup"];
            yield return [message, "privilege", "SeBatchLogonRight", "-o", "-a"];
            yield return [message, "privilege", "SeBatchLogonRight", "-o", "-t", ".*"];

            // Invalid usages of --revoke-pattern.
            message = "Expected invalid usages of revoke-pattern to fail.";
            yield return [message, "privilege", "SeServiceLogonRight", "--revoke-pattern", string.Empty];
            yield return [message, "privilege", "SeServiceLogonRight", "--revoke-pattern", " "];
            yield return [message, "privilege", "SeBatchLogonRight", "-t", string.Empty];
            yield return [message, "privilege", "SeBatchLogonRight", "-t", " "];
            yield return [message, "privilege", "SeServiceLogonRight", "--revoke-pattern", "["];
            yield return [message, "privilege", "SeBatchLogonRight", "-t", "(?<unclosed"];

            // Invalid combinations.
            message = "Expected invalid combinations to fail.";
            yield return [message, "privilege", "SeServiceLogonRight", "--revoke-all", "--grant", "DOMAIN\\UserOrGroup"];
            yield return [message, "privilege", "SeServiceLogonRight", "--revoke", "DOMAIN\\UserOrGroup", "--revoke-pattern", ".*"];
            yield return [message, "privilege", "SeServiceLogonRight", "--revoke-all", "--revoke-pattern", ".*"];
            yield return [message, "privilege", "SeServiceLogonRight", "--revoke-others", "--revoke-pattern", ".*"];
            yield return [message, "privilege", "SeBatchLogonRight", "-r", "DOMAIN\\UserOrGroup", "-t", ".*"];
            yield return [message, "privilege", "SeBatchLogonRight", "-a", "-t", ".*"];
            yield return [message, "privilege", "SeBatchLogonRight", "-o", "-t", ".*"];

            // Invalid --system-name values (empty or whitespace).
            message = "Expected invalid system-name values to fail.";
            yield return [message, "privilege", "SeServiceLogonRight", "--grant", "DOMAIN\\UserOrGroup", "--system-name", string.Empty];
            yield return [message, "privilege", "SeServiceLogonRight", "--grant", "DOMAIN\\UserOrGroup", "--system-name", " "];
            yield return [message, "privilege", "SeBatchLogonRight", "-r", "DOMAIN\\UserOrGroup", "-s", string.Empty];
            yield return [message, "privilege", "SeBatchLogonRight", "-r", "DOMAIN\\UserOrGroup", "-s", " "];
            yield return [message, "privilege", "SeServiceLogonRight", "--revoke-pattern", ".*", "--system-name", string.Empty];
            yield return [message, "privilege", "SeServiceLogonRight", "--revoke-pattern", ".*", "--system-name", " "];
        }
    }

    /// <summary>
    /// Gets valid method arguments for the privilege mode CLI syntax tests.
    /// </summary>
    public static IEnumerable<string?[]> PrivilegeModeValidArgumentData
    {
        get
        {
            // Grant only.
            var message = "Expected grant only to pass.";
            yield return [message, "privilege", "SeServiceLogonRight", "--grant", "DOMAIN\\UserOrGroup"];
            yield return [message, "privilege", "SeBatchLogonRight", "-g", "DOMAIN\\UserOrGroup"];
            yield return [message, "privilege", "SeServiceLogonRight", "--grant", "DOMAIN\\UserOrGroup", "--dry-run"];
            yield return [message, "privilege", "SeServiceLogonRight", "--grant", "DOMAIN\\UserOrGroup", "--system-name", "host.example.com"];
            yield return [message, "privilege", "SeBatchLogonRight", "-g", "DOMAIN\\UserOrGroup", "-d", "-s", "host.example.com"];

            // Revoke only.
            message = "Expected revoke only to pass.";
            yield return [message, "privilege", "SeServiceLogonRight", "--revoke", "DOMAIN\\UserOrGroup"];
            yield return [message, "privilege", "SeBatchLogonRight", "-r", "DOMAIN\\UserOrGroup"];
            yield return [message, "privilege", "SeServiceLogonRight", "--revoke", "DOMAIN\\UserOrGroup", "--dry-run"];
            yield return [message, "privilege", "SeServiceLogonRight", "--revoke", "DOMAIN\\UserOrGroup", "--system-name", "host.example.com"];
            yield return [message, "privilege", "SeBatchLogonRight", "-r", "DOMAIN\\UserOrGroup", "-d", "-s", "host.example.com"];

            // Grant(s) and revoke(s) without overlap.
            message = "Expected grant(s) and revoke(s) without overlap to pass.";
            yield return [message, "privilege", "SeServiceLogonRight", "--grant", "DOMAIN\\UserOrGroupA", "--revoke", "DOMAIN\\UserOrGroupB"];
            yield return [message, "privilege", "SeBatchLogonRight", "-g", "DOMAIN\\UserOrGroupA", "--revoke", "DOMAIN\\UserOrGroupB", "--dry-run", "--system-name", "host.example.com"];

            // Revoke-all (cannot mix with grants/revokes/others/pattern).
            message = "Expected revoke-all to pass.";
            yield return [message, "privilege", "SeServiceLogonRight", "--revoke-all"];
            yield return [message, "privilege", "SeBatchLogonRight", "-a"];
            yield return [message, "privilege", "SeServiceLogonRight", "--revoke-all", "--dry-run"];
            yield return [message, "privilege", "SeServiceLogonRight", "--revoke-all", "--system-name", "host.example.com"];
            yield return [message, "privilege", "SeBatchLogonRight", "-a", "-d", "-s", "host.example.com"];

            // Revoke-others with grants (no revoke/revoke-all/revoke-pattern).
            message = "Expected revoke-others with grants to pass.";
            yield return [message, "privilege", "SeServiceLogonRight", "--grant", "DOMAIN\\UserOrGroup", "--revoke-others"];
            yield return [message, "privilege", "SeBatchLogonRight", "-g", "DOMAIN\\UserOrGroup", "-o"];
            yield return [message, "privilege", "SeServiceLogonRight", "--grant", "DOMAIN\\UserOrGroup", "--revoke-others", "--dry-run"];
            yield return [message, "privilege", "SeServiceLogonRight", "--grant", "DOMAIN\\UserOrGroup", "--revoke-others", "--system-name", "host.example.com"];
            yield return [message, "privilege", "SeBatchLogonRight", "-g", "DOMAIN\\UserOrGroup", "-o", "-d", "-s", "host.example.com"];

            // Revoke-pattern alone (valid regex; no revoke/revoke-all/revoke-others).
            message = "Expected revoke-pattern alone to pass.";
            yield return [message, "privilege", "SeServiceLogonRight", "--revoke-pattern", "^S-1-5-21-"];
            yield return [message, "privilege", "SeBatchLogonRight", "-t", "^S-1-5-21-"];
            yield return [message, "privilege", "SeServiceLogonRight", "--revoke-pattern", "^S-1-5-21-", "--dry-run"];
            yield return [message, "privilege", "SeServiceLogonRight", "--revoke-pattern", "^S-1-5-21-", "--system-name", "host.example.com"];
            yield return [message, "privilege", "SeBatchLogonRight", "-t", "^S-1-5-21-", "-d", "-s", "host.example.com"];

            // Revoke-pattern with grants (no revoke/revoke-all/revoke-others).
            message = "Expected revoke-pattern with grants to pass.";
            yield return [message, "privilege", "SeServiceLogonRight", "--grant", "DOMAIN\\UserOrGroup", "--revoke-pattern", "^S-1-5-21-"];
            yield return [message, "privilege", "SeBatchLogonRight", "-g", "DOMAIN\\UserOrGroup", "-t", "^S-1-5-21-"];
            yield return [message, "privilege", "SeServiceLogonRight", "--grant", "DOMAIN\\UserOrGroup", "--revoke-pattern", "^S-1-5-21-", "--dry-run"];
            yield return [message, "privilege", "SeServiceLogonRight", "--grant", "DOMAIN\\UserOrGroup", "--revoke-pattern", "^S-1-5-21-", "--system-name", "host.example.com"];
            yield return [message, "privilege", "SeBatchLogonRight", "-g", "DOMAIN\\UserOrGroup", "-t", "^S-1-5-21-", "-d", "-s", "host.example.com"];
        }
    }

    /// <summary>
    /// Verifies the CLI rejects parsing list mode with invalid arguments.
    /// </summary>
    /// <param name="message">The test failure message.</param>
    /// <param name="args">The test arguments.</param>
    [TestMethod]
    [DynamicData(nameof(ListModeInvalidArgumentData))]
    public void ListMode_WithInvalidArguments_IsRejected(string message, params string[] args)
    {
        // Arrange.
        using var fixture = new CliMockBuilder();

        var rootCommand = fixture.CliBuilder.Build();

        // Act.
        var rc = rootCommand.Parse(args).Run();

        // Assert.
        Assert.AreNotEqual(0, rc, message);
    }

    /// <summary>
    /// Verifies the CLI rejects parsing list mode with invalid arguments.
    /// </summary>
    /// <param name="message">The test failure message.</param>
    /// <param name="args">The test arguments.</param>
    [TestMethod]
    [DynamicData(nameof(ListModeInvalidArgumentData))]
    public void ListMode_WithInvalidArguments_ThrowsException(string message, params string[] args)
    {
        using var fixture = new CliMockBuilder();

        Assert.Throws<SyntaxException>(() => fixture.CliBuilder.Build().Parse(args).ThrowIfInvalid().Run(), message);
    }

    /// <summary>
    /// Verifies the CLI accepts parsing list mode with valid arguments.
    /// </summary>
    /// <param name="message">The test failure message.</param>
    /// <param name="args">The test arguments.</param>
    [TestMethod]
    [DynamicData(nameof(ListModeValidArgumentData))]
    public void ListMode_WithValidArguments_IsAccepted(string message, params string[] args)
    {
        // Arrange.
        using var fixture = new CliMockBuilder();

        var rootCommand = fixture.CliBuilder.Build();

        // Act.
        var rc = rootCommand.Parse(args).ThrowIfInvalid().Run();

        // Assert.
        Assert.AreEqual(0, rc, message);
    }

    /// <summary>
    /// Verifies the CLI rejects parsing principal mode with invalid arguments.
    /// </summary>
    /// <param name="message">The test failure message.</param>
    /// <param name="args">The test arguments.</param>
    [TestMethod]
    [DynamicData(nameof(PrincipalModeInvalidArgumentData))]
    public void PrincipalMode_WithInvalidArguments_IsRejected(string message, params string[] args)
    {
        using var fixture = new CliMockBuilder();

        Assert.Throws<SyntaxException>(() => fixture.CliBuilder.Build().Parse(args).ThrowIfInvalid().Run(), message);
    }

    /// <summary>
    /// Verifies the CLI rejects parsing principal mode with invalid arguments.
    /// </summary>
    /// <param name="message">The test failure message.</param>
    /// <param name="args">The test arguments.</param>
    [TestMethod]
    [DynamicData(nameof(PrincipalModeInvalidArgumentData))]
    public void PrincipalMode_WithInvalidArguments_ThrowsException(string message, params string[] args)
    {
        // Arrange.
        using var fixture = new CliMockBuilder();

        var rootCommand = fixture.CliBuilder.Build();

        // Act.
        var rc = rootCommand.Parse(args).Run();

        // Assert.
        Assert.AreNotEqual(0, rc, message);
    }

    /// <summary>
    /// Verifies the CLI accepts parsing principal mode with valid arguments.
    /// </summary>
    /// <param name="message">The test failure message.</param>
    /// <param name="args">The test arguments.</param>
    [TestMethod]
    [DynamicData(nameof(PrincipalModeValidArgumentData))]
    public void PrincipalMode_WithValidArguments_IsAccepted(string message, params string[] args)
    {
        // Arrange.
        using var fixture = new CliMockBuilder();

        var rootCommand = fixture.CliBuilder.Build();

        // Act.
        var rc = rootCommand.Parse(args).ThrowIfInvalid().Run();

        // Assert.
        Assert.AreEqual(0, rc, message);
    }

    /// <summary>
    /// Verifies the CLI rejects parsing privilege mode with invalid arguments.
    /// </summary>
    /// <param name="message">The test failure message.</param>
    /// <param name="args">The test arguments.</param>
    [TestMethod]
    [DynamicData(nameof(PrivilegeModeInvalidArgumentData))]
    public void PrivilegeMode_WithInvalidArguments_IsRejected(string message, params string[] args)
    {
        using var fixture = new CliMockBuilder();

        Assert.Throws<SyntaxException>(() => fixture.CliBuilder.Build().Parse(args).ThrowIfInvalid().Run(), message);
    }

    /// <summary>
    /// Verifies the CLI rejects parsing privilege mode with invalid arguments.
    /// </summary>
    /// <param name="message">The test failure message.</param>
    /// <param name="args">The test arguments.</param>
    [TestMethod]
    [DynamicData(nameof(PrivilegeModeInvalidArgumentData))]
    public void PrivilegeMode_WithInvalidArguments_ThrowsException(string message, params string[] args)
    {
        // Arrange.
        using var fixture = new CliMockBuilder();

        var rootCommand = fixture.CliBuilder.Build();

        // Act.
        var rc = rootCommand.Parse(args).Run();

        // Assert.
        Assert.AreNotEqual(0, rc, message);
    }

    /// <summary>
    /// Verifies the CLI accepts parsing privilege mode with valid arguments.
    /// </summary>
    /// <param name="message">The test failure message.</param>
    /// <param name="args">The test arguments.</param>
    [TestMethod]
    [DynamicData(nameof(PrivilegeModeValidArgumentData))]
    public void PrivilegeMode_WithValidArguments_IsAccepted(string message, params string[] args)
    {
        // Arrange.
        using var fixture = new CliMockBuilder();

        var rootCommand = fixture.CliBuilder.Build();

        // Act.
        var rc = rootCommand.Parse(args).ThrowIfInvalid().Run();

        // Assert.
        Assert.AreEqual(0, rc, message);
    }
}