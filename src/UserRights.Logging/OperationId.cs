namespace UserRights.Logging;

/// <summary>
/// Represents operational Windows event ids.
/// </summary>
public static class OperationId
{
    /// <summary>
    /// Indicates the application is executing in privilege mode.
    /// </summary>
    public const int PrivilegeMode = 1001;

    /// <summary>
    /// Indicates the application is executing in principal mode.
    /// </summary>
    public const int PrincipalMode = 1002;

    /// <summary>
    /// Indicates the application is executing in list mode.
    /// </summary>
    public const int ListMode = 1003;

    /// <summary>
    /// Indicates a privilege was successfully granted.
    /// </summary>
    public const int PrivilegeGrantSuccess = 2001;

    /// <summary>
    /// Indicates a privilege has failed to be granted.
    /// </summary>
    public const int PrivilegeGrantFailure = 2002;

    /// <summary>
    /// Indicates a privilege is being granted in dryrun mode.
    /// </summary>
    public const int PrivilegeGrantDryrun = 2003;

    /// <summary>
    /// Indicates a privilege was successfully revoked.
    /// </summary>
    public const int PrivilegeRevokeSuccess = 3001;

    /// <summary>
    /// Indicates a privilege has failed to be revoked.
    /// </summary>
    public const int PrivilegeRevokeFailure = 3002;

    /// <summary>
    /// Indicates a privilege is being revoked in dryrun mode.
    /// </summary>
    public const int PrivilegeRevokeDryrun = 3003;

    /// <summary>
    /// Indicates a fatal error has occurred.
    /// </summary>
    public const int FatalError = 4001;

    /// <summary>
    /// Indicates a syntax error has occurred.
    /// </summary>
    public const int SyntaxError = 4002;
}