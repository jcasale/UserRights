namespace Tests;

/// <summary>
/// Represents an attribute used to mark a test method that requires elevated privileges.
/// </summary>
public sealed class RunWhenElevatedAttribute : ConditionBaseAttribute
{
    /// <summary>
    /// Initializes a new instance of the <see cref="RunWhenElevatedAttribute"/> class.
    /// </summary>
    /// <param name="ignoreMessage">The ignore message indicating the reason for ignoring the test method or test class.</param>
    public RunWhenElevatedAttribute(string ignoreMessage = "Test requires that the current principal be a member of the Administrators group.")
        : base(ConditionMode.Include) => IgnoreMessage = ignoreMessage;

    /// <inheritdoc />
    public override bool IsConditionMet => GetAdministratorStatus();

    /// <inheritdoc />
    public override string GroupName => "RunWhenElevated";

    /// <summary>
    /// Gets a value indicating whether the current process is running with elevated (administrator) privileges.
    /// </summary>
    /// <returns><see langword="true"/> if the current process is running with elevated (administrator) privileges, otherwise <see langword="false"/>.</returns>
    private static bool GetAdministratorStatus()
    {
        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        var principal = new System.Security.Principal.WindowsPrincipal(identity);

        return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    }
}