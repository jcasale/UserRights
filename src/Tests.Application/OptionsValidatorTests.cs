namespace Tests.Application;

using System.Diagnostics;

using UserRights.Application;

using static Tests.OptionsTestData;
using static UserRights.Application.OptionsValidator;

/// <summary>
/// Represents unit tests for the <see cref="OptionsValidator"/> class.
/// </summary>
[TestClass]
public class OptionsValidatorTests
{
    /// <summary>
    /// Verifies that validating principal options with invalid arguments returns errors.
    /// </summary>
    /// <param name="principal">The principal to validate.</param>
    /// <param name="grants">The privileges to grant.</param>
    /// <param name="revocations">The privileges to revoke.</param>
    /// <param name="revokeAll">Revokes all privileges.</param>
    /// <param name="revokeOthers">Revokes all other privileges.</param>
    /// <param name="message">The test case message.</param>
    [TestMethod]
    [DynamicData(nameof(PrincipalInvalidArgumentData), typeof(OptionsTestData))]
    public void ValidatePrincipalOptions_WithInvalidArguments_ReturnsErrors(
        string? principal,
        string[]? grants,
        string[]? revocations,
        bool revokeAll,
        bool revokeOthers,
        string message)
    {
        // Act.
        var errors = ValidatePrincipalOptions(principal, grants, revocations, revokeAll, revokeOthers).ToList();

        foreach (var error in errors)
        {
            Debug.WriteLine(error);
        }

        // Assert.
        Assert.IsNotEmpty(errors, message);
    }

    /// <summary>
    /// Verifies that validating principal options with valid arguments returns no errors.
    /// </summary>
    /// <param name="principal">The principal to validate.</param>
    /// <param name="grants">The privileges to grant.</param>
    /// <param name="revocations">The privileges to revoke.</param>
    /// <param name="revokeAll">Revokes all privileges.</param>
    /// <param name="revokeOthers">Revokes all other privileges.</param>
    /// <param name="message">The test case message.</param>
    [TestMethod]
    [DynamicData(nameof(PrincipalValidArgumentData), typeof(OptionsTestData))]
    public void ValidatePrincipalOptions_WithValidArguments_ReturnsNoErrors(
        string principal,
        string[] grants,
        string[] revocations,
        bool revokeAll,
        bool revokeOthers,
        string message)
    {
        // Act.
        var errors = ValidatePrincipalOptions(principal, grants, revocations, revokeAll, revokeOthers).ToList();

        foreach (var error in errors)
        {
            Debug.WriteLine(error);
        }

        // Assert.
        Assert.IsEmpty(errors, message);
    }

    /// <summary>
    /// Verifies that validating privilege options with invalid arguments returns errors.
    /// </summary>
    /// <param name="privilege">The privilege to validate.</param>
    /// <param name="grants">The principals to grant the privilege to.</param>
    /// <param name="revocations">The principals to revoke the privilege from.</param>
    /// <param name="revokeAll">Revokes all principals.</param>
    /// <param name="revokeOthers">Revokes all other principals.</param>
    /// <param name="revokePattern">The revoke pattern string.</param>
    /// <param name="message">The test case message.</param>
    [TestMethod]
    [DynamicData(nameof(PrivilegeInvalidArgumentData), typeof(OptionsTestData))]
    public void ValidatePrivilegeOptions_WithInvalidArguments_ReturnsErrors(
        string? privilege,
        string[]? grants,
        string[]? revocations,
        bool revokeAll,
        bool revokeOthers,
        string? revokePattern,
        string message)
    {
        // Act.
        var errors = ValidatePrivilegeOptions(privilege, grants, revocations, revokeAll, revokeOthers, revokePattern).ToList();

        foreach (var error in errors)
        {
            Debug.WriteLine(error);
        }

        // Assert.
        Assert.IsNotEmpty(errors, message);
    }

    /// <summary>
    /// Verifies that validating privilege options with valid arguments returns no errors.
    /// </summary>
    /// <param name="privilege">The privilege to validate.</param>
    /// <param name="grants">The principals to grant the privilege to.</param>
    /// <param name="revocations">The principals to revoke the privilege from.</param>
    /// <param name="revokeAll">Revokes all principals.</param>
    /// <param name="revokeOthers">Revokes all other principals.</param>
    /// <param name="revokePattern">The revoke pattern string.</param>
    /// <param name="message">The test case message.</param>
    [TestMethod]
    [DynamicData(nameof(PrivilegeValidArgumentData), typeof(OptionsTestData))]
    public void ValidatePrivilegeOptions_WithValidArguments_ReturnsNoErrors(
        string privilege,
        string[] grants,
        string[] revocations,
        bool revokeAll,
        bool revokeOthers,
        string? revokePattern,
        string message)
    {
        // Act.
        var errors = ValidatePrivilegeOptions(privilege, grants, revocations, revokeAll, revokeOthers, revokePattern).ToList();

        foreach (var error in errors)
        {
            Debug.WriteLine(error);
        }

        // Assert.
        Assert.IsEmpty(errors, message);
    }
}