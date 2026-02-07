namespace Tests.Application;

using System.Diagnostics;

using UserRights.Application;

using static Tests.ValidateParametersTestData;
using static UserRights.Application.ValidateParameters;

/// <summary>
/// Represents unit tests for the <see cref="ValidateParameters"/> class.
/// </summary>
[TestClass]
public class ValidateParametersTests
{
    /// <summary>
    /// Verifies that validating principal parameters with invalid arguments returns errors.
    /// </summary>
    /// <param name="principal">The principal to validate.</param>
    /// <param name="grants">The privileges to grant.</param>
    /// <param name="revocations">The privileges to revoke.</param>
    /// <param name="revokeAll">Revokes all privileges.</param>
    /// <param name="revokeOthers">Revokes all other privileges.</param>
    /// <param name="message">The test case message.</param>
    [TestMethod]
    [DynamicData(nameof(PrincipalInvalidArgumentData), typeof(ValidateParametersTestData))]
    public void ValidatePrincipalParameters_WithInvalidArguments_ReturnsErrors(
        string? principal,
        string[]? grants,
        string[]? revocations,
        bool revokeAll,
        bool revokeOthers,
        string message)
    {
        // Act.
        var result = ValidatePrincipalParameters(principal, grants, revocations, revokeAll, revokeOthers);

        foreach (var (option, error) in result.Errors)
        {
            Debug.WriteLine($"{option}: {error}");
        }

        // Assert.
        Assert.IsFalse(result.IsValid, message);
        Assert.IsNotEmpty(result.Errors, message);
    }

    /// <summary>
    /// Verifies that validating principal parameters with valid arguments returns no errors.
    /// </summary>
    /// <param name="principal">The principal to validate.</param>
    /// <param name="grants">The privileges to grant.</param>
    /// <param name="revocations">The privileges to revoke.</param>
    /// <param name="revokeAll">Revokes all privileges.</param>
    /// <param name="revokeOthers">Revokes all other privileges.</param>
    /// <param name="message">The test case message.</param>
    [TestMethod]
    [DynamicData(nameof(PrincipalValidArgumentData), typeof(ValidateParametersTestData))]
    public void ValidatePrincipalParameters_WithValidArguments_ReturnsNoErrors(
        string principal,
        string[] grants,
        string[] revocations,
        bool revokeAll,
        bool revokeOthers,
        string message)
    {
        // Act.
        var result = ValidatePrincipalParameters(principal, grants, revocations, revokeAll, revokeOthers);

        foreach (var (option, error) in result.Errors)
        {
            Debug.WriteLine($"{option}: {error}");
        }

        // Assert.
        Assert.IsTrue(result.IsValid, message);
        Assert.IsEmpty(result.Errors, message);
    }

    /// <summary>
    /// Verifies that validating privilege parameters with invalid arguments returns errors.
    /// </summary>
    /// <param name="privilege">The privilege to validate.</param>
    /// <param name="grants">The principals to grant the privilege to.</param>
    /// <param name="revocations">The principals to revoke the privilege from.</param>
    /// <param name="revokeAll">Revokes all principals.</param>
    /// <param name="revokeOthers">Revokes all other principals.</param>
    /// <param name="revokePattern">The revoke pattern string.</param>
    /// <param name="message">The test case message.</param>
    [TestMethod]
    [DynamicData(nameof(PrivilegeInvalidArgumentData), typeof(ValidateParametersTestData))]
    public void ValidatePrivilegeParameters_WithInvalidArguments_ReturnsErrors(
        string? privilege,
        string[]? grants,
        string[]? revocations,
        bool revokeAll,
        bool revokeOthers,
        string? revokePattern,
        string message)
    {
        // Act.
        var result = ValidatePrivilegeParameters(privilege, grants, revocations, revokeAll, revokeOthers, revokePattern);

        foreach (var (option, error) in result.Errors)
        {
            Debug.WriteLine($"{option}: {error}");
        }

        // Assert.
        Assert.IsFalse(result.IsValid, message);
        Assert.IsNotEmpty(result.Errors, message);
    }

    /// <summary>
    /// Verifies that validating privilege parameters with valid arguments returns no errors.
    /// </summary>
    /// <param name="privilege">The privilege to validate.</param>
    /// <param name="grants">The principals to grant the privilege to.</param>
    /// <param name="revocations">The principals to revoke the privilege from.</param>
    /// <param name="revokeAll">Revokes all principals.</param>
    /// <param name="revokeOthers">Revokes all other principals.</param>
    /// <param name="revokePattern">The revoke pattern string.</param>
    /// <param name="message">The test case message.</param>
    [TestMethod]
    [DynamicData(nameof(PrivilegeValidArgumentData), typeof(ValidateParametersTestData))]
    public void ValidatePrivilegeParameters_WithValidArguments_ReturnsNoErrors(
        string privilege,
        string[] grants,
        string[] revocations,
        bool revokeAll,
        bool revokeOthers,
        string? revokePattern,
        string message)
    {
        // Act.
        var result = ValidatePrivilegeParameters(privilege, grants, revocations, revokeAll, revokeOthers, revokePattern);

        foreach (var (option, error) in result.Errors)
        {
            Debug.WriteLine($"{option}: {error}");
        }

        // Assert.
        Assert.IsTrue(result.IsValid, message);
        Assert.IsEmpty(result.Errors, message);
    }
}