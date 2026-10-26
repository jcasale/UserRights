namespace UserRights.Tests.Extensions;

using UserRights.Extensions.Security;

using static UserRights.Tests.TestData;

/// <summary>
/// Represents tests for the security extensions.
/// </summary>
[TestClass]
public class SecurityExtensionsTests
{
    /// <summary>
    /// Verifies an account name translates to a security identifier.
    /// </summary>
    [TestMethod]
    public void ToSecurityIdentifier_WithAccountName_ShouldWork()
    {
        var result = PrincipalName1.ToSecurityIdentifier();

        Assert.AreEqual(PrincipalSid1, result);
    }

    /// <summary>
    /// Verifies a prefixed security identifier is parsed without being translated.
    /// </summary>
    /// <param name="value">The prefixed security identifier.</param>
    /// <param name="expected">The expected security identifier.</param>
    [TestMethod]
    [DataRow("*S-1-5-32-544", "S-1-5-32-544")]
    [DataRow("*s-1-5-32-544", "S-1-5-32-544")]
    [DataRow("*S-1-5-21-1111111111-2222222222-3333333333-9999", "S-1-5-21-1111111111-2222222222-3333333333-9999")]
    public void ToSecurityIdentifier_WithPrefixedSid_ShouldWork(string value, string expected)
    {
        var result = value.ToSecurityIdentifier();

        Assert.AreEqual(new(expected), result);
    }

    /// <summary>
    /// Verifies an invalid prefixed security identifier throws an exception.
    /// </summary>
    /// <param name="value">The invalid prefixed security identifier.</param>
    [TestMethod]
    [DataRow("*")]
    [DataRow("* ")]
    [DataRow("*S-1-bogus")]
    [DataRow("*S-1-")]
    [DataRow("*BA")]
    [DataRow("*BUILTIN\\Administrators")]
    public void ToSecurityIdentifier_WithInvalidPrefixedSid_ThrowsException(string value) =>
        Assert.Throws<SecurityTranslationException>(value.ToSecurityIdentifier);

    /// <summary>
    /// Verifies a security identifier without the prefix is treated as an account name and throws an exception.
    /// </summary>
    [TestMethod]
    public void ToSecurityIdentifier_WithUnprefixedSid_ThrowsException() =>
        Assert.Throws<SecurityTranslationException>(() => "S-1-5-32-544".ToSecurityIdentifier());

    /// <summary>
    /// Verifies an unknown account name throws an exception.
    /// </summary>
    [TestMethod]
    public void ToSecurityIdentifier_WithUnknownAccountName_ThrowsException() =>
        Assert.Throws<SecurityTranslationException>(() => $"{Guid.NewGuid():N}\\{Guid.NewGuid():N}".ToSecurityIdentifier());

    /// <summary>
    /// Verifies an empty or whitespace value throws an exception.
    /// </summary>
    /// <param name="value">The invalid value.</param>
    [TestMethod]
    [DataRow("")]
    [DataRow(" ")]
    public void ToSecurityIdentifier_WithEmptyValue_ThrowsException(string value) =>
        Assert.Throws<ArgumentException>(value.ToSecurityIdentifier);

    /// <summary>
    /// Verifies a security identifier without an account throws an exception when translated to an account.
    /// </summary>
    [TestMethod]
    public void ToAccount_WithUnresolvedSid_ThrowsException() =>
        Assert.Throws<SecurityTranslationException>(() => PrincipalSidUnresolved.ToAccount());
}