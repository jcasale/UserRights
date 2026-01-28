namespace UserRights.Application;

using System.Globalization;
using System.Text.RegularExpressions;

/// <summary>
/// Represents validation logic for command options.
/// </summary>
public static class OptionsValidator
{
    /// <summary>
    /// Validates the options for modifying a principal.
    /// </summary>
    /// <param name="principal">The principal to modify.</param>
    /// <param name="grants">The privileges to grant to the principal.</param>
    /// <param name="revocations">The privileges to revoke from the principal.</param>
    /// <param name="revokeAll">Revokes all privileges from the principal.</param>
    /// <param name="revokeOthers">Revokes all privileges from the principal excluding those being granted.</param>
    /// <returns>A sequence of validation error messages.</returns>
    public static IEnumerable<string> ValidatePrincipalOptions(
        string? principal,
        string[]? grants,
        string[]? revocations,
        bool revokeAll,
        bool revokeOthers)
    {
        // Ensure the principal is a valid string.
        if (string.IsNullOrWhiteSpace(principal))
        {
            yield return "The principal cannot be empty or whitespace.";
        }

        // Ensure principal mode is used with at least one of grant, revoke, or revoke all.
        if (grants is not { Length: > 0 } && revocations is not { Length: > 0 } && !revokeAll)
        {
            yield return "At least one of grant, revoke, or revoke all is required.";
        }

        // Ensure the grants are valid strings.
        if (grants?.Any(string.IsNullOrWhiteSpace) is true)
        {
            yield return "The grants cannot contain empty or whitespace values.";
        }

        // Ensure the revocations are valid strings.
        if (revocations?.Any(string.IsNullOrWhiteSpace) is true)
        {
            yield return "The revocations cannot contain empty or whitespace values.";
        }

        // Ensure the grants do not overlap with revocations or contain duplicates.
        var grantsSet = grants?.ToHashSet(StringComparer.InvariantCultureIgnoreCase) ?? [];
        var revocationsSet = revocations?.ToHashSet(StringComparer.InvariantCultureIgnoreCase) ?? [];

        if (grantsSet.Overlaps(revocationsSet))
        {
            yield return "The grants and revocations cannot overlap.";
        }

        if (grants is not null && grants.Length != grantsSet.Count)
        {
            yield return "The grants cannot contain duplicates.";
        }

        if (revocations is not null && revocations.Length != revocationsSet.Count)
        {
            yield return "The revocations cannot contain duplicates.";
        }

        // Ensure revoke all is not used with any other option.
        if (revokeAll && (revokeOthers || grants is { Length: > 0 } || revocations is { Length: > 0 }))
        {
            yield return "The revoke all option cannot be used with any other option.";
        }

        // Ensure revoke others is only used with grant.
        if (revokeOthers && (revokeAll || grants is not { Length: > 0 } || revocations is { Length: > 0 }))
        {
            yield return "The revoke others option is only valid with grants.";
        }
    }

    /// <summary>
    /// Validates the options for modifying a privilege.
    /// </summary>
    /// <param name="privilege">The privilege to modify.</param>
    /// <param name="grants">The principals to grant the privilege to.</param>
    /// <param name="revocations">The principals to revoke the privilege from.</param>
    /// <param name="revokeAll">Revokes all principals from the privilege.</param>
    /// <param name="revokeOthers">Revokes all principals from the privilege excluding those being granted.</param>
    /// <param name="revokePattern">Revokes all principals whose SID matches the regular expression excluding those being granted.</param>
    /// <returns>A sequence of validation error messages.</returns>
    public static IEnumerable<string> ValidatePrivilegeOptions(
        string? privilege,
        string[]? grants,
        string[]? revocations,
        bool revokeAll,
        bool revokeOthers,
        string? revokePattern)
    {
        // Ensure the privilege is a valid string.
        if (string.IsNullOrWhiteSpace(privilege))
        {
            yield return "The privilege cannot be empty or whitespace.";
        }

        // Ensure privilege mode is used with at least one of grant, revoke, revoke all, or revoke pattern.
        if (grants is not { Length: > 0 } && revocations is not { Length: > 0 } && !revokeAll && string.IsNullOrWhiteSpace(revokePattern))
        {
            yield return "At least one of grant, revoke, revoke all, or revoke pattern is required.";
        }

        // Ensure the grants are valid strings.
        if (grants?.Any(string.IsNullOrWhiteSpace) is true)
        {
            yield return "The grants cannot contain empty or whitespace values.";
        }

        // Ensure the revocations are valid strings.
        if (revocations?.Any(string.IsNullOrWhiteSpace) is true)
        {
            yield return "The revocations cannot contain empty or whitespace values.";
        }

        // Ensure the grants do not overlap with revocations or contain duplicates.
        var grantsSet = grants?.ToHashSet(StringComparer.InvariantCultureIgnoreCase) ?? [];
        var revocationsSet = revocations?.ToHashSet(StringComparer.InvariantCultureIgnoreCase) ?? [];

        if (grantsSet.Overlaps(revocationsSet))
        {
            yield return "The grants and revocations cannot overlap.";
        }

        if (grants is not null && grants.Length != grantsSet.Count)
        {
            yield return "The grants cannot contain duplicates.";
        }

        if (revocations is not null && revocations.Length != revocationsSet.Count)
        {
            yield return "The revocations cannot contain duplicates.";
        }

        // Ensure revoke all is not used with any other option.
        if (revokeAll && (grants is { Length: > 0 } || revocations is { Length: > 0 } || revokeOthers || !string.IsNullOrWhiteSpace(revokePattern)))
        {
            yield return "The revoke all option cannot be used with any other option.";
        }

        // Ensure revoke others is only used with grant.
        if (revokeOthers && (grants is not { Length: > 0 } || revocations is { Length: > 0 } || revokeAll || !string.IsNullOrWhiteSpace(revokePattern)))
        {
            yield return "The revoke others option is only valid with grants.";
        }

        // Ensure revoke pattern is not used with revoke, revoke all, or revoke others.
        if (!string.IsNullOrWhiteSpace(revokePattern) && (revocations is { Length: > 0 } || revokeAll || revokeOthers))
        {
            yield return "The revoke pattern option is only valid when used alone or with grants.";
        }

        // Ensure the revoke pattern is a valid regular expression.
        if (!string.IsNullOrWhiteSpace(revokePattern))
        {
            Exception? exception = null;
            try
            {
                _ = new Regex(revokePattern, RegexOptions.None, TimeSpan.FromSeconds(1));
            }
            catch (RegexParseException e)
            {
                exception = e;
            }

            if (exception is not null)
            {
                yield return string.Create(CultureInfo.InvariantCulture, $"The revoke pattern must be a valid regular expression: {exception.Message}");
            }
        }
    }
}