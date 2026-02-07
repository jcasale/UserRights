namespace UserRights.Application;

using System.Text.RegularExpressions;

/// <summary>
/// Represents validation logic for command parameters.
/// </summary>
public static class ValidateParameters
{
    /// <summary>
    /// Validates the parameters when modifying a principal.
    /// </summary>
    /// <param name="principal">The principal to modify.</param>
    /// <param name="grants">The privileges to grant to the principal.</param>
    /// <param name="revocations">The privileges to revoke from the principal.</param>
    /// <param name="revokeAll">Revokes all privileges from the principal.</param>
    /// <param name="revokeOthers">Revokes all privileges from the principal excluding those being granted.</param>
    /// <returns>
    /// A validation result containing any errors found.
    /// </returns>
    public static ValidationResult ValidatePrincipalParameters(
        string? principal,
        string[]? grants,
        string[]? revocations,
        bool revokeAll,
        bool revokeOthers)
    {
        var errors = new List<ValidationError>();

        // Ensure the principal is a valid string.
        if (string.IsNullOrWhiteSpace(principal))
        {
            errors.Add(new(nameof(principal), "The principal cannot be empty or whitespace."));
        }

        // Ensure principal mode is used with at least one of grant, revoke, or revoke all.
        if (grants is not { Length: > 0 } && revocations is not { Length: > 0 } && !revokeAll)
        {
            errors.Add(new(nameof(principal), "At least one of grant, revoke, or revoke all is required."));
        }

        // Ensure the grants are valid strings.
        if (grants?.Any(string.IsNullOrWhiteSpace) is true)
        {
            errors.Add(new(nameof(grants), "The grants cannot contain empty or whitespace values."));
        }

        // Ensure the revocations are valid strings.
        if (revocations?.Any(string.IsNullOrWhiteSpace) is true)
        {
            errors.Add(new(nameof(revocations), "The revocations cannot contain empty or whitespace values."));
        }

        // Ensure the grants do not overlap with revocations or contain duplicates.
        var grantsSet = grants?.ToHashSet(StringComparer.InvariantCultureIgnoreCase) ?? [];
        var revocationsSet = revocations?.ToHashSet(StringComparer.InvariantCultureIgnoreCase) ?? [];

        if (grantsSet.Overlaps(revocationsSet))
        {
            errors.Add(new(nameof(grants), "The grants and revocations cannot overlap."));
        }

        if (grants is not null && grants.Length != grantsSet.Count)
        {
            errors.Add(new(nameof(grants), "The grants cannot contain duplicates."));
        }

        if (revocations is not null && revocations.Length != revocationsSet.Count)
        {
            errors.Add(new(nameof(revocations), "The revocations cannot contain duplicates."));
        }

        // Ensure revoke all is not used with any other option.
        if (revokeAll && (revokeOthers || grants is { Length: > 0 } || revocations is { Length: > 0 }))
        {
            errors.Add(new(nameof(revokeAll), "The revoke all option cannot be used with any other option."));
        }

        // Ensure revoke others is only used with grant.
        if (revokeOthers && (revokeAll || grants is not { Length: > 0 } || revocations is { Length: > 0 }))
        {
            errors.Add(new(nameof(revokeOthers), "The revoke others option is only valid with grants."));
        }

        return errors.Count == 0 ? ValidationResult.Success : new(errors);
    }

    /// <summary>
    /// Validates the parameters when modifying a privilege.
    /// </summary>
    /// <param name="privilege">The privilege to modify.</param>
    /// <param name="grants">The principals to grant the privilege to.</param>
    /// <param name="revocations">The principals to revoke the privilege from.</param>
    /// <param name="revokeAll">Revokes all principals from the privilege.</param>
    /// <param name="revokeOthers">Revokes all principals from the privilege excluding those being granted.</param>
    /// <param name="revokePattern">Revokes all principals whose SID matches the regular expression pattern excluding those being granted.</param>
    /// <returns>
    /// A validation result containing any errors found.
    /// </returns>
    public static ValidationResult ValidatePrivilegeParameters(
        string? privilege,
        string[]? grants,
        string[]? revocations,
        bool revokeAll,
        bool revokeOthers,
        string? revokePattern)
    {
        var errors = new List<ValidationError>();

        // Ensure the privilege is a valid string.
        if (string.IsNullOrWhiteSpace(privilege))
        {
            errors.Add(new(nameof(privilege), "The privilege cannot be empty or whitespace."));
        }

        // Ensure privilege mode is used with at least one of grant, revoke, revoke all, or revoke pattern.
        if (grants is not { Length: > 0 } && revocations is not { Length: > 0 } && !revokeAll && string.IsNullOrWhiteSpace(revokePattern))
        {
            errors.Add(new(nameof(privilege), "At least one of grant, revoke, revoke all, or revoke pattern is required."));
        }

        // Ensure the grants are valid strings.
        if (grants?.Any(string.IsNullOrWhiteSpace) is true)
        {
            errors.Add(new(nameof(grants), "The grants cannot contain empty or whitespace values."));
        }

        // Ensure the revocations are valid strings.
        if (revocations?.Any(string.IsNullOrWhiteSpace) is true)
        {
            errors.Add(new(nameof(revocations), "The revocations cannot contain empty or whitespace values."));
        }

        // Ensure the grants do not overlap with revocations or contain duplicates.
        var grantsSet = grants?.ToHashSet(StringComparer.InvariantCultureIgnoreCase) ?? [];
        var revocationsSet = revocations?.ToHashSet(StringComparer.InvariantCultureIgnoreCase) ?? [];

        if (grantsSet.Overlaps(revocationsSet))
        {
            errors.Add(new(nameof(grants), "The grants and revocations cannot overlap."));
        }

        if (grants is not null && grants.Length != grantsSet.Count)
        {
            errors.Add(new(nameof(grants), "The grants cannot contain duplicates."));
        }

        if (revocations is not null && revocations.Length != revocationsSet.Count)
        {
            errors.Add(new(nameof(revocations), "The revocations cannot contain duplicates."));
        }

        // Ensure revoke all is not used with any other option.
        if (revokeAll && (grants is { Length: > 0 } || revocations is { Length: > 0 } || revokeOthers || !string.IsNullOrWhiteSpace(revokePattern)))
        {
            errors.Add(new(nameof(revokeAll), "The revoke all option cannot be used with any other option."));
        }

        // Ensure revoke others is only used with grant.
        if (revokeOthers && (grants is not { Length: > 0 } || revocations is { Length: > 0 } || revokeAll || !string.IsNullOrWhiteSpace(revokePattern)))
        {
            errors.Add(new(nameof(revokeOthers), "The revoke others option is only valid with grants."));
        }

        // Ensure revoke pattern is not used with revoke, revoke all, or revoke others.
        if (!string.IsNullOrWhiteSpace(revokePattern) && (revocations is { Length: > 0 } || revokeAll || revokeOthers))
        {
            errors.Add(new(nameof(revokePattern), "The revoke pattern option is only valid when used alone or with grants."));
        }

        // Ensure the revoke pattern is a valid regular expression.
        if (!string.IsNullOrWhiteSpace(revokePattern))
        {
            try
            {
                _ = new Regex(revokePattern, RegexOptions.None, TimeSpan.FromSeconds(1));
            }
            catch (RegexParseException e)
            {
                errors.Add(new(nameof(revokePattern), $"The revoke pattern must be a valid regular expression: {e.Message}"));
            }
        }

        return errors.Count == 0 ? ValidationResult.Success : new(errors);
    }
}