# Windows User Rights Assignment Utility

The `UserRights.exe` utility is an application for managing the User Rights Assignment security policy settings.

`UserRights.exe` is similar to `ntrights.exe` from the Windows 2003 Resource Kit utility, with additional functionality making it more flexible for use in automation.

## Use Case - Automating User Rights Assignment on Windows Servers

Managing user rights assignment with group policies is not trivial. The interface only allows either exclusively specifying all the principals that will be granted the right, or leaving the user right unmanaged. That is the only reasonable approach, the grants will vary depending on the roles or applications that are installed. There may be virtual accounts (e.g., IIS application pool accounts with security identifiers matching S-1-5-82-&ast;) or NT service accounts (e.g., MSSQL accounts with security identifiers matching S-1-5-80-&ast;) that are granted privileges.

This requires the creation and maintenance of unique and highly specific group policies for each platform and software combination. For example, a typical approach for managing the *SeServiceLogonRight* right might resemble:

1. Create a new group policy object.
1. Add a group policy preference item using *Local Users and Groups* to create a local security group for the permission being managed (e.g., `allow-log-on-service`).
   - Ensure the mode is set to *Update*.
   - Ensure *Delete all member users* is enabled.
   - Ensure *Delete all member groups* is enabled.
   - Enable item level targeting, add an *LDAP Query* and configure it to pass **only** when the LDAP query does **not** return a value indicating the related directory group was not found (e.g., `DOMAIN\allow-log-on-service-%ComputerName%`).
1. Add another group policy preference item using *Local Users and Groups* to create a local security group for the permission being managed (e.g., `allow-log-on-service`).
   - Ensure the mode is set to *Update*.
   - Ensure *Delete all member users* is enabled.
   - Ensure *Delete all member groups* is enabled.
   - Configure a single member by adding the related directory group using the variable based convention (e.g., `DOMAIN\allow-log-on-service-%ComputerName%`).
   - Enable item level targeting, add an *LDAP Query* and configure it to pass **only** when the LDAP query **does** return a value indicating the related directory group was found (e.g., `DOMAIN\allow-log-on-service-%ComputerName%`).
1. Enable the group policy *User Right Assignment* for the *SeServiceLogonRight* right:
   - Add any required local users.
   - Add any required local groups.
   - Add any required virtual accounts.
   - Add any required NT service accounts.
   - Add the new local group created above, `allow-log-on-service`.
1. Link the policy and configure the security and filtering as required.

When the policy executes, the `%ComputerName%` variable will be expanded and the applicable preference will create the local group, and the grants for the user right privilege will be overwritten. If the related directory security group is later provisioned, it will be added to the local group and the user rights will apply. While there is nothing wrong with this approach, it certainly *is* the most secure, but it has fairly high overhead.

An alternative approach without the local groups that uses `UserRights.exe` to grant the required directory group and revoke any inappropriate grants using a pattern is possible.

This example illustrates an approach for managing the *SeServiceLogonRight* right and can be applied to any of the user rights.

1. Copy the `UserRights.exe` utility to a network share that is accessible by all computer accounts.
1. Create an Active Directory security group for the server that should have the *SeServiceLogonRight* right managed. The group name must contain the `sAMAccountName` in addition to any conventions that are required. For example, to manage the *SeServiceLogonRight* privilege for a server named *MyServer*, create a security group named `allow-log-on-service-MyServer` and grant membership to all the required service accounts.
1. Create a group policy object, open it in the editor, and create a new scheduled immediate task:

    ![Alt text](/docs/images/group-policy-editor.png "group-policy-editor")

1. Select the general tab and configure the task:

    ![Alt text](/docs/images/scheduled-task-general.png "scheduled-task-general")

   - Set the task to run in the `NT AUTHORITY\System` context.
   - Set the task to run whether the user is logged in or not.
   - Set the task to run with the highest privileges.
   - Set the task to be hidden in the scheduled task console while it is executing.

1. Select the action tab and configure the task to execute the `UserRights.exe` utility.

    ![Alt text](/docs/images/scheduled-task-action.png "scheduled-task-action")

    - Set the program to the full path to the utility.
      For example: `\\example.com\NETLOGON\UserRights.exe`.
    - Set the arguments to execute the utility in *privilege* mode, grant the *SeServiceLogonRight* privilege to a security group corresponding to the servers `sAMAccountName` value, and remove any other regular user accounts or groups. For example:

        `privilege SeServiceLogonRight --grant EXAMPLE\allow-log-on-service-%ComputerName% --revoke-pattern "^S-1-5-21"`

1. Select the common tab and enable item level targeting.

    ![Alt text](/docs/images/scheduled-task-common.png "scheduled-task-common")

1. Select the targeting button, and configure item level targeting to ensure the preference is only executed when the corresponding Active Directory security exists in the directory.

    ![Alt text](/docs/images/scheduled-task-targeting-editor.png "scheduled-task-targeting-editor")

   - Select *New Item*, then choose *LDAP Query*.
   - Select *Item Options*, then choose *IS*.
   - Set the filter to `(&(objectCategory=group)(name=allow-log-on-service-%ComputerName%))`
   - Set the binding to `LDAP:`
   - Set the attribute to the same type used in the filter `name`

   The example above uses the groups `name` attribute type, which may be a better option than `sAMAccountName` in some environments.
1. Repeat all the above steps with the following changes to accommodate the case when the directory group does not exist:
   - Configure the action to execute the `UserRights.exe` utility with the following arguments:

       `privilege SeServiceLogonRight --revoke-pattern "^S-1-5-21"`

   - Configure item level targeting to enable the preference when the LDAP query does not return a value.

Granting the privilege to a new user or service account only requires granting membership in the associated directory security group. Servers without a corresponding directory security will only have the user right privilege pruned according to the pattern.

If the privilege is later directly granted to a local or domain user account or group, group policy will revoke the grant. The pattern can be extended to prevent well-known security identifiers for built-in non-privileged contexts as well (use the dry-run flag to verify your regular expression).

## Instrumentation

Diagnostic messages are emitted to the console and the Windows application event log.

Events originate from the *UserRights* source and have the following possible ids:

| Event Id | Description                                               |
|:--------:|-----------------------------------------------------------|
|   1001   | Indicates the application is executing in privilege mode. |
|   1002   | Indicates the application is executing in principal mode. |
|   1003   | Indicates the application is executing in list mode.      |
|   2001   | Indicates a privilege was successfully granted.           |
|   2002   | Indicates a privilege has failed to be granted.           |
|   2003   | Indicates a privilege is being granted in dryrun mode.    |
|   3001   | Indicates a privilege was successfully revoked.           |
|   3002   | Indicates a privilege has failed to be revoked.           |
|   3003   | Indicates a privilege is being revoked in dryrun mode.    |
|   4001   | Indicates a fatal error has occurred.                     |
|   4002   | Indicates a syntax error has occurred.                    |

## Examples

### Manage a Principal

- Grant a privilege and revoke a different privilege from a principal:

```bat
UserRights.exe principal "DOMAIN\UserOrGroup" --grant SeServiceLogonRight --revoke SeDenyServiceLogonRight
```

- Grant multiple privileges, and revoke any other privileges assigned to a principal:

```bat
UserRights.exe principal "DOMAIN\UserOrGroup" --grant SeServiceLogonRight --grant SeInteractiveLogonRight --revoke-others
```

- Revoke a privilege from a principal:

```bat
UserRights.exe principal "DOMAIN\UserOrGroup" --revoke SeDenyServiceLogonRight
```

- Revoke all privileges from a principal:

```bat
UserRights.exe principal "DOMAIN\UserOrGroup" --revoke-all
```

### Manage a Privilege

- Assign a principal, and revoke all other principals matching a pattern (everything except builtin and virtual accounts) from a privilege in dryrun mode to only instrument the changes:

```bat
UserRights.exe privilege SeServiceLogonRight --grant "DOMAIN\UserOrGroup" --revoke-pattern "^S-1-5-21-" --dry-run
```

- Revoke all principals matching a pattern (everything except builtin and virtual accounts) from a privilege:

```bat
UserRights.exe privilege SeServiceLogonRight --revoke-pattern "^S-1-5-21-"
```

- Assign a principal and revoke a different principal from a privilege:

```bat
UserRights.exe privilege SeServiceLogonRight --grant "DOMAIN\User" --revoke "DOMAIN\Group"
```

- Revoke a principal assigned to a privilege:

```bat
UserRights.exe privilege SeServiceLogonRight --revoke "DOMAIN\UserOrGroup"
```

- Revoke all principals assigned to a privilege:

```bat
UserRights.exe privilege SeServiceLogonRight --revoke-all
```

### Enumerate Privileges and Principals

- List all principals and privileges in CSV format to `STDOUT`:

```bat
UserRights.exe list
```

- List all principals and privileges in JSON format to `STDOUT`:

```bat
UserRights.exe list --json
```

- List all principals and privileges in CSV format to a file:

```bat
UserRights.exe list --path x:\path\file.csv
```

## Additional Info

Releases are provided in two formats that both target .Net Framework 4.6.2 for the most compatibility:

  * An archive containing the executable and all required libraries.
  * An archive containing a single, packed executable to make deployment simple.
    * This format triggers false positives with antivirus.

## Useful Links

- [User Rights Assignment](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment)
- [Well-Known SID Structures](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/81d92bba-d22b-4a8c-908a-554ab29148ab)
- [Regular Expression Language - Quick Reference](https://docs.microsoft.com/en-us/dotnet/standard/base-types/regular-expression-language-quick-reference)