# Convert-STIG2LGPO
Convert-STIG2LGPO is a PowerShell script that automates the tedious process of converting DoD Microsoft STIG Baselines into [LGPO](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/security-compliance-toolkit-10#what-is-the-local-group-policy-object-lgpo-tool) ingestible text files.

> [!IMPORTANT]
> This tool is intended for use on **nondomain-joined systems**. Domain-joined systems, by nature, should receive group policy configurations from Group Policy Objects (GPOs) stored on the system's respective Active Directory Domain Controller.

# To-Do

- Rewrite DELETE/DELETEALLVALUES action logic.

## Windows 11 V2R5 STIG

- `V-253369`: Capture multiple Registry values in one CheckContent string.
- `V-253395`: Capture multiple Registry values in one CheckContent string.

## Microsoft Edge V2R4 STIG

- `V-260467`: Create regex pattern to exclude non-standard double quote characters.