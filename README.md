# Convert-STIG2LGPO
Convert-STIG2LGPO is a PowerShell script that automates the tedious process of converting DoD Microsoft STIG Baselines into [LGPO](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/security-compliance-toolkit-10#what-is-the-local-group-policy-object-lgpo-tool) ingestible text files.

> [!IMPORTANT]
> This script is intended for use on **nondomain-joined systems**. Domain-joined systems, by nature, should receive group policy configurations from Group Policy Objects (GPOs) stored on the system's respective Active Directory Domain Controller.

# To-Do

- Add `-SelfReport` switch parameter to create text w/ benchmark info and identify uncaptured Registry Vuln IDs.
  - As quarterly STIGs are released, new Vuln IDs, which may or may not be Registry-related, are added. A built-in feature to report discrepancies would help both myself and end users identify security gaps to be fixed in future `Convert-STIG2LGPO` releases.

- Rewrite DELETE/DELETEALLVALUES action logic.

## Adobe Reader DC Continuous Track V2R1

- Add regex to handle specific formatting based on benchmark value

## Windows 11 V2R7 STIG

- `V-253369`: Capture multiple Registry values in one CheckContent string.
- `V-253395`: Capture multiple Registry values in one CheckContent string.

## Microsoft Edge V2R5 STIG

- `V-260467`: Create regex pattern to exclude non-standard double quote characters.