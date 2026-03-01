# CIS Microsoft 365 Foundations Benchmark v6.0.0 - Automated Compliance Checker

[![PowerShell Gallery](https://img.shields.io/powershellgallery/v/CIS-M365-Benchmark.svg)](https://www.powershellgallery.com/packages/CIS-M365-Benchmark)
[![PowerShell Gallery Downloads](https://img.shields.io/powershellgallery/dt/CIS-M365-Benchmark.svg)](https://www.powershellgallery.com/packages/CIS-M365-Benchmark)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B%20%7C%207%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CIS Benchmark](https://img.shields.io/badge/CIS%20Benchmark-v6.0.0-orange.svg)](https://www.cisecurity.org/)
[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-Support-yellow.svg)](https://buymeacoffee.com/mohammedsiddiqui)
[![PowerShellNerd Profile](https://img.shields.io/badge/PowerShellNerd-Profile-purple.svg)](https://powershellnerd.com/profile/mohammedsiddiqui)

A comprehensive PowerShell module that audits your Microsoft 365 environment against **all 140 CIS Microsoft 365 Foundations Benchmark v6.0.0 controls** and generates detailed HTML and CSV compliance reports.

## What's New in v4.1.0

**v4.1.0 - Connection Reliability & Diagnostics Release (Issues #13, #14)**
- **Fix: Intune 403 Forbidden errors (Issue #14)** - Added missing `DeviceManagementConfiguration.Read.All` and `DeviceManagementServiceConfig.Read.All` Graph API scopes for checks 4.1, 4.2
- **Fix: 2.1.11 now reports missing file types (Issue #13)** - Instead of generic "Fail", shows which specific attachment types are missing per malware filter policy
- **Fix: 5.2.3.4 permission error guidance** - Detects `AuditLog.Read.All` consent issues and provides admin consent remediation steps
- **Fix: Exchange Online WAM errors** - Uses `-DisableWAM` for reliable authentication across all environments
- **Fix: SharePoint Online auth loop** - Uses `-ModernAuth` for seamless browser-based authentication
- **Fix: Teams 8.2.x federation errors** - Force-loads MicrosoftTeams ConfigAPI submodules to prevent "cmdlet not recognized" errors

**v4.0.0 - Major Code Audit & Bug Fix Release**
- **Critical Fix: XSS vulnerability** - All HTML report output now sanitized via `[System.Net.WebUtility]::HtmlEncode()`
- **Critical Fix: 6.1.2 false failures (Issue #12)** - Now respects `DefaultAuditSet` so mailboxes using Microsoft's default audit actions correctly pass
- **Critical Fix: 1.1.1 false positives** - No longer flags read-only roles (Global Reader, Directory Readers, etc.) as administrative accounts
- **Critical Fix: Intune 4.1 & 4.2** - Now verify actual compliance policy values instead of just checking if objects exist
- **Critical Fix: Password expiration (1.3.1)** - Now requires exactly `2147483647` (never expire) instead of accepting >365 days
- **Critical Fix: 6.2.1 outbound spam** - Iterates all policies instead of treating array as single object
- **Performance: O(n²) array growth eliminated** - Results collection uses `List<T>` instead of `+=`
- **File-based audit logging** - Every check result now logged to timestamped `.log` file alongside reports
- **Null safety** - Fixed null reference on missing Graph scopes, null check order, `.Count` on single objects (PS 5.1)
- **Security hardened** - Removed `-Force -AllowClobber`, removed hardcoded ClientId, environment variable cleanup
- **No more side effects on import** - Dependencies checked at connect time, not module import
- **Sovereign cloud support** - SharePoint URL validation now accepts `.sharepoint.us`, `.sharepoint.de`, `.sharepoint.cn`
- **Get-CISBenchmarkControl** fully populated with all 140 controls
- **Teams connection non-fatal** - If Teams fails to connect, remaining 8 sections still run

**v3.0.5 - Fix False Positive on onmicrosoft.com Domains (Issue #9)**
- DMARC, SPF, and DKIM checks skip `*.onmicrosoft.com` domains managed by Microsoft

## Features

- **140 Compliance Controls** across all M365 services
- **66% Fully Automated** - 92 controls run automatically via Microsoft Graph API
- **Zero-Parameter Authentication** - `Connect-CISBenchmark` for easy setup
- **Dual Report Format** - Professional HTML and CSV reports with floating action buttons
- **Profile-based Filtering** - Check L1, L2, or All controls
- **Secure Authentication** - Modern OAuth 2.0 with persistent token caching
- **Read-Only Assessment** - No changes to your environment
- **Actionable Remediation** - Each failed check includes specific remediation steps
- **PowerShell 5.1 & 7+ Compatible** - Works on Windows PowerShell and PowerShell Core
- **Cached API Calls** - Minimized redundant Microsoft Graph and service calls

## Automation Coverage

| Category | Total Controls | Automated | Manual | Coverage |
|----------|---------------|-----------|--------|----------|
| **Section 1: M365 Admin** | 15 | 5 | 10 | 33% |
| **Section 2: M365 Defender** | 20 | 15 | 5 | 75% |
| **Section 3: Purview** | 4 | 3 | 1 | 75% |
| **Section 4: Intune** | 2 | 2 | 0 | 100% |
| **Section 5: Entra ID** | 45 | 27 | 18 | 60% |
| **Section 6: Exchange** | 12 | 11 | 1 | 92% |
| **Section 7: SharePoint** | 13 | 12 | 1 | 92% |
| **Section 8: Teams** | 17 | 17 | 0 | 100% |
| **Section 9: Power BI** | 12 | 0 | 12 | 0% |
| **TOTAL** | **140** | **92** | **48** | **66%** |

## Installation

```powershell
# Install from PowerShell Gallery
Install-Module -Name CIS-M365-Benchmark -Scope CurrentUser

# Update to latest version
Update-Module -Name CIS-M365-Benchmark
```

## Prerequisites

### Required PowerShell Modules

The following modules are **automatically installed** when you first use the module:

| Module | Purpose |
|--------|---------|
| `Microsoft.Graph` (v2.0+) | Entra ID, Conditional Access, PIM, Authentication Methods |
| `ExchangeOnlineManagement` | Exchange Online configuration checks |
| `Microsoft.Online.SharePoint.PowerShell` | SharePoint Online tenant settings |
| `MicrosoftTeams` | Teams meeting, messaging, and federation policies |

### Required Permissions

Your account needs the following permissions:

**Microsoft Graph API:**
- `Directory.Read.All`
- `Policy.Read.All`
- `AuditLog.Read.All`
- `UserAuthenticationMethod.Read.All`
- `IdentityRiskyUser.Read.All`
- `Application.Read.All`
- `Organization.Read.All`
- `User.Read.All`
- `Group.Read.All`
- `RoleManagement.Read.All`
- `Reports.Read.All`
- `DeviceManagementConfiguration.Read.All`
- `DeviceManagementServiceConfig.Read.All`

**Exchange Online:**
- View-Only Organization Management or higher

**SharePoint Online:**
- SharePoint Administrator or Global Administrator

**Microsoft Teams:**
- Teams Administrator or Global Administrator

## Usage

```powershell
# Quick start - 3 steps
Import-Module CIS-M365-Benchmark
Connect-CISBenchmark
Invoke-CISBenchmark

# Specify tenant manually
Invoke-CISBenchmark `
    -TenantDomain "contoso.onmicrosoft.com" `
    -SharePointAdminUrl "https://contoso-admin.sharepoint.com"

# Check only L1 or L2 controls
Invoke-CISBenchmark -ProfileLevel "L1"
Invoke-CISBenchmark -ProfileLevel "L2"

# Custom output directory
Invoke-CISBenchmark -OutputPath "C:\CIS-Reports"

# Device code authentication (headless/remote sessions)
Connect-CISBenchmark -UseDeviceCode
Invoke-CISBenchmark

# Full example with all parameters
Invoke-CISBenchmark `
    -TenantDomain "contoso.onmicrosoft.com" `
    -SharePointAdminUrl "https://contoso-admin.sharepoint.com" `
    -ProfileLevel "All" `
    -OutputPath "C:\Security\CIS-Reports" `
    -Verbose

# Look up a specific control
Get-CISBenchmarkControl -ControlNumber "5.2.2.1"

# Check prerequisites and module versions
Test-CISBenchmarkPrerequisites

# Module info
Get-CISBenchmarkInfo
```

## Output Reports

### HTML Report
- **File**: `CIS-M365-Compliance-Report_YYYYMMDD_HHMMSS.html`
- Professional dark-themed report with summary dashboard, progress bars, and L1/L2 breakdown
- Filterable results table with search, remediation steps for each failed control

### CSV Report
- **File**: `CIS-M365-Compliance-Report_YYYYMMDD_HHMMSS.csv`
- Import into Excel for tracking over time or further analysis

### Audit Log
- **File**: `CIS-M365-Audit_YYYYMMDD_HHMMSS.log`
- Timestamped log of every check result for compliance evidence

## Troubleshooting

**Issue: "Connect-CISBenchmark is not recognized"**
- Install the latest version: `Install-Module -Name CIS-M365-Benchmark -Scope CurrentUser -Force`

**Issue: Authentication browser window doesn't open**
- Use device code authentication: `Connect-CISBenchmark -UseDeviceCode`

**Issue: Multiple sign-in prompts**
- Normal. Each M365 service (Graph, Exchange, SharePoint, Teams) may prompt separately.

**Issue: SPO authentication fails on PowerShell 7+**
- The module handles this automatically. If issues persist, try Windows PowerShell 5.1.

**Issue: PIM or Identity Governance errors**
- Ensure PIM is licensed. Controls 5.3.4/5.3.5 require Entra ID P2.

## Security Considerations

- **Read-Only**: Script only reads configuration, never modifies settings
- **Secure Auth**: Uses OAuth 2.0 modern authentication
- **No Credentials Stored**: Authentication tokens are session-based only
- **No MSOL Dependency**: Fully migrated to Microsoft Graph API
- **Audit Trail**: All checks are logged with timestamps
- **Sensitive Data**: Reports may contain tenant configuration details - store securely

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## References

- [CIS Microsoft 365 Foundations Benchmark v6.0.0](https://www.cisecurity.org/benchmark/microsoft_365)
- [Microsoft Graph API Documentation](https://docs.microsoft.com/en-us/graph/)
- [Microsoft 365 Security Best Practices](https://docs.microsoft.com/en-us/microsoft-365/security/)

## Author

**Mohammed Siddiqui**
- LinkedIn: [Let's Chat!](https://www.linkedin.com/in/mohammedsiddiqui6872/)
- Profile: [PowerShellNerd Profile](https://powershellnerd.com/profile/mohammedsiddiqui)

## Acknowledgments

- CIS (Center for Internet Security) for the comprehensive benchmark
- Microsoft for providing Graph API and PowerShell modules
- The Microsoft 365 security community
- Thanks to ITEngineer-0815, M0nk3yOo, ozsaid, boscorelly, and Mateusz Jagiello for their contributions and issue reports

## Support

For issues, questions, or suggestions:
- [Open an Issue](https://github.com/mohammedsiddiqui6872/CIS-Microsoft-365-Foundations-Benchmark/issues)
- [Start a Discussion](https://github.com/mohammedsiddiqui6872/CIS-Microsoft-365-Foundations-Benchmark/discussions)
- [PowerShellNerd](https://powershellnerd.com)

---

**If you find this tool helpful, please consider giving it a star!**

**Disclaimer**: This toolkit is not affiliated with or endorsed by Microsoft Corporation or CIS (Center for Internet Security). This script is provided as-is for compliance assessment purposes. Always test in a non-production environment first.
