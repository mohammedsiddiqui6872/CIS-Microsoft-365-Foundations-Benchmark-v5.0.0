# Changelog

All notable changes to the CIS Microsoft 365 Foundations Benchmark Compliance Checker.

## [2.4.1] - Current Version

### Bug Fixes - User-Reported Issues

**Fixed FOUR Controls Based on User Feedback**:

1. **Control 5.1.3.1 - Dynamic Guest Group Detection**: Enhanced membership rule pattern matching to handle multiple formats including `user.userType -eq "Guest"`, `user.userType -eq 'Guest'`, and `(user.userType -eq "Guest")`. Removed restrictive Property parameter that was preventing MembershipRule from being retrieved. Now displays the matched rule in Pass details for verification.

2. **Control 5.2.3.1 - Microsoft Authenticator MFA Fatigue**: Improved hashtable property access with dual fallback methods (bracket notation and dot notation). Added explicit null handling that treats unconfigured settings as "not configured" instead of empty values. Fixes issue where number matching showed blank value despite being enabled.

3. **Control 5.2.3.2 - Custom Banned Passwords**: Enhanced API access by switching from `Get-MgBetaDirectorySetting` to direct Graph API call (`/beta/settings`). Added robust error handling with fallback to manual check when API is unavailable. Improved parsing to handle both comma and tab-delimited password lists.

4. **Control 7.2.3 - SharePoint External Sharing**: Strengthened validation logic by using explicit array matching (`-in` operator) instead of chained OR conditions. Added string normalization (`.ToString().Trim()`) to handle potential type mismatches. Now uses compliant values array for clearer validation logic.

**Note**: Control 5.2.4.1 (SSPR for All Users) was already correctly marked as MANUAL in v2.3.8. Users seeing this as "Fail" are running an outdated version.

## [2.4.0] - Previous Version

### Critical False Positive Fixes - Batch 2 (Complete)

**Fixed ELEVEN Additional Controls**:

1. **Control 5.2.2.4 - Admin Sign-In Frequency**: Now validates actual frequency value (≤4 hours) instead of just checking if property exists. Accepts hours ≤4, 1 day, or "every time" as compliant.

2. **Control 5.2.2.10 - MFA Registration Managed Device**: Now validates policy actually requires compliant/domain-joined device. Previous implementation only checked if policy targeting MFA registration existed.

3. **Control 5.2.2.11 - Intune Enrollment Frequency**: Now validates frequency is set to "every time" (most restrictive). Previous implementation only checked if policy existed.

4. **Control 5.2.3.6 - System-Preferred MFA**: Fixed hashtable property access using AdditionalProperties for beta API. Now properly detects enabled/disabled/default states.

5. **Control 6.5.3 - OWA Storage Providers**: Now checks ALL OWA mailbox policies instead of hardcoded "OwaMailboxPolicy-Default" which may not exist in all tenants.

6. **Control 8.2.1 - Teams External Domains**: Fixed contradictory logic. Now properly checks federation access, allowed domains, and blocked domains configurations.

7. **Control 7.2.4 - OneDrive Sharing**: Now accepts "ExternalUserSharingOnly" (New and existing guests) as compliant per CIS Benchmark, consistent with Control 7.2.3.

8. **Control 8.4.1 - Teams App Policies**: Fixed wrong cmdlet. Now uses `Get-CsTeamsAppPermissionPolicy` (not AppSetupPolicy) and checks DefaultCatalogAppsType and GlobalCatalogAppsType.

9. **Control 5.2.2.3 - Legacy Auth Blocking**: Enhanced validation to check both "exchangeActiveSync" and "other" client types, or policies with 4+ client types for comprehensive coverage.

10. **Control 7.3.4 - Site Custom Scripts**: Improved filtering to exclude personal sites, redirect sites, app catalog, content type hub, and search centers where DenyAddAndCustomizePages doesn't apply.

11. **CA Policy Enhancements**: Added report-only mode detection and exclusion warnings to Controls 5.2.2.1 and 5.2.2.2. Policies in "enabledForReportingButNotEnforced" state now trigger failures with specific remediation.

## [2.3.9] - Previous Version

### Critical False Positive Fixes - Batch 1

**Fixed FOUR Critical Controls**:

1. **Control 5.2.2.12 - Device Code Flow Blocking**: Fixed completely wrong property check. Now properly checks for Conditional Access policy with `AuthenticationFlows.TransferMethods` containing "deviceCodeFlow" and grant control set to "block". Previous implementation incorrectly checked `AllowedToUseSSPR` which is for admin password reset, not device code flow.

2. **Control 7.3.3 - Custom Script on Personal Sites**: Fixed tenant-only check. Now samples up to 100 actual OneDrive personal sites to verify `DenyAddAndCustomizePages` setting. Previous implementation only checked tenant default which doesn't affect existing sites.

3. **Control 2.4.4 - ZAP for Teams**: Fixed duplicate/wrong check. Now uses `Get-TeamsProtectionPolicy` and checks `ZapEnabled` property for Teams messages. Previous implementation incorrectly used `Get-AtpPolicyForO365.EnableATPForSPOTeamsODB` which is for Safe Attachments, not ZAP.

4. **Control 6.1.2 - Mailbox Audit Actions**: Fixed missing validation. Now actually validates audit actions (Owner, Delegate, Admin) match CIS requirements by sampling mailboxes. Previous implementation only checked if auditing was enabled org-wide without validating which actions were being audited.

## [2.3.8] - Previous Version

### Multiple Critical Fixes for False Positives

**Fixed THREE False Positive Controls**:

1. **Control 5.2.3.2 - Custom Banned Passwords**: Now correctly detects custom banned password lists using the proper directory settings API (`Get-MgBetaDirectorySetting` with template ID `5cf42378-d67d-4f36-ba46-e8b86229381d`). Previous implementation was checking incorrect property.

2. **Control 5.2.4.1 - SSPR Enabled for All**: Changed to manual control. Microsoft does NOT provide Graph API to check SSPR scope (All vs Selected vs None). The `authorizationPolicy.allowedToUseSSPR` only applies to administrators, not regular users.

3. **Control 7.2.3 - External Content Sharing**: Now correctly accepts "New and existing guests" (`ExternalUserSharingOnly`) as compliant per CIS Benchmark recommendations. This is the recommended secure configuration for external collaboration.

## [2.3.7] - Previous Version

### Bug Fix - Microsoft Authenticator Number Matching Detection

**Fixed Control 5.2.3.1**: Corrected hashtable property access for Microsoft Authenticator MFA fatigue protection settings. The control was returning empty values for number matching due to incorrect nested hashtable property access. Now properly detects both number matching and app context configuration.

## [2.3.4] - Previous Version

### Latest Updates

**Module Features:**
- ✅ **130 Automated Compliance Checks** across all M365 services
- 📊 **68% Automation Coverage** - Most checks run automatically
- 📈 **Zero-Parameter Usage** - Auto-detection of tenant information
- 🔐 **Secure Authentication** - Modern OAuth 2.0 with `Connect-CISBenchmark`
- 📄 **Dual Report Format** - HTML and CSV reports with actionable remediation
- 🎯 **Profile Filtering** - Check L1, L2, or All controls
- 🛡️ **Read-Only Assessment** - No modifications to your environment

**Installation:**
```powershell
Install-Module -Name CIS-M365-Benchmark -Scope CurrentUser
Connect-CISBenchmark
Invoke-CISBenchmark
```

### What's Covered

**Compliance Checks Across 9 Sections:**
1. Microsoft 365 Admin Center (8 controls)
2. Microsoft 365 Defender (14 controls)
3. Microsoft Purview (3 controls)
4. Microsoft Intune Admin Center (2 controls)
5. Microsoft Entra Admin Center (41 controls)
6. Exchange Admin Center (14 controls)
7. SharePoint Admin Center (14 controls)
8. Microsoft Teams Admin Center (13 controls)
9. Microsoft Fabric / Power BI (11 controls)

### Technical Highlights

- Auto-detection of tenant domain and SharePoint admin URL
- Automatic prerequisite module installation and updates
- Enhanced HTML reports with modern UI and floating action buttons
- Comprehensive error handling and graceful fallbacks
- PowerShell 5.1 and 7+ compatibility
- Microsoft.Graph 2.0+ support with automatic version management

---

## Support

- 🐛 [Report Issues](https://github.com/mohammedsiddiqui6872/CIS-Microsoft-365-Foundations-Benchmark-v5.0.0/issues)
- 💬 [Discussions](https://github.com/mohammedsiddiqui6872/CIS-Microsoft-365-Foundations-Benchmark-v5.0.0/discussions)
- ☕ [Support Development](https://buymeacoffee.com/mohammedsiddiqui)
