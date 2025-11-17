# Changelog

All notable changes to the CIS Microsoft 365 Foundations Benchmark Compliance Checker will be documented in this file.

## [2.5.2] - 2025-11-17

### 🐛 Bug Fixes
- **Fixed Click Functionality**: Resolved critical issues with interactive elements in HTML reports
  - Converted all inline onclick handlers to programmatic event listeners
  - Fixed tenant name dropdown not responding to clicks
  - Fixed score card filtering not working when clicked
  - Added proper DOM ready detection with multiple fallback mechanisms
  - Enhanced event attachment reliability with defensive coding
  - Improved search box functionality with both keyup and input events
  - Added console logging for debugging event attachment
  - Ensures all interactive elements work across different browsers and security contexts

## [2.4.4] - 2025-01-17

### ✨ New Features
- **Real-time Search Box**: Added instant search functionality to HTML reports
  - Search across control number, title, level (L1/L2), status, and details
  - Live filtering as you type with result counter
  - Clear search to restore all results
  - Clears filter buttons when searching and vice versa

- **L1/L2 Level Tracking**: Added dedicated score cards for profile levels
  - New L1 Checks card showing passed/total L1 controls with compliance rate
  - New L2 Checks card showing passed/total L2 controls with compliance rate
  - Clickable cards to filter results by profile level
  - Console output includes L1/L2 statistics breakdown

- **Enhanced UI Design**: Modern, professional report styling
  - Compact summary boxes with reduced height for better space efficiency
  - Unified black background for all score cards
  - Animated white glowing borders with continuous pulsing effect
  - Color-coded text for easy status identification
  - Improved hover effects with enhanced glow
  - Active state shows blue glow when filtering

### Technical Details
- Added 8 new global counters: L1Total, L1Passed, L1Failed, L1Manual, L2Total, L2Passed, L2Failed, L2Manual
- Updated Add-Result function to track L1/L2 statistics separately
- Implemented searchTable() JavaScript function for real-time filtering
- Added data-level attribute to table rows for level-based filtering
- CSS animations using @keyframes for smooth border glow effect
- Enhanced filterResults() function to support both status and level filtering

### User Experience Improvements
- Search box positioned prominently above Detailed Results table
- Results counter displays "Found X results out of Y controls"
- Search supports partial matching across all columns
- Smooth transitions and professional animations throughout
- Better visual hierarchy with compact, consistent design

## [2.4.3] - 2025-01-17

### 🐛 Bug Fixes
- **Fixed Control 5.2.3.1**: False positive eliminated for Microsoft Authenticator MFA fatigue protection
  - Now accepts "default" state as compliant (Microsoft enabled number matching by default in 2025)
  - Added missing third check: `displayLocationInformationRequiredState` (geographic location)
  - CIS 5.2.3.1 requires THREE settings: (1) number matching, (2) app name display, (3) location display
  - Before: Only accepted "enabled" state and checked 2 of 3 required settings
  - After: Accepts both "enabled" and "default" states and checks all 3 required settings

### Technical Details
- Updated validation logic to accept `$state -eq "enabled" -or $state -eq "default"`
- Added `displayLocationInformationRequiredState` check per CIS Benchmark v5.0.0 requirement
- Enhanced details output to show all three setting states for better troubleshooting
- Updated remediation guidance to include all three required configuration steps

### Issue Reported
User reported false positive where number matching showed "not configured" despite being enabled by Microsoft's default settings.

## [2.1.1] - 2025-01-13

### 🐛 Bug Fixes
- **Fixed SharePointAdminUrl validation**: Parameter now accepts URLs with trailing slashes
  - Before: `https://tenant-admin.sharepoint.com/` would fail validation
  - After: Both `https://tenant-admin.sharepoint.com` and `https://tenant-admin.sharepoint.com/` work
- **Improved URL handling**: Added automatic trimming of trailing slashes before passing to compliance script

### Technical Details
- Updated regex pattern from `^https://.*-admin\.sharepoint\.com$` to `^https://.*-admin\.sharepoint\.com/?$`
- Added `TrimEnd('/')` to clean URLs before processing

### Issue Reported
User reported error when using tab-completion which adds trailing slash to SharePoint URLs.

## [2.1.0] - 2025-01-13

### 🚀 Major Update - Module Command Support

This is a **breaking change** release that restructures the project as a proper PowerShell module with exported cmdlets.

### ✨ Added
- **PowerShell Module Structure**: Module now exports proper cmdlets instead of requiring direct script execution
- **New Commands**:
  - `Invoke-CISBenchmark` - Main cmdlet to run compliance checks with full parameter support
  - `Get-CISBenchmarkControl` - Query information about specific CIS controls
  - `Test-CISBenchmarkPrerequisites` - Verify all required PowerShell modules are installed
  - `Get-CISBenchmarkInfo` - Display module information and quick start guide
- **Enhanced Parameter Support**: Better validation and help documentation for all parameters
- **Verbose Logging**: Support for `-Verbose` switch to see detailed execution progress
- **Summary Output**: `Invoke-CISBenchmark` returns a PSCustomObject with compliance statistics

### 🔧 Changed
- **Breaking**: Module structure changed from script-only to proper PSM1/PSD1 module
- **Breaking**: After installing from PowerShell Gallery, use `Invoke-CISBenchmark` instead of running `.ps1` file
- Updated `ModuleVersion` from 2.0.0 to 2.1.0
- Updated README.md with module command usage examples
- Script execution logic now only runs when called directly, not when dot-sourced

### 🐛 Fixed
- Fixed module loading errors when importing from PowerShell Gallery
- Fixed mandatory parameter validation errors during module import
- Script no longer auto-executes when imported as module dependency

### 📝 Documentation
- Added comprehensive comment-based help for all exported functions
- Updated README with module command examples
- Added "Legacy Script Usage" section for backward compatibility
- Enhanced inline documentation with better examples

### 💡 Usage Examples

After installation:
```powershell
# Import module
Import-Module CIS-M365-Benchmark

# See available commands
Get-Command -Module CIS-M365-Benchmark

# Run compliance check
Invoke-CISBenchmark -TenantDomain "tenant.onmicrosoft.com" `
                    -SharePointAdminUrl "https://tenant-admin.sharepoint.com"

# Check prerequisites
Test-CISBenchmarkPrerequisites

# Get module info
Get-CISBenchmarkInfo
```

### 🔄 Migration Guide

**For PowerShell Gallery users:**
```powershell
# Old way (v2.0.0) - NO LONGER WORKS
Install-Module CIS-M365-Benchmark
# Then manually find and run .ps1 file (confusing!)

# New way (v2.1.0)
Install-Module CIS-M365-Benchmark
Import-Module CIS-M365-Benchmark
Invoke-CISBenchmark -TenantDomain "tenant.onmicrosoft.com" `
                    -SharePointAdminUrl "https://tenant-admin.sharepoint.com"
```

**For direct script users:**
- No changes required - script can still be run directly:
  ```powershell
  .\CIS-M365-Compliance-Checker.ps1 -TenantDomain "..." -SharePointAdminUrl "..."
  ```

## [2.0.0] - 2025-01-11

### 🚀 Major Release - Significant Automation Improvements

### Added
- ✨ **25+ New Automated Checks** - Increased automation coverage from ~35% to 68%
- 📊 **Section 4: Intune Checks** - Automated device compliance and enrollment restrictions
- 🔐 **Section 5.3: PIM & Governance** - Full automation of Privileged Identity Management checks
- 🎯 **Enhanced CA Policy Checks** - Automated detection of Conditional Access policies
- 🔑 **Authentication Method Automation** - MFA fatigue protection, weak auth detection
- 📈 **Access Reviews Automation** - Automated checks for guest and privileged role reviews
- 📝 **Comprehensive Documentation** - Added PERMISSIONS.md with detailed permission requirements

### Automated Checks (New in v2.0)

#### Section 1: M365 Admin Center
- 1.3.1: Password expiration policy validation

#### Section 4: Microsoft Intune
- 4.1: Device compliance policy settings
- 4.2: Personal device enrollment restrictions

#### Section 5: Entra ID
- 5.1.2.2: Third-party app registration restrictions
- 5.1.2.4: Entra admin center access controls
- 5.2.2.10: Managed device requirement for MFA registration
- 5.2.2.11: Intune enrollment sign-in frequency
- 5.2.3.1: Microsoft Authenticator MFA fatigue protection
- 5.2.3.2: Custom banned password lists
- 5.2.3.5: Weak authentication methods (SMS/Voice) detection
- 5.2.3.6: System-preferred MFA configuration
- 5.2.4.1: Self-service password reset (SSPR) validation
- 5.3.1: Privileged Identity Management (PIM) configuration
- 5.3.2: Access reviews for guest users
- 5.3.3: Access reviews for privileged roles
- 5.3.4: Global Administrator approval requirements
- 5.3.5: Privileged Role Administrator approval requirements

#### Section 6: Exchange Online
- 6.1.2: Mailbox audit actions configuration

#### Section 7: SharePoint Online
- 7.3.2: OneDrive sync restrictions for unmanaged devices
- 7.3.3: Custom script execution restrictions on personal sites

#### Section 8: Microsoft Teams
- 8.4.1: Teams app permission policies

### Fixed
- 🐛 **1.2.1**: Fixed Get-MgGroup visibility filter error (unsupported query)
- 🐛 **3.2.1 & 3.2.2**: Fixed DLP policy cmdlet errors with graceful fallback
- 🐛 **6.1.3**: Fixed mailbox audit bypass check using correct cmdlet
- 🔧 **MSOnline Connection**: Made optional with graceful degradation
- 🔧 **Multiple Sign-ins**: Improved session reuse with TenantId parameter

### Changed
- ⚡ **Performance**: Reduced manual checks from 44% to 25-27%
- 📊 **Automation Coverage**: Increased from ~35-38% to 68%
- 🎨 **Logging**: Enhanced progress logging with better status messages
- 🔐 **Error Handling**: Improved try-catch blocks with graceful fallbacks
- 📝 **Remediation Steps**: Added detailed remediation for all automated checks

### Performance Metrics

| Metric | v1.0 | v2.0 | Improvement |
|--------|------|------|-------------|
| Total Controls | 130 | 130 | - |
| Automated | ~45-50 | ~89 | +78% |
| Manual | ~57 | ~41 | -28% |
| Errors | ~3 | ~0-1 | -67% |
| Coverage | 35-38% | 68% | +80% |

## [1.0.0] - 2025-01-10

### Initial Release

### Added
- ✅ Complete CIS Microsoft 365 Foundations Benchmark v5.0.0 coverage
- ✅ 130 compliance controls across 9 sections
- ✅ HTML and CSV report generation
- ✅ Microsoft Graph API integration
- ✅ Exchange Online compliance checks
- ✅ SharePoint Online security validation
- ✅ Microsoft Teams configuration assessment
- ✅ Basic Entra ID (Azure AD) checks
- ✅ Microsoft 365 Defender security controls
- ✅ Microsoft Purview audit and DLP checks

### Supported Sections
1. Microsoft 365 Admin Center (8 controls)
2. Microsoft 365 Defender (14 controls)
3. Microsoft Purview (3 controls)
4. Microsoft Intune Admin Center (2 controls)
5. Microsoft Entra Admin Center (41 controls)
6. Exchange Admin Center (14 controls)
7. SharePoint Admin Center (14 controls)
8. Microsoft Teams Admin Center (13 controls)
9. Microsoft Fabric / Power BI (11 controls)

### Known Limitations (v1.0)
- High percentage of manual checks (~44%)
- MSOnline connection issues
- Some Graph API filter errors
- DLP cmdlet availability issues

---

## Version History

- **v2.0.0** (2025-01-11) - Major automation improvements, 68% coverage
- **v1.0.0** (2025-01-10) - Initial release, 35-38% coverage

## Upgrade Guide

### From v1.0 to v2.0

No breaking changes. Simply replace the script file and run as before:

```powershell
# Download latest version
git pull origin main

# Run with same parameters as before
.\CIS-M365-Compliance-Checker.ps1 `
    -TenantDomain "your-tenant.onmicrosoft.com" `
    -SharePointAdminUrl "https://your-tenant-admin.sharepoint.com"
```

### New Permissions Required (v2.0)

The following additional Graph API permissions are now utilized:
- `RoleManagement.Read.All` (for PIM checks)
- Access to beta endpoints for advanced features

No action required if using Global Reader role - this already includes these permissions.

## Future Roadmap

### Planned for v2.1
- [ ] Certificate-based authentication for automation
- [ ] Power BI module integration for Section 9
- [ ] Custom report templates
- [ ] Compliance trend tracking over time
- [ ] Email report delivery

### Planned for v3.0
- [ ] Remediation automation (fix failed controls)
- [ ] Drift detection (compare against baseline)
- [ ] Integration with Azure DevOps pipelines
- [ ] Custom control definitions
- [ ] Multi-tenant support

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to contribute to this project.

## Support

- 🐛 [Report bugs](https://github.com/mohammedsiddiqui6872/CIS-Microsoft-365-Foundations-Benchmark-v5.0.0/issues)
- 💡 [Request features](https://github.com/mohammedsiddiqui6872/CIS-Microsoft-365-Foundations-Benchmark-v5.0.0/issues)
- 💬 [Ask questions](https://github.com/mohammedsiddiqui6872/CIS-Microsoft-365-Foundations-Benchmark-v5.0.0/discussions)
