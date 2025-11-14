# Changelog

All notable changes to the CIS Microsoft 365 Foundations Benchmark Compliance Checker.

## [2.3.4] - Current Version

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
