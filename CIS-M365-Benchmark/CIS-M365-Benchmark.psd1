@{

RootModule = 'CIS-M365-Benchmark.psm1'
ModuleVersion = '2.5.1'
CompatiblePSEditions = @('Desktop', 'Core')
GUID = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
Author = 'Mohammed Siddiqui'
CompanyName = 'Community'
Copyright = '(c) 2025 Mohammed Siddiqui. All rights reserved. MIT License.'
Description = 'Comprehensive PowerShell script that audits Microsoft 365 environments against all 130 CIS Microsoft 365 Foundations Benchmark v5.0.0 controls. Features 68% automated compliance checks with HTML and CSV reporting. Covers M365 Admin Center, Defender, Purview, Intune, Entra ID, Exchange, SharePoint, Teams, and Power BI security controls.'
PowerShellVersion = '5.1'

FunctionsToExport = @(
    'Connect-CISBenchmark',
    'Invoke-CISBenchmark',
    'Get-CISBenchmarkControl',
    'Test-CISBenchmarkPrerequisites',
    'Get-CISBenchmarkInfo'
)

CmdletsToExport = @()
VariablesToExport = @()
AliasesToExport = @()

FileList = @(
    'CIS-M365-Benchmark.psm1',
    'CIS-M365-Compliance-Checker.ps1',
    'README.md',
    'CHANGELOG.md',
    'PERMISSIONS.md',
    'LICENSE'
)

PrivateData = @{
    PSData = @{
        Tags = @('CIS', 'Microsoft365', 'M365', 'Compliance', 'Security', 'Audit', 'Benchmark', 'EntraID', 'AzureAD', 'Exchange', 'SharePoint', 'Teams', 'Intune', 'Defender', 'Purview', 'SecurityCompliance', 'GRC', 'RiskManagement')
        LicenseUri = 'https://github.com/mohammedsiddiqui6872/CIS-Microsoft-365-Foundations-Benchmark-v5.0.0/blob/main/LICENSE'
        ProjectUri = 'https://github.com/mohammedsiddiqui6872/CIS-Microsoft-365-Foundations-Benchmark-v5.0.0'
        IconUri = 'https://raw.githubusercontent.com/mohammedsiddiqui6872/CIS-Microsoft-365-Foundations-Benchmark-v5.0.0/main/.github/icon.png'
        ReleaseNotes = 'See https://github.com/mohammedsiddiqui6872/CIS-Microsoft-365-Foundations-Benchmark-v5.0.0/blob/main/CHANGELOG.md'
        RequireLicenseAcceptance = $false
    }
}

HelpInfoURI = 'https://github.com/mohammedsiddiqui6872/CIS-Microsoft-365-Foundations-Benchmark-v5.0.0/blob/main/README.md'

}
