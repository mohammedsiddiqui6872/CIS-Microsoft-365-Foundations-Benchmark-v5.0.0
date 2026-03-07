#Requires -Version 5.1

<#
.SYNOPSIS
    CIS Microsoft 365 Foundations Benchmark v6.0.0 Compliance Checker

.DESCRIPTION
    Comprehensive PowerShell script to audit Microsoft 365 environment against all 140 CIS benchmark controls.
    Generates detailed HTML and CSV reports showing compliance status for each control.

.NOTES
    Version: 5.0.0
    Author: Mohammed Siddiqui
    Date: 2026-03-03

    Required PowerShell Modules:
    - Microsoft.Graph (Install-Module Microsoft.Graph -Scope CurrentUser)
    - ExchangeOnlineManagement (Install-Module ExchangeOnlineManagement -Scope CurrentUser)
    - Microsoft.Online.SharePoint.PowerShell (Install-Module Microsoft.Online.SharePoint.PowerShell -Scope CurrentUser)
    - MicrosoftTeams (Install-Module MicrosoftTeams -Scope CurrentUser)

.PARAMETER TenantDomain
    Your Microsoft 365 tenant domain (e.g., contoso.onmicrosoft.com)

.PARAMETER SharePointAdminUrl
    Your SharePoint admin URL (e.g., https://contoso-admin.sharepoint.com)

.PARAMETER OutputPath
    Path where the HTML and CSV reports will be saved. Default: Current directory

.PARAMETER ProfileLevel
    CIS profile level to check: 'L1', 'L2', or 'All'. Default: 'All'

.EXAMPLE
    .\CIS-M365-Compliance-Checker.ps1 -TenantDomain "contoso.onmicrosoft.com" -SharePointAdminUrl "https://contoso-admin.sharepoint.com"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$TenantDomain,

    [Parameter(Mandatory=$true)]
    [string]$SharePointAdminUrl,

    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".",

    [Parameter(Mandatory=$false)]
    [ValidateSet('L1','L2','All')]
    [string]$ProfileLevel = 'All',

    [Parameter(Mandatory=$false)]
    [ValidateSet('AdminCenter','Defender','Purview','Intune','EntraID','Exchange','SharePoint','Teams','PowerBI')]
    [string[]]$ExcludeSections = @()
)

# Global Variables
$Script:Results = [System.Collections.Generic.List[PSCustomObject]]::new()
$Script:TotalControls = 0
$Script:PassedControls = 0
$Script:FailedControls = 0
$Script:ManualControls = 0
$Script:ErrorControls = 0

$Script:RequestedProfileLevel = $ProfileLevel
$Script:LogFilePath = $null

# Level-specific counters
$Script:L1TotalControls = 0
$Script:L1PassedControls = 0
$Script:L1FailedControls = 0
$Script:L1ManualControls = 0
$Script:L1ErrorControls = 0
$Script:L2TotalControls = 0
$Script:L2PassedControls = 0
$Script:L2FailedControls = 0
$Script:L2ManualControls = 0
$Script:L2ErrorControls = 0

#region Helper Functions

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info','Success','Warning','Error')]
        [string]$Level = 'Info'
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch($Level) {
        'Info' { 'Cyan' }
        'Success' { 'Green' }
        'Warning' { 'Yellow' }
        'Error' { 'Red' }
    }

    Write-Host "[$timestamp] " -NoNewline
    Write-Host "[$Level] " -ForegroundColor $color -NoNewline
    Write-Host $Message

    # Write to log file if path is set
    if ($Script:LogFilePath) {
        try {
            "[$timestamp] [$Level] $Message" | Out-File -FilePath $Script:LogFilePath -Append -Encoding utf8
        }
        catch {
            # Do not recurse or fail if logging itself fails
        }
    }
}

function Add-Result {
    param(
        [string]$ControlNumber,
        [string]$ControlTitle,
        [string]$ProfileLevel,
        [ValidateSet('Pass','Fail','Manual','Error')]
        [string]$Result,
        [string]$Details,
        [string]$Remediation = ""
    )

    # Filter based on requested profile level
    # If user requested L1, only show L1 controls
    # If user requested L2, only show L2 controls
    # If user requested All, show all controls
    if ($Script:RequestedProfileLevel -ne 'All') {
        if ($ProfileLevel -ne $Script:RequestedProfileLevel) {
            # Skip this control as it doesn't match the requested profile
            return
        }
    }

    $Script:TotalControls++

    # Track level-specific statistics
    if ($ProfileLevel -eq 'L1') {
        $Script:L1TotalControls++
        switch($Result) {
            'Pass' { $Script:L1PassedControls++ }
            'Fail' { $Script:L1FailedControls++ }
            'Manual' { $Script:L1ManualControls++ }
            'Error' { $Script:L1ErrorControls++ }
        }
    }
    elseif ($ProfileLevel -eq 'L2') {
        $Script:L2TotalControls++
        switch($Result) {
            'Pass' { $Script:L2PassedControls++ }
            'Fail' { $Script:L2FailedControls++ }
            'Manual' { $Script:L2ManualControls++ }
            'Error' { $Script:L2ErrorControls++ }
        }
    }

    switch($Result) {
        'Pass' { $Script:PassedControls++ }
        'Fail' { $Script:FailedControls++ }
        'Manual' { $Script:ManualControls++ }
        'Error' { $Script:ErrorControls++ }
    }

    $Script:Results.Add([PSCustomObject]@{
        ControlNumber = $ControlNumber
        ControlTitle = $ControlTitle
        ProfileLevel = $ProfileLevel
        Result = $Result
        Details = $Details
        Remediation = $Remediation
    })

    # Log each control result to audit file
    $logLevel = switch ($Result) {
        'Pass' { 'Success' }
        'Fail' { 'Warning' }
        'Error' { 'Error' }
        default { 'Info' }
    }
    Write-Log "[$ControlNumber] [$ProfileLevel] $Result - $Details" -Level $logLevel
}

function Test-ModuleInstalled {
    param([string]$ModuleName)

    if (Get-Module -ListAvailable -Name $ModuleName) {
        return $true
    }
    return $false
}

function Get-HtmlEncoded {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return "" }
    return [System.Net.WebUtility]::HtmlEncode($Text)
}

function Connect-M365Services {
    Write-Log "Connecting to Microsoft 365 services..." -Level Info
    Write-Log "NOTE: You will be prompted to sign in once. The same session will be used for all services." -Level Info

    # Check if device code authentication was requested via Connect-CISM365Benchmark -UseDeviceCode
    $useDeviceAuth = $env:CIS_USE_DEVICE_CODE -eq "true"

    try {
        # ── Power BI FIRST ──────────────────────────────────────────────────
        # Must connect Power BI BEFORE Microsoft.Graph loads its MSAL version.
        # In PS 5.1, both modules bundle different MSAL.NET versions and the first
        # one loaded wins. By connecting PowerBI first, its MSAL loads cleanly.
        # If Graph is already loaded (from Connect-CISM365Benchmark), we use a
        # background runspace to isolate the PowerBI token acquisition.
        $Script:PowerBIConnected = $false
        $Script:PowerBIAccessToken = $null

        $pbiModule = Get-Module -ListAvailable -Name MicrosoftPowerBIMgmt.Profile -ErrorAction SilentlyContinue
        if (-not $pbiModule) {
            Write-Log "Installing MicrosoftPowerBIMgmt.Profile..." -Level Info
            try {
                Install-Module -Name MicrosoftPowerBIMgmt.Profile -Scope CurrentUser -Force -SkipPublisherCheck -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
                $pbiModule = $true
            }
            catch {
                Write-Log "Could not install MicrosoftPowerBIMgmt.Profile: $_" -Level Warning
            }
        }

        if ($pbiModule) {
            $graphMsalLoaded = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object {
                $_.GetName().Name -eq 'Microsoft.Identity.Client'
            }

            if ($graphMsalLoaded) {
                # Graph MSAL already loaded - use isolated PowerShell runspace to avoid conflicts
                Write-Log "Acquiring Power BI token via isolated runspace (Graph MSAL already loaded)..." -Level Info
                try {
                    $pbiResult = powershell.exe -NoProfile -Command {
                        try {
                            Import-Module MicrosoftPowerBIMgmt.Profile -ErrorAction Stop -WarningAction SilentlyContinue
                            $WarningPreference = 'SilentlyContinue'
                            Connect-PowerBIServiceAccount -ErrorAction Stop | Out-Null
                            $token = Get-PowerBIAccessToken -AsString -ErrorAction Stop
                            Write-Output ($token.Replace("Bearer ", ""))
                        }
                        catch {
                            Write-Output "ERROR:$($_.Exception.Message)"
                        }
                    } 2>$null

                    if ($pbiResult -and -not $pbiResult.StartsWith("ERROR:")) {
                        $Script:PowerBIAccessToken = $pbiResult.Trim()
                        $Script:PowerBIConnected = $true
                        Write-Log "Acquired Power BI token via isolated runspace" -Level Success
                    }
                    else {
                        $errMsg = if ($pbiResult) { $pbiResult.Replace("ERROR:", "") } else { "No output from runspace" }
                        Write-Log "Warning: Isolated Power BI auth failed: $errMsg" -Level Warning
                        Write-Log "Power BI checks (Section 9) will remain manual." -Level Warning
                    }
                }
                catch {
                    Write-Log "Warning: Could not acquire Power BI token: $_" -Level Warning
                    Write-Log "Power BI checks (Section 9) will remain manual." -Level Warning
                }
            }
            else {
                # No MSAL loaded yet - safe to use PowerBI module directly
                Write-Log "Connecting to Power BI Service..." -Level Info
                try {
                    Import-Module MicrosoftPowerBIMgmt.Profile -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -Force
                    $prevWarnPref = $WarningPreference
                    $WarningPreference = 'SilentlyContinue'
                    Connect-PowerBIServiceAccount -ErrorAction Stop | Out-Null
                    $pbiTokenObj = Get-PowerBIAccessToken -AsString -ErrorAction Stop
                    $Script:PowerBIAccessToken = $pbiTokenObj.Replace("Bearer ", "")
                    $Script:PowerBIConnected = $true
                    $WarningPreference = $prevWarnPref
                    Write-Log "Connected to Power BI Service and acquired token" -Level Success
                }
                catch {
                    $WarningPreference = if ($prevWarnPref) { $prevWarnPref } else { 'Continue' }
                    Write-Log "Warning: Could not connect to Power BI: $_" -Level Warning
                    Write-Log "Power BI checks (Section 9) will remain manual." -Level Warning
                }
            }
        }

        # ── Microsoft Graph ─────────────────────────────────────────────────
        # Check if Microsoft Graph is already connected (e.g., via Connect-CISM365Benchmark)
        $mgContext = Get-MgContext -ErrorAction SilentlyContinue

        if (-not $mgContext -or -not $mgContext.TenantId) {
            Write-Log "Connecting to Microsoft Graph..." -Level Info
            Connect-MgGraph -Scopes "Directory.Read.All", "Policy.Read.All", "AuditLog.Read.All", `
                                   "UserAuthenticationMethod.Read.All", "IdentityRiskyUser.Read.All", `
                                   "IdentityRiskEvent.Read.All", "Application.Read.All", `
                                   "Organization.Read.All", "User.Read.All", "Group.Read.All", `
                                   "RoleManagement.Read.All", "Reports.Read.All", `
                                   "DeviceManagementConfiguration.Read.All", `
                                   "DeviceManagementServiceConfig.Read.All", `
                                   "OrgSettings-AppsAndServices.Read.All", `
                                   "OrgSettings-Forms.Read.All" -NoWelcome -ErrorAction Stop
            Write-Log "Connected to Microsoft Graph" -Level Success
            $mgContext = Get-MgContext
        } else {
            Write-Log "Microsoft Graph already connected - reusing existing session" -Level Success
        }

        # Get the tenant ID to reuse for other service connections
        $tenantId = $mgContext.TenantId

        Write-Log "Using authenticated session for remaining services (TenantId: $tenantId)..." -Level Info

        # ── Exchange Online ─────────────────────────────────────────────────
        # Always use browser auth for Exchange - works reliably on both PS 5.1 and 7+
        Write-Log "Connecting to Exchange Online..." -Level Info
        Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        Write-Log "Connected to Exchange Online" -Level Success

        # ── SharePoint Online ───────────────────────────────────────────────
        Write-Log "Connecting to SharePoint Online..." -Level Info
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            if (-not (Get-Module -Name "Microsoft.Online.SharePoint.PowerShell")) {
                Import-Module Microsoft.Online.SharePoint.PowerShell -UseWindowsPowerShell -WarningAction SilentlyContinue -DisableNameChecking -Force
            }
        }
        if ($useDeviceAuth) {
            Connect-SPOService -Url $SharePointAdminUrl -ModernAuth $true -UseSystemBrowser $true -ErrorAction Stop
        } else {
            Connect-SPOService -Url $SharePointAdminUrl -ModernAuth $true -ErrorAction Stop
        }
        Write-Log "Connected to SharePoint Online" -Level Success

        # ── Microsoft Teams ─────────────────────────────────────────────────
        # Non-fatal - if it fails, Section 8 checks will report errors but all other sections proceed
        Write-Log "Connecting to Microsoft Teams..." -Level Info
        try {
            if ($useDeviceAuth) {
                Connect-MicrosoftTeams -TenantId $tenantId -UseDeviceAuthentication -ErrorAction Stop | Out-Null
            } else {
                Connect-MicrosoftTeams -TenantId $tenantId -ErrorAction Stop | Out-Null
            }
            Write-Log "Connected to Microsoft Teams" -Level Success
        }
        catch {
            Write-Log "Warning: Could not connect to Microsoft Teams: $_" -Level Warning
            Write-Log "Teams-related checks (Section 8) will report errors. All other checks will proceed." -Level Warning
        }

        Write-Log "MSOnline module is retired. All checks now use Microsoft Graph." -Level Info

        # ── Security & Compliance ───────────────────────────────────────────
        Write-Log "Connecting to Security & Compliance PowerShell..." -Level Info
        try {
            if ($useDeviceAuth) {
                Connect-IPPSSession -Device -WarningAction SilentlyContinue -ErrorAction Stop
            } else {
                Connect-IPPSSession -WarningAction SilentlyContinue -ErrorAction Stop
            }
            Write-Log "Connected to Security & Compliance PowerShell" -Level Success
            $Script:IPPSConnected = $true
        }
        catch {
            Write-Log "Warning: Could not connect to Security & Compliance: $_" -Level Warning
            Write-Log "DLP and sensitivity label checks will fall back to manual review." -Level Warning
            $Script:IPPSConnected = $false
        }

        Write-Log "All service connections established successfully!" -Level Success
        return $true
    }
    catch {
        Write-Log "Failed to connect to M365 services: $_" -Level Error
        return $false
    }
}

#endregion

#region Section 1: Microsoft 365 Admin Center

function Test-M365AdminCenter {
    Write-Log "Checking Section 1: Microsoft 365 Admin Center..." -Level Info

    # 1.1.1 - Ensure Administrative accounts are cloud-only
    try {
        Write-Log "Checking 1.1.1 - Administrative accounts are cloud-only" -Level Info

        # Read-only role template IDs to exclude - these are not administrative roles
        # CIS requires only privileged (write/modify) admin accounts to be cloud-only
        $readOnlyRoleTemplateIds = @(
            "88d8e3e3-8f55-4a1e-953a-9b9898b8876b"  # Directory Readers
            "f2ef992c-3afb-46b9-b7cf-a126ee74c451"  # Global Reader
            "790c1fb9-7f7d-4f88-86a1-ef1f95c05c1b"  # Message Center Reader
            "4a5d8f65-41da-4de4-8968-e035b65339cf"  # Reports Reader
            "5d6b6bb7-de71-4623-b4af-96380a352509"  # Security Reader
        )

        $allRoles = Get-MgDirectoryRole -All -ErrorAction Stop
        $adminRoles = $allRoles | Where-Object { $_.RoleTemplateId -notin $readOnlyRoleTemplateIds }

        $adminUsers = @()
        foreach ($role in $adminRoles) {
            $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -ErrorAction Stop
            foreach ($member in $members) {
                if ($member.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.user') {
                    $user = Get-MgUser -UserId $member.Id -Property Id,UserPrincipalName,OnPremisesSyncEnabled -ErrorAction Stop
                    if ($user.OnPremisesSyncEnabled -eq $true) {
                        $adminUsers += "$($user.UserPrincipalName) ($($role.DisplayName))"
                    }
                }
            }
        }

        # Deduplicate in case a user has multiple admin roles
        $adminUsers = @($adminUsers | Select-Object -Unique)

        if ($adminUsers.Count -eq 0) {
            Add-Result -ControlNumber "1.1.1" -ControlTitle "Ensure Administrative accounts are cloud-only" `
                       -ProfileLevel "L1" -Result "Pass" -Details "All administrative accounts are cloud-only"
        }
        else {
            Add-Result -ControlNumber "1.1.1" -ControlTitle "Ensure Administrative accounts are cloud-only" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Synced admin accounts found: $($adminUsers -join ', ')" `
                       -Remediation "Convert administrative accounts to cloud-only accounts"
        }
    }
    catch {
        Add-Result -ControlNumber "1.1.1" -ControlTitle "Ensure Administrative accounts are cloud-only" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 1.1.2 - Ensure two emergency access accounts have been defined
    try {
        Write-Log "Checking 1.1.2 - Emergency access accounts" -Level Info

        # Get Global Administrator role members
        $globalAdminRole = Get-MgDirectoryRole -Filter "DisplayName eq 'Global Administrator'" -ErrorAction Stop
        $globalAdminMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id -ErrorAction Stop

        # Get all Conditional Access policies to find excluded users
        $caPolicies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
        $caExcludedUsers = @{}
        foreach ($policy in $caPolicies) {
            if ($policy.State -eq 'enabled' -and $policy.Conditions.Users.ExcludeUsers) {
                foreach ($uid in $policy.Conditions.Users.ExcludeUsers) {
                    if (-not $caExcludedUsers.ContainsKey($uid)) { $caExcludedUsers[$uid] = 0 }
                    $caExcludedUsers[$uid]++
                }
            }
        }
        $enabledPolicyCount = ($caPolicies | Where-Object { $_.State -eq 'enabled' }).Count

        # Identify emergency access accounts: cloud-only Global Admins excluded from CA policies
        $emergencyAccounts = @()
        foreach ($member in $globalAdminMembers) {
            if ($member.AdditionalProperties.'@odata.type' -ne '#microsoft.graph.user') { continue }
            $user = Get-MgUser -UserId $member.Id -Property Id,UserPrincipalName,DisplayName,OnPremisesSyncEnabled,AccountEnabled -ErrorAction Stop
            if ($user.OnPremisesSyncEnabled -eq $true) { continue }
            if (-not $user.AccountEnabled) { continue }

            # Check if excluded from most CA policies (emergency accounts should be excluded from all/most)
            $excludedCount = if ($caExcludedUsers.ContainsKey($user.Id)) { $caExcludedUsers[$user.Id] } else { 0 }
            $excludeRatio = if ($enabledPolicyCount -gt 0) { $excludedCount / $enabledPolicyCount } else { 0 }

            # Emergency account heuristics: excluded from at least 50% of CA policies
            if ($excludeRatio -ge 0.5) {
                $emergencyAccounts += "$($user.UserPrincipalName) (excluded from $excludedCount/$enabledPolicyCount CA policies)"
            }
        }

        if ($emergencyAccounts.Count -ge 2) {
            Add-Result -ControlNumber "1.1.2" -ControlTitle "Ensure two emergency access accounts have been defined" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Found $($emergencyAccounts.Count) emergency access accounts: $($emergencyAccounts -join '; ')"
        }
        elseif ($emergencyAccounts.Count -eq 1) {
            Add-Result -ControlNumber "1.1.2" -ControlTitle "Ensure two emergency access accounts have been defined" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Only 1 emergency access account detected: $($emergencyAccounts -join '; '). At least 2 are required." `
                       -Remediation "Create a second emergency access (break glass) account that is cloud-only, has Global Admin role, and is excluded from all Conditional Access policies"
        }
        else {
            Add-Result -ControlNumber "1.1.2" -ControlTitle "Ensure two emergency access accounts have been defined" `
                       -ProfileLevel "L1" -Result "Fail" -Details "No emergency access accounts detected. Looked for cloud-only Global Admins excluded from Conditional Access policies." `
                       -Remediation "Create two emergency access (break glass) accounts that are cloud-only, have Global Admin role, and are excluded from all Conditional Access policies"
        }
    }
    catch {
        Add-Result -ControlNumber "1.1.2" -ControlTitle "Ensure two emergency access accounts have been defined" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 1.1.3 - Ensure that between two and four global admins are designated
    try {
        Write-Log "Checking 1.1.3 - Global admin count" -Level Info
        $globalAdminRole = Get-MgDirectoryRole -Filter "DisplayName eq 'Global Administrator'" -ErrorAction Stop
        $globalAdmins = Get-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id -ErrorAction Stop
        $globalAdminCount = $globalAdmins.Count

        if ($globalAdminCount -ge 2 -and $globalAdminCount -le 4) {
            Add-Result -ControlNumber "1.1.3" -ControlTitle "Ensure that between two and four global admins are designated" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Global admin count: $globalAdminCount"
        }
        else {
            Add-Result -ControlNumber "1.1.3" -ControlTitle "Ensure that between two and four global admins are designated" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Global admin count: $globalAdminCount (should be 2-4)" `
                       -Remediation "Adjust global administrator count to between 2 and 4"
        }
    }
    catch {
        Add-Result -ControlNumber "1.1.3" -ControlTitle "Ensure that between two and four global admins are designated" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 1.1.4 - Ensure administrative accounts use licenses with a reduced application footprint
    try {
        Write-Log "Checking 1.1.4 - Admin account license footprint" -Level Info

        # Allowlist approach per CIS v6.0.0 guidance (page 30):
        # Only these lightweight/admin-only SKUs are acceptable for admin accounts.
        # Any SKU NOT in this list includes applications and should be flagged.
        $allowedSkus = @(
            "AAD_PREMIUM",           # Microsoft Entra ID P1
            "AAD_PREMIUM_P2",        # Microsoft Entra ID P2
            "INTUNE_A",              # Microsoft Intune Plan 1
            "INTUNE_EDU",            # Microsoft Intune for Education
            "EMSPREMIUM",            # Enterprise Mobility + Security E5
            "EMS",                   # Enterprise Mobility + Security E3
            "RIGHTSMANAGEMENT",       # Azure Information Protection Plan 1
            "THREAT_INTELLIGENCE",    # Microsoft Defender for Office 365 P2
            "ATP_ENTERPRISE",         # Microsoft Defender for Office 365 P1
            "ATA",                   # Microsoft Defender for Identity
            "ADALLOM_STANDALONE",     # Microsoft Defender for Cloud Apps
            "IDENTITY_THREAT_PROTECTION" # Microsoft 365 E5 Security
        )

        $allRoles1_1_4 = Get-MgDirectoryRole -All -ErrorAction Stop
        $adminRoles1_1_4 = $allRoles1_1_4 | Where-Object { $_.RoleTemplateId -notin $readOnlyRoleTemplateIds }

        $adminUserIds = @()
        foreach ($role in $adminRoles1_1_4) {
            $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -ErrorAction Stop
            foreach ($member in $members) {
                if ($member.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.user') {
                    $adminUserIds += $member.Id
                }
            }
        }
        $adminUserIds = @($adminUserIds | Select-Object -Unique)

        $adminsWithHeavyLicenses = @()
        foreach ($userId in $adminUserIds) {
            $licenses = Get-MgUserLicenseDetail -UserId $userId -ErrorAction SilentlyContinue
            $disallowedSkus = $licenses | Where-Object { $_.SkuPartNumber -notin $allowedSkus }
            if ($disallowedSkus) {
                $user = Get-MgUser -UserId $userId -Property UserPrincipalName -ErrorAction SilentlyContinue
                $adminsWithHeavyLicenses += "$($user.UserPrincipalName) ($($disallowedSkus.SkuPartNumber -join ', '))"
            }
        }

        if ($adminsWithHeavyLicenses.Count -eq 0) {
            Add-Result -ControlNumber "1.1.4" -ControlTitle "Ensure administrative accounts use licenses with a reduced application footprint" `
                       -ProfileLevel "L1" -Result "Pass" -Details "All $($adminUserIds.Count) admin accounts use only reduced-footprint licenses"
        }
        else {
            Add-Result -ControlNumber "1.1.4" -ControlTitle "Ensure administrative accounts use licenses with a reduced application footprint" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Admins with application-bearing licenses: $($adminsWithHeavyLicenses -join '; ')" `
                       -Remediation "Assign only lightweight licenses (Entra ID P1/P2, EMS, Intune, Defender) to admin accounts. Remove any SKU that includes M365 apps (E3, E5, Business Premium, F-series, etc.)"
        }
    }
    catch {
        Add-Result -ControlNumber "1.1.4" -ControlTitle "Ensure administrative accounts use licenses with a reduced application footprint" `
                   -ProfileLevel "L1" -Result "Manual" -Details "Unable to check admin licensing: $_" `
                   -Remediation "Verify admin accounts use minimal licenses in Entra Admin Center > Users"
    }

    # 1.2.1 - Ensure that only organizationally managed/approved public groups exist
    try {
        Write-Log "Checking 1.2.1 - Public groups approval" -Level Info
        # Get all groups and filter by visibility property (Graph API filter doesn't support visibility)
        $allGroups = Get-MgGroup -All -Property DisplayName,Visibility,Id -ErrorAction Stop
        $publicGroups = $allGroups | Where-Object { $_.Visibility -eq 'Public' }

        if ($publicGroups.Count -eq 0) {
            Add-Result -ControlNumber "1.2.1" -ControlTitle "Ensure that only organizationally managed/approved public groups exist" `
                       -ProfileLevel "L2" -Result "Pass" -Details "No public groups found"
        }
        else {
            $groupNames = ($publicGroups | Select-Object -ExpandProperty DisplayName) -join ', '
            Add-Result -ControlNumber "1.2.1" -ControlTitle "Ensure that only organizationally managed/approved public groups exist" `
                       -ProfileLevel "L2" -Result "Manual" -Details "Public groups found: $groupNames. Manual verification needed" `
                       -Remediation "Review and approve or remove unauthorized public groups"
        }
    }
    catch {
        Add-Result -ControlNumber "1.2.1" -ControlTitle "Ensure that only organizationally managed/approved public groups exist" `
                   -ProfileLevel "L2" -Result "Error" -Details "Error: $_"
    }

    # 1.2.2 - Ensure sign-in to shared mailboxes is blocked
    try {
        Write-Log "Checking 1.2.2 - Shared mailbox sign-in blocked" -Level Info
        $sharedMailboxes = Get-EXOMailbox -RecipientTypeDetails SharedMailbox -ResultSize Unlimited -ErrorAction Stop
        $enabledSharedMB = @()

        foreach ($mb in $sharedMailboxes) {
            $user = Get-MgUser -UserId $mb.ExternalDirectoryObjectId -Property AccountEnabled -ErrorAction SilentlyContinue
            if ($user.AccountEnabled) {
                $enabledSharedMB += $mb.UserPrincipalName
            }
        }

        if ($enabledSharedMB.Count -eq 0) {
            Add-Result -ControlNumber "1.2.2" -ControlTitle "Ensure sign-in to shared mailboxes is blocked" `
                       -ProfileLevel "L1" -Result "Pass" -Details "All shared mailboxes have sign-in disabled"
        }
        else {
            Add-Result -ControlNumber "1.2.2" -ControlTitle "Ensure sign-in to shared mailboxes is blocked" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Shared mailboxes with sign-in enabled: $($enabledSharedMB -join ', ')" `
                       -Remediation "Disable sign-in for shared mailboxes: Set-MgUser -UserId <ID> -AccountEnabled `$false"
        }
    }
    catch {
        Add-Result -ControlNumber "1.2.2" -ControlTitle "Ensure sign-in to shared mailboxes is blocked" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 1.3.1 - Ensure the 'Password expiration policy' is set to never expire
    try {
        Write-Log "Checking 1.3.1 - Password expiration policy" -Level Info
        # Check password policy via Graph API
        $defaultDomain = Get-MgDomain -ErrorAction Stop | Where-Object { $_.IsDefault -eq $true } | Select-Object -First 1

        # CIS requires passwords to be set to "never expire" which is exactly 2147483647
        # Any other value (even large ones like 400 days) is NOT compliant
        if ($defaultDomain.PasswordValidityPeriodInDays -eq 2147483647) {
            Add-Result -ControlNumber "1.3.1" -ControlTitle "Ensure the 'Password expiration policy' is set to 'Set passwords to never expire'" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Password expiration set to never expire (2147483647 days)"
        }
        else {
            Add-Result -ControlNumber "1.3.1" -ControlTitle "Ensure the 'Password expiration policy' is set to 'Set passwords to never expire'" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Password expires in $($defaultDomain.PasswordValidityPeriodInDays) days (must be set to never expire)" `
                       -Remediation "Update-MgDomain -DomainId $($defaultDomain.Id) -PasswordValidityPeriodInDays 2147483647"
        }
    }
    catch {
        Add-Result -ControlNumber "1.3.1" -ControlTitle "Ensure the 'Password expiration policy' is set to 'Set passwords to never expire'" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 1.3.2 - Ensure 'Idle session timeout' is set to '3 hours (or less)' for unmanaged devices
    try {
        Write-Log "Checking 1.3.2 - Idle session timeout" -Level Info
        $timeoutPolicies = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/policies/activityBasedTimeoutPolicies" -ErrorAction Stop

        if ($timeoutPolicies.value.Count -gt 0) {
            $compliant = $false
            $timeoutValue = "Not set"
            foreach ($policy in $timeoutPolicies.value) {
                foreach ($def in $policy.definition) {
                    $parsed = $def | ConvertFrom-Json
                    $appPolicy = $parsed.ActivityBasedTimeoutPolicy.ApplicationPolicies | Where-Object { $_.ApplicationId -eq "default" }
                    if ($appPolicy -and $appPolicy.WebSessionIdleTimeout) {
                        $timeout = [TimeSpan]::Parse($appPolicy.WebSessionIdleTimeout)
                        $timeoutValue = $appPolicy.WebSessionIdleTimeout
                        if ($timeout.TotalHours -le 3) { $compliant = $true }
                    }
                }
            }
            if ($compliant) {
                Add-Result -ControlNumber "1.3.2" -ControlTitle "Ensure 'Idle session timeout' is set to '3 hours (or less)' for unmanaged devices" `
                           -ProfileLevel "L2" -Result "Pass" -Details "Idle session timeout configured: $timeoutValue"
            }
            else {
                Add-Result -ControlNumber "1.3.2" -ControlTitle "Ensure 'Idle session timeout' is set to '3 hours (or less)' for unmanaged devices" `
                           -ProfileLevel "L2" -Result "Fail" -Details "Idle session timeout exceeds 3 hours: $timeoutValue" `
                           -Remediation "Set idle session timeout to 3 hours or less in M365 Admin Center > Settings > Org Settings > Security & privacy"
            }
        }
        else {
            Add-Result -ControlNumber "1.3.2" -ControlTitle "Ensure 'Idle session timeout' is set to '3 hours (or less)' for unmanaged devices" `
                       -ProfileLevel "L2" -Result "Fail" -Details "No activity-based timeout policy configured" `
                       -Remediation "Configure idle session timeout in M365 Admin Center > Settings > Org Settings > Security & privacy"
        }
    }
    catch {
        Add-Result -ControlNumber "1.3.2" -ControlTitle "Ensure 'Idle session timeout' is set to '3 hours (or less)' for unmanaged devices" `
                   -ProfileLevel "L2" -Result "Manual" -Details "Unable to check idle session timeout: $_" `
                   -Remediation "Check M365 Admin Center > Settings > Org Settings > Security & privacy"
    }

    # 1.3.3 - Ensure 'External sharing' of calendars is not available
    try {
        Write-Log "Checking 1.3.3 - External calendar sharing" -Level Info
        $sharingPolicies = Get-SharingPolicy -ErrorAction Stop
        $externalCalendarEnabled = $false

        foreach ($policy in $sharingPolicies) {
            if ($policy.Enabled -eq $true -and $policy.Domains) {
                foreach ($domain in $policy.Domains) {
                    # Domain entries containing 'CalendarSharing' indicate external calendar sharing
                    if ($domain -like "*CalendarSharing*") {
                        $externalCalendarEnabled = $true
                        break
                    }
                }
            }
            if ($externalCalendarEnabled) { break }
        }

        if (-not $externalCalendarEnabled) {
            Add-Result -ControlNumber "1.3.3" -ControlTitle "Ensure 'External sharing' of calendars is not available" `
                       -ProfileLevel "L2" -Result "Pass" -Details "External calendar sharing is disabled"
        }
        else {
            Add-Result -ControlNumber "1.3.3" -ControlTitle "Ensure 'External sharing' of calendars is not available" `
                       -ProfileLevel "L2" -Result "Fail" -Details "External calendar sharing is enabled in sharing policy" `
                       -Remediation "Set-SharingPolicy -Identity 'Default Sharing Policy' -Enabled `$false"
        }
    }
    catch {
        Add-Result -ControlNumber "1.3.3" -ControlTitle "Ensure 'External sharing' of calendars is not available" `
                   -ProfileLevel "L2" -Result "Manual" -Details "Unable to check sharing policy: $_. Check M365 Admin Center > Settings > Calendar" `
                   -Remediation "Disable external calendar sharing"
    }

    # 1.3.4 - Ensure 'User owned apps and services' is restricted
    try {
        Write-Log "Checking 1.3.4 - User owned apps and services" -Level Info
        # Try the nested settings endpoint first, fall back to parent endpoint
        $appsSettings = $null
        try {
            $appsSettings = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/admin/appsAndServices/settings" -ErrorAction Stop
        }
        catch {
            $appsResponse = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/admin/appsAndServices" -ErrorAction Stop
            $appsSettings = $appsResponse.settings
            if (-not $appsSettings) { $appsSettings = $appsResponse }
        }
        $storeDisabled = $appsSettings.isOfficeStoreEnabled -eq $false
        $trialDisabled = $appsSettings.isAppAndServicesTrialEnabled -eq $false

        if ($storeDisabled -and $trialDisabled) {
            Add-Result -ControlNumber "1.3.4" -ControlTitle "Ensure 'User owned apps and services' is restricted" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Office Store disabled, app trials disabled"
        }
        else {
            $issues = @()
            if (-not $storeDisabled) { $issues += "Office Store enabled" }
            if (-not $trialDisabled) { $issues += "App trials enabled" }
            Add-Result -ControlNumber "1.3.4" -ControlTitle "Ensure 'User owned apps and services' is restricted" `
                       -ProfileLevel "L1" -Result "Fail" -Details ($issues -join '; ') `
                       -Remediation "Disable user-owned apps in M365 Admin Center > Settings > Org Settings > User owned apps and services"
        }
    }
    catch {
        Add-Result -ControlNumber "1.3.4" -ControlTitle "Ensure 'User owned apps and services' is restricted" `
                   -ProfileLevel "L1" -Result "Manual" -Details "Unable to check app settings: $_" `
                   -Remediation "Check M365 Admin Center > Settings > Org Settings > User owned apps and services. Ensure OrgSettings-AppsAndServices.Read.All scope is consented."
    }

    # 1.3.5 - Ensure internal phishing protection for Forms is enabled
    try {
        Write-Log "Checking 1.3.5 - Forms phishing protection" -Level Info
        # Try nested settings endpoint first, fall back to parent endpoint
        $formsSettings = $null
        try {
            $formsSettings = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/admin/forms/settings" -ErrorAction Stop
        }
        catch {
            $formsResponse = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/admin/forms" -ErrorAction Stop
            $formsSettings = $formsResponse.settings
            if (-not $formsSettings) { $formsSettings = $formsResponse }
        }

        if ($formsSettings.isInOrgFormsPhishingScanEnabled -eq $true) {
            Add-Result -ControlNumber "1.3.5" -ControlTitle "Ensure internal phishing protection for Forms is enabled" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Internal phishing protection for Forms is enabled"
        }
        else {
            Add-Result -ControlNumber "1.3.5" -ControlTitle "Ensure internal phishing protection for Forms is enabled" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Internal phishing protection for Forms is disabled" `
                       -Remediation "Enable phishing protection in M365 Admin Center > Settings > Org Settings > Microsoft Forms"
        }
    }
    catch {
        Add-Result -ControlNumber "1.3.5" -ControlTitle "Ensure internal phishing protection for Forms is enabled" `
                   -ProfileLevel "L1" -Result "Manual" -Details "Unable to check Forms settings: $_" `
                   -Remediation "Check M365 Admin Center > Settings > Org Settings > Microsoft Forms. Ensure OrgSettings-Forms.Read.All scope is consented."
    }

    # 1.3.6 - Ensure the customer lockbox feature is enabled
    try {
        Write-Log "Checking 1.3.6 - Customer lockbox" -Level Info
        $orgConfig = Get-OrganizationConfig -ErrorAction Stop

        if ($orgConfig.CustomerLockBoxEnabled -eq $true) {
            Add-Result -ControlNumber "1.3.6" -ControlTitle "Ensure the customer lockbox feature is enabled" `
                       -ProfileLevel "L2" -Result "Pass" -Details "Customer Lockbox is enabled"
        }
        else {
            Add-Result -ControlNumber "1.3.6" -ControlTitle "Ensure the customer lockbox feature is enabled" `
                       -ProfileLevel "L2" -Result "Fail" -Details "Customer Lockbox is not enabled" `
                       -Remediation "Set-OrganizationConfig -CustomerLockBoxEnabled `$true (requires E5/G5 or Customer Lockbox add-on)"
        }
    }
    catch {
        Add-Result -ControlNumber "1.3.6" -ControlTitle "Ensure the customer lockbox feature is enabled" `
                   -ProfileLevel "L2" -Result "Manual" -Details "Unable to check Customer Lockbox: $_. Check M365 Admin Center > Settings > Org Settings > Security & Privacy > Customer Lockbox" `
                   -Remediation "Enable Customer Lockbox feature"
    }

    # 1.3.7 - Ensure 'third-party storage services' are restricted in 'Microsoft 365 on the web'
    try {
        Write-Log "Checking 1.3.7 - Third-party storage services" -Level Info
        $m365WebSP = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq 'c1f33bc0-bdb4-4248-ba9b-096807ddb43e'" -ErrorAction Stop

        if ($m365WebSP.value.Count -eq 0 -or $m365WebSP.value[0].accountEnabled -eq $false) {
            Add-Result -ControlNumber "1.3.7" -ControlTitle "Ensure 'third-party storage services' are restricted in 'Microsoft 365 on the web'" `
                       -ProfileLevel "L2" -Result "Pass" -Details "Third-party storage services are disabled for M365 on the web"
        }
        else {
            Add-Result -ControlNumber "1.3.7" -ControlTitle "Ensure 'third-party storage services' are restricted in 'Microsoft 365 on the web'" `
                       -ProfileLevel "L2" -Result "Fail" -Details "Third-party storage services are enabled for M365 on the web" `
                       -Remediation "Disable third-party storage in M365 Admin Center > Settings > Org Settings > Microsoft 365 on the web"
        }
    }
    catch {
        Add-Result -ControlNumber "1.3.7" -ControlTitle "Ensure 'third-party storage services' are restricted in 'Microsoft 365 on the web'" `
                   -ProfileLevel "L2" -Result "Manual" -Details "Unable to check third-party storage: $_" `
                   -Remediation "Check M365 Admin Center > Settings > Org Settings > Microsoft 365 on the web"
    }

    # 1.3.8 - Ensure that Sways cannot be shared with people outside of your organization
    Add-Result -ControlNumber "1.3.8" -ControlTitle "Ensure that Sways cannot be shared with people outside of your organization" `
               -ProfileLevel "L2" -Result "Manual" -Details "Check M365 Admin Center > Settings > Org Settings > Sway" `
               -Remediation "Disable external Sway sharing"

    # 1.3.9 - Ensure shared bookings pages are restricted to select users (NEW in v6.0.0)
    try {
        Write-Log "Checking 1.3.9 - Shared bookings page restrictions" -Level Info

        $orgConfig = Get-OrganizationConfig -ErrorAction Stop
        $owaPolicies = Get-OwaMailboxPolicy -ErrorAction Stop

        $bookingsEnabled = $orgConfig.BookingsEnabled
        $bookingsCreationPolicies = @($owaPolicies | Where-Object { $_.BookingsMailboxCreationEnabled -eq $true })
        $allPolicies = @($owaPolicies)

        if ($bookingsEnabled -eq $false) {
            Add-Result -ControlNumber "1.3.9" -ControlTitle "Ensure shared bookings pages are restricted to select users" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Microsoft Bookings is disabled organization-wide"
        }
        elseif ($bookingsCreationPolicies.Count -eq 0) {
            Add-Result -ControlNumber "1.3.9" -ControlTitle "Ensure shared bookings pages are restricted to select users" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Bookings mailbox creation is disabled in all $($allPolicies.Count) OWA mailbox policies"
        }
        elseif ($bookingsCreationPolicies.Count -lt $allPolicies.Count) {
            $enabledNames = ($bookingsCreationPolicies | ForEach-Object { $_.Name }) -join ', '
            Add-Result -ControlNumber "1.3.9" -ControlTitle "Ensure shared bookings pages are restricted to select users" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Bookings creation restricted to select policies ($($bookingsCreationPolicies.Count)/$($allPolicies.Count)): $enabledNames"
        }
        else {
            Add-Result -ControlNumber "1.3.9" -ControlTitle "Ensure shared bookings pages are restricted to select users" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Bookings mailbox creation is enabled in all $($allPolicies.Count) OWA mailbox policies - not restricted to select users" `
                       -Remediation "Set BookingsMailboxCreationEnabled to `$false on OWA mailbox policies, or disable Bookings via Set-OrganizationConfig -BookingsEnabled `$false"
        }
    }
    catch {
        Add-Result -ControlNumber "1.3.9" -ControlTitle "Ensure shared bookings pages are restricted to select users" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }
}

#endregion

#region Section 2: Microsoft 365 Defender

function Test-M365Defender {
    Write-Log "Checking Section 2: Microsoft 365 Defender..." -Level Info

    # Pre-fetch shared data for this section
    $cachedMalwareFilterPolicy = $null
    $cachedHostedContentFilterPolicy = $null
    $cachedAcceptedDomains = $null
    $cachedConnectionFilterPolicy = $null
    try { $cachedMalwareFilterPolicy = Get-MalwareFilterPolicy } catch { Write-Log "Warning: Could not retrieve MalwareFilterPolicy. Related checks will report errors." -Level Warning }
    try { $cachedHostedContentFilterPolicy = Get-HostedContentFilterPolicy } catch { Write-Log "Warning: Could not retrieve HostedContentFilterPolicy. Related checks will report errors." -Level Warning }
    try { $cachedConnectionFilterPolicy = Get-HostedConnectionFilterPolicy -Identity Default } catch { Write-Log "Warning: Could not retrieve ConnectionFilterPolicy. Related checks will report errors." -Level Warning }
    try { $cachedAcceptedDomains = Get-AcceptedDomain } catch { Write-Log "Warning: Could not retrieve AcceptedDomain. Related checks will report errors." -Level Warning }

    # 2.1.1 - Ensure Safe Links for Office Applications is Enabled
    try {
        Write-Log "Checking 2.1.1 - Safe Links for Office Applications" -Level Info
        $safeLinksPolicies = Get-SafeLinksPolicy
        $safeLinksEnabled = $false

        foreach ($policy in $safeLinksPolicies) {
            if ($policy.EnableSafeLinksForOffice -eq $true) {
                $safeLinksEnabled = $true
                break
            }
        }

        if ($safeLinksEnabled) {
            Add-Result -ControlNumber "2.1.1" -ControlTitle "Ensure Safe Links for Office Applications is Enabled" `
                       -ProfileLevel "L2" -Result "Pass" -Details "Safe Links for Office applications is enabled"
        }
        else {
            Add-Result -ControlNumber "2.1.1" -ControlTitle "Ensure Safe Links for Office Applications is Enabled" `
                       -ProfileLevel "L2" -Result "Fail" -Details "Safe Links for Office applications is not enabled" `
                       -Remediation "Enable Safe Links in a policy: Set-SafeLinksPolicy -EnableSafeLinksForOffice `$true"
        }
    }
    catch {
        Add-Result -ControlNumber "2.1.1" -ControlTitle "Ensure Safe Links for Office Applications is Enabled" `
                   -ProfileLevel "L2" -Result "Error" -Details "Error: $_"
    }

    # 2.1.2 - Ensure the Common Attachment Types Filter is enabled
    try {
        Write-Log "Checking 2.1.2 - Common Attachment Types Filter" -Level Info
        if ($null -eq $cachedMalwareFilterPolicy) { throw "MalwareFilterPolicy data unavailable" }
        $malwarePolicies = $cachedMalwareFilterPolicy
        $commonAttachmentsEnabled = $false

        foreach ($policy in $malwarePolicies) {
            if ($policy.EnableFileFilter -eq $true) {
                $commonAttachmentsEnabled = $true
                break
            }
        }

        if ($commonAttachmentsEnabled) {
            Add-Result -ControlNumber "2.1.2" -ControlTitle "Ensure the Common Attachment Types Filter is enabled" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Common attachment types filter is enabled"
        }
        else {
            Add-Result -ControlNumber "2.1.2" -ControlTitle "Ensure the Common Attachment Types Filter is enabled" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Common attachment types filter is not enabled" `
                       -Remediation "Enable common attachment filter: Set-MalwareFilterPolicy -EnableFileFilter `$true"
        }
    }
    catch {
        Add-Result -ControlNumber "2.1.2" -ControlTitle "Ensure the Common Attachment Types Filter is enabled" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 2.1.3 - Ensure notifications for internal users sending malware is Enabled
    try {
        Write-Log "Checking 2.1.3 - Malware notifications for internal users" -Level Info
        if ($null -eq $cachedMalwareFilterPolicy) { throw "MalwareFilterPolicy data unavailable" }
        $malwarePolicies = $cachedMalwareFilterPolicy
        $notificationsEnabled = $false

        foreach ($policy in $malwarePolicies) {
            if ($policy.EnableInternalSenderAdminNotifications -eq $true) {
                $notificationsEnabled = $true
                break
            }
        }

        if ($notificationsEnabled) {
            Add-Result -ControlNumber "2.1.3" -ControlTitle "Ensure notifications for internal users sending malware is Enabled" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Internal malware notifications enabled"
        }
        else {
            Add-Result -ControlNumber "2.1.3" -ControlTitle "Ensure notifications for internal users sending malware is Enabled" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Internal malware notifications not enabled" `
                       -Remediation "Enable notifications: Set-MalwareFilterPolicy -EnableInternalSenderAdminNotifications `$true"
        }
    }
    catch {
        Add-Result -ControlNumber "2.1.3" -ControlTitle "Ensure notifications for internal users sending malware is Enabled" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 2.1.4 - Ensure Safe Attachments policy is enabled
    try {
        Write-Log "Checking 2.1.4 - Safe Attachments policy" -Level Info
        $safeAttachmentPolicies = Get-SafeAttachmentPolicy

        if ($safeAttachmentPolicies.Count -gt 0) {
            $enabledPolicy = $safeAttachmentPolicies | Where-Object { $_.Enable -eq $true }
            if ($enabledPolicy) {
                Add-Result -ControlNumber "2.1.4" -ControlTitle "Ensure Safe Attachments policy is enabled" `
                           -ProfileLevel "L2" -Result "Pass" -Details "Safe Attachments policy is enabled"
            }
            else {
                Add-Result -ControlNumber "2.1.4" -ControlTitle "Ensure Safe Attachments policy is enabled" `
                           -ProfileLevel "L2" -Result "Fail" -Details "Safe Attachments policy exists but not enabled" `
                           -Remediation "Enable Safe Attachments policy"
            }
        }
        else {
            Add-Result -ControlNumber "2.1.4" -ControlTitle "Ensure Safe Attachments policy is enabled" `
                       -ProfileLevel "L2" -Result "Fail" -Details "No Safe Attachments policy found" `
                       -Remediation "Create and enable Safe Attachments policy"
        }
    }
    catch {
        Add-Result -ControlNumber "2.1.4" -ControlTitle "Ensure Safe Attachments policy is enabled" `
                   -ProfileLevel "L2" -Result "Error" -Details "Error: $_"
    }

    # 2.1.5 - Ensure Safe Attachments for SharePoint, OneDrive, and Microsoft Teams is Enabled
    try {
        Write-Log "Checking 2.1.5 - Safe Attachments for SPO/ODB/Teams" -Level Info
        $atpPolicy = Get-AtpPolicyForO365

        if ($atpPolicy.EnableATPForSPOTeamsODB -eq $true) {
            Add-Result -ControlNumber "2.1.5" -ControlTitle "Ensure Safe Attachments for SharePoint, OneDrive, and Microsoft Teams is Enabled" `
                       -ProfileLevel "L2" -Result "Pass" -Details "Safe Attachments enabled for SPO/ODB/Teams"
        }
        else {
            Add-Result -ControlNumber "2.1.5" -ControlTitle "Ensure Safe Attachments for SharePoint, OneDrive, and Microsoft Teams is Enabled" `
                       -ProfileLevel "L2" -Result "Fail" -Details "Safe Attachments not enabled for SPO/ODB/Teams" `
                       -Remediation "Set-AtpPolicyForO365 -EnableATPForSPOTeamsODB `$true"
        }
    }
    catch {
        Add-Result -ControlNumber "2.1.5" -ControlTitle "Ensure Safe Attachments for SharePoint, OneDrive, and Microsoft Teams is Enabled" `
                   -ProfileLevel "L2" -Result "Error" -Details "Error: $_"
    }

    # 2.1.6 - Ensure Exchange Online Spam Policies are set to notify administrators
    try {
        Write-Log "Checking 2.1.6 - Spam policy notifications" -Level Info
        $hostedOutboundPolicies = Get-HostedOutboundSpamFilterPolicy
        $notificationsConfigured = $false

        foreach ($policy in $hostedOutboundPolicies) {
            if ($policy.NotifyOutboundSpamRecipients -eq $true -or $policy.NotifyOutboundSpam -eq $true) {
                $notificationsConfigured = $true
                break
            }
        }

        if ($notificationsConfigured) {
            Add-Result -ControlNumber "2.1.6" -ControlTitle "Ensure Exchange Online Spam Policies are set to notify administrators" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Spam policy notifications configured"
        }
        else {
            Add-Result -ControlNumber "2.1.6" -ControlTitle "Ensure Exchange Online Spam Policies are set to notify administrators" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Spam policy notifications not configured" `
                       -Remediation "Configure admin notifications in spam filter policies"
        }
    }
    catch {
        Add-Result -ControlNumber "2.1.6" -ControlTitle "Ensure Exchange Online Spam Policies are set to notify administrators" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 2.1.7 - Ensure that an anti-phishing policy has been created
    try {
        Write-Log "Checking 2.1.7 - Anti-phishing policy" -Level Info
        $antiPhishPolicies = Get-AntiPhishPolicy

        if ($antiPhishPolicies.Count -gt 0) {
            Add-Result -ControlNumber "2.1.7" -ControlTitle "Ensure that an anti-phishing policy has been created" `
                       -ProfileLevel "L2" -Result "Pass" -Details "Anti-phishing policy exists"
        }
        else {
            Add-Result -ControlNumber "2.1.7" -ControlTitle "Ensure that an anti-phishing policy has been created" `
                       -ProfileLevel "L2" -Result "Fail" -Details "No anti-phishing policy found" `
                       -Remediation "Create an anti-phishing policy"
        }
    }
    catch {
        Add-Result -ControlNumber "2.1.7" -ControlTitle "Ensure that an anti-phishing policy has been created" `
                   -ProfileLevel "L2" -Result "Error" -Details "Error: $_"
    }

    # 2.1.8 - Ensure that SPF records are published for all Exchange Domains
    try {
        Write-Log "Checking 2.1.8 - SPF records" -Level Info
        $acceptedDomains = $cachedAcceptedDomains
        $missingSpf = @()

        foreach ($domain in $acceptedDomains) {
            if ($domain.DomainType -eq "Authoritative") {
                # Skip *.onmicrosoft.com domains - SPF is managed by Microsoft
                if ($domain.DomainName -like "*.onmicrosoft.com") {
                    Write-Log "Skipping $($domain.DomainName) - Microsoft-managed domain" -Level Info
                    continue
                }
                try {
                    $spfRecord = Resolve-DnsName -Name $domain.DomainName -Type TXT -ErrorAction SilentlyContinue |
                                 Where-Object { $_.Strings -like "*v=spf1*" }
                    if (-not $spfRecord) {
                        $missingSpf += $domain.DomainName
                    }
                }
                catch {
                    $missingSpf += $domain.DomainName
                }
            }
        }

        if ($missingSpf.Count -eq 0) {
            Add-Result -ControlNumber "2.1.8" -ControlTitle "Ensure that SPF records are published for all Exchange Domains" `
                       -ProfileLevel "L1" -Result "Pass" -Details "SPF records present for all domains"
        }
        else {
            Add-Result -ControlNumber "2.1.8" -ControlTitle "Ensure that SPF records are published for all Exchange Domains" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Missing SPF records for: $($missingSpf -join ', ')" `
                       -Remediation "Publish SPF records for all domains"
        }
    }
    catch {
        Add-Result -ControlNumber "2.1.8" -ControlTitle "Ensure that SPF records are published for all Exchange Domains" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 2.1.9 - Ensure that DKIM is enabled for all Exchange Online Domains
    try {
        Write-Log "Checking 2.1.9 - DKIM enabled" -Level Info
        $dkimConfigs = Get-DkimSigningConfig
        # Exclude *.onmicrosoft.com domains - DKIM is managed by Microsoft
        $disabledDkim = $dkimConfigs | Where-Object { $_.Enabled -eq $false -and $_.Domain -notlike "*.onmicrosoft.com" }

        if ($disabledDkim.Count -eq 0) {
            Add-Result -ControlNumber "2.1.9" -ControlTitle "Ensure that DKIM is enabled for all Exchange Online Domains" `
                       -ProfileLevel "L1" -Result "Pass" -Details "DKIM enabled for all domains"
        }
        else {
            $domains = $disabledDkim.Domain -join ', '
            Add-Result -ControlNumber "2.1.9" -ControlTitle "Ensure that DKIM is enabled for all Exchange Online Domains" `
                       -ProfileLevel "L1" -Result "Fail" -Details "DKIM not enabled for: $domains" `
                       -Remediation "Enable DKIM signing for all domains"
        }
    }
    catch {
        Add-Result -ControlNumber "2.1.9" -ControlTitle "Ensure that DKIM is enabled for all Exchange Online Domains" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 2.1.10 - Ensure DMARC Records for all Exchange Online domains are published
    try {
        Write-Log "Checking 2.1.10 - DMARC records" -Level Info
        $acceptedDomains = $cachedAcceptedDomains
        $missingDmarc = @()
        $skippedSubdomains = @()

        # Collect authoritative domains (excluding onmicrosoft.com)
        $authDomains = @($acceptedDomains | Where-Object {
            $_.DomainType -eq "Authoritative" -and $_.DomainName -notlike "*.onmicrosoft.com"
        })

        # First pass: resolve DMARC for all domains and build parent sp= lookup
        $dmarcCache = @{}
        foreach ($domain in $authDomains) {
            try {
                $dmarcRecord = Resolve-DnsName -Name "_dmarc.$($domain.DomainName)" -Type TXT -ErrorAction SilentlyContinue |
                               Where-Object { $_.Strings -like "*v=DMARC1*" }
                if ($dmarcRecord) {
                    $dmarcCache[$domain.DomainName] = ($dmarcRecord.Strings | Where-Object { $_ -like "*v=DMARC1*" }) -join " "
                }
            }
            catch {
                # DNS resolution failed - domain has no DMARC
            }
        }

        # Second pass: check each domain, skipping subdomains covered by parent sp= tag
        foreach ($domain in $authDomains) {
            $domainName = $domain.DomainName
            Write-Log "Checking DMARC for $domainName" -Level Info

            # Check if this is a subdomain and if the parent domain DMARC has sp= tag
            $parts = $domainName.Split('.')
            $isSubdomainCovered = $false
            if ($parts.Count -gt 2) {
                # Build parent domain (e.g., sub.example.com -> example.com)
                $parentDomain = ($parts[($parts.Count - 2)..($parts.Count - 1)]) -join '.'
                if ($dmarcCache.ContainsKey($parentDomain) -and $dmarcCache[$parentDomain] -match 'sp=') {
                    $isSubdomainCovered = $true
                    $skippedSubdomains += $domainName
                    Write-Log "Skipping $domainName - parent domain $parentDomain DMARC has sp= tag" -Level Info
                }
            }

            if (-not $isSubdomainCovered) {
                if (-not $dmarcCache.ContainsKey($domainName)) {
                    $missingDmarc += $domainName
                }
            }
        }

        $detailParts = @()
        if ($missingDmarc.Count -eq 0 -and $skippedSubdomains.Count -eq 0) {
            $detailParts += "DMARC records present for all domains"
        }
        elseif ($missingDmarc.Count -eq 0 -and $skippedSubdomains.Count -gt 0) {
            $detailParts += "DMARC records present for all domains ($($skippedSubdomains.Count) subdomain(s) covered by parent sp= policy: $($skippedSubdomains -join ', '))"
        }

        if ($missingDmarc.Count -eq 0) {
            Add-Result -ControlNumber "2.1.10" -ControlTitle "Ensure DMARC Records for all Exchange Online domains are published" `
                       -ProfileLevel "L1" -Result "Pass" -Details ($detailParts -join "; ")
        }
        else {
            $details = "Missing DMARC records for: $($missingDmarc -join ', ')"
            if ($skippedSubdomains.Count -gt 0) {
                $details += " (Subdomains covered by parent sp= policy: $($skippedSubdomains -join ', '))"
            }
            Add-Result -ControlNumber "2.1.10" -ControlTitle "Ensure DMARC Records for all Exchange Online domains are published" `
                       -ProfileLevel "L1" -Result "Fail" -Details $details `
                       -Remediation "Publish DMARC records for all domains: _dmarc.<domain> TXT 'v=DMARC1; p=reject; rua=mailto:dmarc@<domain>'"
        }
    }
    catch {
        Add-Result -ControlNumber "2.1.10" -ControlTitle "Ensure DMARC Records for all Exchange Online domains are published" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 2.1.11 - Ensure comprehensive attachment filtering is applied
    try {
        Write-Log "Checking 2.1.11 - Comprehensive attachment filtering" -Level Info
        if ($null -eq $cachedMalwareFilterPolicy) { throw "MalwareFilterPolicy data unavailable" }
        $malwarePolicies = $cachedMalwareFilterPolicy

        # Key dangerous file types per CIS Benchmark (representative subset for validation)
        $requiredBlockedTypes = @('ace','ani','app','docm','exe','jar','reg','scr','vbe','vbs','xlsm')

        # Collect policies with file filter enabled
        $enabledPolicies = @($malwarePolicies | Where-Object { $_.EnableFileFilter -eq $true -and $_.FileTypes })

        if ($enabledPolicies.Count -gt 0) {
            # Union all blocked file types across all active policies
            $allBlockedTypes = @()
            $policyNames = @()
            foreach ($policy in $enabledPolicies) {
                $allBlockedTypes += $policy.FileTypes
                $policyNames += $policy.Name
            }
            $allBlockedTypes = @($allBlockedTypes | Select-Object -Unique)

            $missingTypes = @($requiredBlockedTypes | Where-Object { $allBlockedTypes -notcontains $_ })

            if ($missingTypes.Count -eq 0) {
                Add-Result -ControlNumber "2.1.11" -ControlTitle "Ensure comprehensive attachment filtering is applied" `
                           -ProfileLevel "L2" -Result "Pass" -Details "Comprehensive attachment filtering configured across $($enabledPolicies.Count) policy/policies ($($policyNames -join ', ')). $($allBlockedTypes.Count) total file types blocked."
            }
            else {
                Add-Result -ControlNumber "2.1.11" -ControlTitle "Ensure comprehensive attachment filtering is applied" `
                           -ProfileLevel "L2" -Result "Fail" -Details "File filter enabled in $($enabledPolicies.Count) policy/policies but missing types across all policies combined: $($missingTypes -join ', ')" `
                           -Remediation "Add missing file types to a malware filter policy: Set-MalwareFilterPolicy -Identity '<PolicyName>' -FileTypes @{Add='$($missingTypes -join "','")' }"
            }
        }
        else {
            $policyCount = @($malwarePolicies).Count
            Add-Result -ControlNumber "2.1.11" -ControlTitle "Ensure comprehensive attachment filtering is applied" `
                       -ProfileLevel "L2" -Result "Fail" -Details "No malware filter policies have the file filter enabled ($policyCount policies found)" `
                       -Remediation "Enable the Common Attachment Types Filter: Set-MalwareFilterPolicy -Identity 'Default' -EnableFileFilter `$true"
        }
    }
    catch {
        Add-Result -ControlNumber "2.1.11" -ControlTitle "Ensure comprehensive attachment filtering is applied" `
                   -ProfileLevel "L2" -Result "Error" -Details "Error: $_"
    }

    # 2.1.12 - Ensure the connection filter IP allow list is not used
    try {
        Write-Log "Checking 2.1.12 - Connection filter IP allow list" -Level Info
        if ($null -eq $cachedConnectionFilterPolicy) { throw "ConnectionFilterPolicy data unavailable" }
        $connectionFilter = $cachedConnectionFilterPolicy

        if ($connectionFilter.IPAllowList.Count -eq 0) {
            Add-Result -ControlNumber "2.1.12" -ControlTitle "Ensure the connection filter IP allow list is not used" `
                       -ProfileLevel "L1" -Result "Pass" -Details "IP allow list is empty"
        }
        else {
            Add-Result -ControlNumber "2.1.12" -ControlTitle "Ensure the connection filter IP allow list is not used" `
                       -ProfileLevel "L1" -Result "Fail" -Details "IP allow list contains $($connectionFilter.IPAllowList.Count) entries" `
                       -Remediation "Remove all entries from IP allow list"
        }
    }
    catch {
        Add-Result -ControlNumber "2.1.12" -ControlTitle "Ensure the connection filter IP allow list is not used" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 2.1.13 - Ensure the connection filter safe list is off
    try {
        Write-Log "Checking 2.1.13 - Connection filter safe list" -Level Info
        if ($null -eq $cachedConnectionFilterPolicy) { throw "ConnectionFilterPolicy data unavailable" }
        $connectionFilter = $cachedConnectionFilterPolicy

        if ($connectionFilter.EnableSafeList -eq $false) {
            Add-Result -ControlNumber "2.1.13" -ControlTitle "Ensure the connection filter safe list is off" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Safe list is disabled"
        }
        else {
            Add-Result -ControlNumber "2.1.13" -ControlTitle "Ensure the connection filter safe list is off" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Safe list is enabled" `
                       -Remediation "Set-HostedConnectionFilterPolicy -Identity Default -EnableSafeList `$false"
        }
    }
    catch {
        Add-Result -ControlNumber "2.1.13" -ControlTitle "Ensure the connection filter safe list is off" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 2.1.14 - Ensure inbound anti-spam policies do not contain allowed domains
    try {
        Write-Log "Checking 2.1.14 - Anti-spam allowed domains" -Level Info
        if ($null -eq $cachedHostedContentFilterPolicy) { throw "HostedContentFilterPolicy data unavailable" }
        $contentFilters = $cachedHostedContentFilterPolicy
        $policiesWithAllowedItems = @()
        $totalAllowedDomains = 0
        $totalAllowedSenders = 0

        foreach ($policy in $contentFilters) {
            $domainCount = if ($policy.AllowedSenderDomains) { @($policy.AllowedSenderDomains).Count } else { 0 }
            $senderCount = if ($policy.AllowedSenders) { @($policy.AllowedSenders).Count } else { 0 }

            if ($domainCount -gt 0 -or $senderCount -gt 0) {
                $totalAllowedDomains += $domainCount
                $totalAllowedSenders += $senderCount

                $policyInfo = "$($policy.Name): $domainCount domain(s), $senderCount sender(s)"
                $policiesWithAllowedItems += $policyInfo
            }
        }

        if ($policiesWithAllowedItems.Count -eq 0) {
            Add-Result -ControlNumber "2.1.14" -ControlTitle "Ensure inbound anti-spam policies do not contain allowed domains" `
                       -ProfileLevel "L1" -Result "Pass" -Details "No allowed domains/senders configured in anti-spam policies"
        }
        else {
            # CIS Benchmark requires zero allowed domains/senders for maximum security
            # However, some organizations may have legitimate business needs for trusted partners
            $failDetails = "Found $totalAllowedDomains allowed domain(s) and $totalAllowedSenders allowed sender(s) across $($policiesWithAllowedItems.Count) policy/policies. " +
                          "Details: $($policiesWithAllowedItems -join '; '). " +
                          "Note: CIS recommends zero allowed domains/senders. Review each entry to ensure it's required for business operations."

            Add-Result -ControlNumber "2.1.14" -ControlTitle "Ensure inbound anti-spam policies do not contain allowed domains" `
                       -ProfileLevel "L1" -Result "Fail" -Details $failDetails `
                       -Remediation "Review and remove unnecessary allowed domains/senders from anti-spam policies. Only keep entries essential for business operations."
        }
    }
    catch {
        Add-Result -ControlNumber "2.1.14" -ControlTitle "Ensure inbound anti-spam policies do not contain allowed domains" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 2.2.1 - Ensure emergency access account activity is monitored
    Add-Result -ControlNumber "2.2.1" -ControlTitle "Ensure emergency access account activity is monitored" `
               -ProfileLevel "L1" -Result "Manual" -Details "Configure Cloud App Security alerts for emergency account usage" `
               -Remediation "Set up monitoring and alerts for emergency access accounts"

    # 2.4.1 - Ensure Priority account protection is enabled and configured
    try {
        Write-Log "Checking 2.4.1 - Priority account protection" -Level Info
        $eopRules = @(Get-EOPProtectionPolicyRule -ErrorAction Stop)
        $atpRules = @(Get-ATPProtectionPolicyRule -ErrorAction Stop)

        $eopEnabled = $eopRules | Where-Object { $_.State -eq "Enabled" }
        $atpEnabled = $atpRules | Where-Object { $_.State -eq "Enabled" }

        if ($eopEnabled -and $atpEnabled) {
            Add-Result -ControlNumber "2.4.1" -ControlTitle "Ensure Priority account protection is enabled and configured" `
                       -ProfileLevel "L1" -Result "Pass" -Details "EOP and ATP protection policy rules are enabled"
        }
        else {
            $missing = @()
            if (-not $eopEnabled) { $missing += "EOP protection rules" }
            if (-not $atpEnabled) { $missing += "ATP protection rules" }
            Add-Result -ControlNumber "2.4.1" -ControlTitle "Ensure Priority account protection is enabled and configured" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Missing: $($missing -join ', ')" `
                       -Remediation "Configure priority account protection in M365 Defender portal > Email & collaboration"
        }
    }
    catch {
        Add-Result -ControlNumber "2.4.1" -ControlTitle "Ensure Priority account protection is enabled and configured" `
                   -ProfileLevel "L1" -Result "Manual" -Details "Unable to check protection policies: $_" `
                   -Remediation "Verify in M365 Defender portal > Email & collaboration > Priority account protection"
    }

    # 2.4.2 - Ensure Priority accounts have 'Strict protection' presets applied
    try {
        Write-Log "Checking 2.4.2 - Strict preset for priority accounts" -Level Info
        $strictEOP = Get-EOPProtectionPolicyRule -Identity "Strict Preset Security Policy" -ErrorAction Stop
        $strictATP = Get-ATPProtectionPolicyRule -Identity "Strict Preset Security Policy" -ErrorAction Stop

        $strictEnabled = ($strictEOP.State -eq "Enabled") -and ($strictATP.State -eq "Enabled")
        $hasTargets = ($strictEOP.SentTo -or $strictEOP.SentToMemberOf) -and
                      ($strictATP.SentTo -or $strictATP.SentToMemberOf)

        if ($strictEnabled -and $hasTargets) {
            Add-Result -ControlNumber "2.4.2" -ControlTitle "Ensure Priority accounts have 'Strict protection' presets applied" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Strict Preset Security Policy is enabled and targets configured"
        }
        elseif ($strictEnabled -and -not $hasTargets) {
            Add-Result -ControlNumber "2.4.2" -ControlTitle "Ensure Priority accounts have 'Strict protection' presets applied" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Strict Preset enabled but no priority accounts/groups targeted" `
                       -Remediation "Add priority accounts to Strict Preset Security Policy targets"
        }
        else {
            Add-Result -ControlNumber "2.4.2" -ControlTitle "Ensure Priority accounts have 'Strict protection' presets applied" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Strict Preset Security Policy not enabled" `
                       -Remediation "Enable Strict Preset Security Policy and apply to priority accounts"
        }
    }
    catch {
        Add-Result -ControlNumber "2.4.2" -ControlTitle "Ensure Priority accounts have 'Strict protection' presets applied" `
                   -ProfileLevel "L1" -Result "Manual" -Details "Unable to check Strict Preset policy: $_" `
                   -Remediation "Verify strict protection preset is applied to priority accounts in M365 Defender"
    }

    # 2.4.3 - Ensure Microsoft Defender for Cloud Apps is enabled and configured
    Add-Result -ControlNumber "2.4.3" -ControlTitle "Ensure Microsoft Defender for Cloud Apps is enabled and configured" `
               -ProfileLevel "L2" -Result "Manual" -Details "Verify Defender for Cloud Apps configuration in M365 Defender portal" `
               -Remediation "Enable and configure Microsoft Defender for Cloud Apps"

    # 2.4.4 - Ensure Zero-hour auto purge for Microsoft Teams is on
    try {
        Write-Log "Checking 2.4.4 - Zero-hour auto purge for Teams" -Level Info
        $teamsProtectionPolicy = Get-TeamsProtectionPolicy

        if ($teamsProtectionPolicy.ZapEnabled -eq $true) {
            Add-Result -ControlNumber "2.4.4" -ControlTitle "Ensure Zero-hour auto purge for Microsoft Teams is on" `
                       -ProfileLevel "L1" -Result "Pass" -Details "ZAP for Teams messages is enabled"
        }
        else {
            Add-Result -ControlNumber "2.4.4" -ControlTitle "Ensure Zero-hour auto purge for Microsoft Teams is on" `
                       -ProfileLevel "L1" -Result "Fail" -Details "ZAP for Teams messages is disabled" `
                       -Remediation "Set-TeamsProtectionPolicy -ZapEnabled `$true"
        }
    }
    catch {
        Add-Result -ControlNumber "2.4.4" -ControlTitle "Ensure Zero-hour auto purge for Microsoft Teams is on" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_ - Requires Defender for Office 365 Plan 2" `
                   -Remediation "Enable Defender for Office 365 Plan 2 and configure Teams protection policy"
    }

    # 2.1.15 - Ensure outbound anti-spam message limits are in place (NEW in v6.0.0)
    try {
        Write-Log "Checking 2.1.15 - Outbound anti-spam message limits" -Level Info
        $outboundSpam = Get-HostedOutboundSpamFilterPolicy -ErrorAction Stop
        $defaultPolicy = $outboundSpam | Where-Object { $_.IsDefault -eq $true }
        if (-not $defaultPolicy) { $defaultPolicy = $outboundSpam | Select-Object -First 1 }

        if ($defaultPolicy) {
            $extLimit = $defaultPolicy.RecipientLimitExternalPerHour
            $intLimit = $defaultPolicy.RecipientLimitInternalPerHour
            $dayLimit = $defaultPolicy.RecipientLimitPerDay
            $action = $defaultPolicy.ActionWhenThresholdReached

            $hasLimits = ($extLimit -gt 0) -and ($intLimit -gt 0) -and ($dayLimit -gt 0)
            $blocksUser = ($action -eq "BlockUser" -or $action -eq "BlockUserForToday")

            if ($hasLimits -and $blocksUser) {
                Add-Result -ControlNumber "2.1.15" -ControlTitle "Ensure outbound anti-spam message limits are in place" `
                           -ProfileLevel "L1" -Result "Pass" -Details "Limits: External/hr=$extLimit, Internal/hr=$intLimit, Daily=$dayLimit, Action=$action"
            }
            else {
                Add-Result -ControlNumber "2.1.15" -ControlTitle "Ensure outbound anti-spam message limits are in place" `
                           -ProfileLevel "L1" -Result "Fail" -Details "Limits: External/hr=$extLimit, Internal/hr=$intLimit, Daily=$dayLimit, Action=$action" `
                           -Remediation "Set outbound spam limits and set ActionWhenThresholdReached to BlockUser"
            }
        }
        else {
            Add-Result -ControlNumber "2.1.15" -ControlTitle "Ensure outbound anti-spam message limits are in place" `
                       -ProfileLevel "L1" -Result "Fail" -Details "No outbound spam filter policy found" `
                       -Remediation "Configure outbound spam filter policy with message limits"
        }
    }
    catch {
        Add-Result -ControlNumber "2.1.15" -ControlTitle "Ensure outbound anti-spam message limits are in place" `
                   -ProfileLevel "L1" -Result "Manual" -Details "Unable to check outbound spam policy: $_" `
                   -Remediation "Check Microsoft Defender Portal > Policies > Anti-spam > Outbound policy"
    }
}

#endregion

#region Section 3: Microsoft Purview

function Test-Purview {
    Write-Log "Checking Section 3: Microsoft Purview..." -Level Info

    # 3.1.1 - Ensure Microsoft 365 audit log search is Enabled
    try {
        Write-Log "Checking 3.1.1 - Audit log search enabled" -Level Info
        $auditConfig = Get-AdminAuditLogConfig

        if ($auditConfig.UnifiedAuditLogIngestionEnabled -eq $true) {
            Add-Result -ControlNumber "3.1.1" -ControlTitle "Ensure Microsoft 365 audit log search is Enabled" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Unified audit logging is enabled"
        }
        else {
            Add-Result -ControlNumber "3.1.1" -ControlTitle "Ensure Microsoft 365 audit log search is Enabled" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Unified audit logging is not enabled" `
                       -Remediation "Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled `$true"
        }
    }
    catch {
        Add-Result -ControlNumber "3.1.1" -ControlTitle "Ensure Microsoft 365 audit log search is Enabled" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 3.2.1 - Ensure DLP policies are enabled
    try {
        Write-Log "Checking 3.2.1 - DLP policies enabled" -Level Info
        # DLP cmdlets require Security & Compliance connection, try to get policies
        try {
            $dlpPolicies = Get-DlpCompliancePolicy -ErrorAction Stop
            $enabledDlpPolicies = $dlpPolicies | Where-Object { $_.Enabled -eq $true }

            if ($enabledDlpPolicies.Count -gt 0) {
                Add-Result -ControlNumber "3.2.1" -ControlTitle "Ensure DLP policies are enabled" `
                           -ProfileLevel "L1" -Result "Pass" -Details "$($enabledDlpPolicies.Count) DLP policies enabled"
            }
            else {
                Add-Result -ControlNumber "3.2.1" -ControlTitle "Ensure DLP policies are enabled" `
                           -ProfileLevel "L1" -Result "Fail" -Details "No enabled DLP policies found" `
                           -Remediation "Create and enable DLP policies"
            }
        }
        catch {
            # If Get-DlpCompliancePolicy cmdlet not available, mark as Manual
            Add-Result -ControlNumber "3.2.1" -ControlTitle "Ensure DLP policies are enabled" `
                       -ProfileLevel "L1" -Result "Manual" -Details "DLP cmdlets not available. Verify in Microsoft Purview > Data loss prevention" `
                       -Remediation "Connect to Security & Compliance PowerShell or verify DLP policies in Microsoft Purview portal"
        }
    }
    catch {
        Add-Result -ControlNumber "3.2.1" -ControlTitle "Ensure DLP policies are enabled" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 3.2.2 - Ensure DLP policies are enabled for Microsoft Teams
    try {
        Write-Log "Checking 3.2.2 - DLP for Teams" -Level Info
        try {
            $dlpPolicies = Get-DlpCompliancePolicy -ErrorAction Stop
            $teamsDlpEnabled = $false

            foreach ($policy in $dlpPolicies) {
                if ($policy.TeamsLocation -ne $null -and $policy.Enabled -eq $true) {
                    $teamsDlpEnabled = $true
                    break
                }
            }

            if ($teamsDlpEnabled) {
                Add-Result -ControlNumber "3.2.2" -ControlTitle "Ensure DLP policies are enabled for Microsoft Teams" `
                           -ProfileLevel "L1" -Result "Pass" -Details "DLP enabled for Teams"
            }
            else {
                Add-Result -ControlNumber "3.2.2" -ControlTitle "Ensure DLP policies are enabled for Microsoft Teams" `
                           -ProfileLevel "L1" -Result "Fail" -Details "DLP not enabled for Teams" `
                           -Remediation "Enable DLP policies for Teams location"
            }
        }
        catch {
            # If Get-DlpCompliancePolicy cmdlet not available, mark as Manual
            Add-Result -ControlNumber "3.2.2" -ControlTitle "Ensure DLP policies are enabled for Microsoft Teams" `
                       -ProfileLevel "L1" -Result "Manual" -Details "DLP cmdlets not available. Verify in Microsoft Purview > Data loss prevention" `
                       -Remediation "Connect to Security & Compliance PowerShell or verify DLP policies in Microsoft Purview portal"
        }
    }
    catch {
        Add-Result -ControlNumber "3.2.2" -ControlTitle "Ensure DLP policies are enabled for Microsoft Teams" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 3.3.1 - Ensure Information Protection sensitivity label policies are published
    try {
        Write-Log "Checking 3.3.1 - Sensitivity label policies" -Level Info
        try {
            $labelPolicies = Get-LabelPolicy -ErrorAction Stop
            if ($labelPolicies.Count -gt 0) {
                $enabledPolicies = @($labelPolicies | Where-Object { $_.Mode -ne "PendingDeletion" })
                if ($enabledPolicies.Count -gt 0) {
                    $policyNames = ($enabledPolicies | Select-Object -ExpandProperty Name) -join ', '
                    Add-Result -ControlNumber "3.3.1" -ControlTitle "Ensure Information Protection sensitivity label policies are published" `
                               -ProfileLevel "L1" -Result "Pass" -Details "Sensitivity label policies published: $policyNames"
                }
                else {
                    Add-Result -ControlNumber "3.3.1" -ControlTitle "Ensure Information Protection sensitivity label policies are published" `
                               -ProfileLevel "L1" -Result "Fail" -Details "No active sensitivity label policies found" `
                               -Remediation "Create and publish sensitivity label policies in Microsoft Purview > Information Protection"
                }
            }
            else {
                Add-Result -ControlNumber "3.3.1" -ControlTitle "Ensure Information Protection sensitivity label policies are published" `
                           -ProfileLevel "L1" -Result "Fail" -Details "No sensitivity label policies found" `
                           -Remediation "Create and publish sensitivity label policies in Microsoft Purview > Information Protection"
            }
        }
        catch {
            Add-Result -ControlNumber "3.3.1" -ControlTitle "Ensure Information Protection sensitivity label policies are published" `
                       -ProfileLevel "L1" -Result "Manual" -Details "Unable to check sensitivity labels: $_. Connect to S&C PowerShell or verify in Purview portal." `
                       -Remediation "Verify sensitivity labels in Microsoft Purview > Information Protection"
        }
    }
    catch {
        Add-Result -ControlNumber "3.3.1" -ControlTitle "Ensure Information Protection sensitivity label policies are published" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }
}

#endregion

#region Section 4: Microsoft Intune Admin Center

function Test-Intune {
    Write-Log "Checking Section 4: Microsoft Intune Admin Center..." -Level Info

    # 4.1 - Ensure devices without a compliance policy are marked 'not compliant'
    try {
        Write-Log "Checking 4.1 - Non-compliant device marking" -Level Info
        # Check the actual compliance policy setting that controls what happens to devices without a policy
        # The setting "markDevicesWithNoCompliancePolicyAsCompliant" must be set to "nonCompliant"
        $deviceManagementSettings = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/settings" -ErrorAction Stop

        # The key setting: devices with no compliance policy should be marked as "nonCompliant"
        $markAsNonCompliant = $false
        if ($deviceManagementSettings.deviceComplianceCheckinThresholdDays -or $deviceManagementSettings -is [hashtable]) {
            # Check the secureByDefault property - when true, devices without policy are non-compliant
            if ($deviceManagementSettings.secureByDefault -eq $true) {
                $markAsNonCompliant = $true
            }
        }

        if (-not $markAsNonCompliant) {
            # Fallback: check via the compliance policy setting state summaries for the specific setting
            try {
                $complianceDefaults = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies" -ErrorAction Stop
                $hasCompliancePolicies = @($complianceDefaults.value).Count -gt 0

                if ($hasCompliancePolicies) {
                    # Policies exist but we cannot confirm the default marking behavior via API
                    Add-Result -ControlNumber "4.1" -ControlTitle "Ensure devices without a compliance policy are marked 'not compliant'" `
                               -ProfileLevel "L2" -Result "Manual" `
                               -Details "Compliance policies exist ($(@($complianceDefaults.value).Count) found) but the default device compliance setting cannot be fully verified via API. Verify manually that 'Mark devices with no compliance policy assigned as' is set to 'Not compliant'." `
                               -Remediation "Intune Admin Center > Devices > Compliance policies > Compliance policy settings > Set 'Mark devices with no compliance policy assigned as' to 'Not compliant'"
                }
                else {
                    Add-Result -ControlNumber "4.1" -ControlTitle "Ensure devices without a compliance policy are marked 'not compliant'" `
                               -ProfileLevel "L2" -Result "Fail" -Details "No compliance policies found in Intune" `
                               -Remediation "Create compliance policies and set 'Mark devices with no compliance policy assigned as' to 'Not compliant' in Intune > Devices > Compliance policies > Compliance policy settings"
                }
            }
            catch {
                Add-Result -ControlNumber "4.1" -ControlTitle "Ensure devices without a compliance policy are marked 'not compliant'" `
                           -ProfileLevel "L2" -Result "Manual" -Details "Unable to fully verify compliance policy default setting via API. Verify manually." `
                           -Remediation "Intune Admin Center > Devices > Compliance policies > Compliance policy settings > Verify 'Mark devices with no compliance policy assigned as' is set to 'Not compliant'"
            }
        }
        else {
            Add-Result -ControlNumber "4.1" -ControlTitle "Ensure devices without a compliance policy are marked 'not compliant'" `
                       -ProfileLevel "L2" -Result "Pass" -Details "Devices without a compliance policy are marked as not compliant (secureByDefault enabled)"
        }
    }
    catch {
        Add-Result -ControlNumber "4.1" -ControlTitle "Ensure devices without a compliance policy are marked 'not compliant'" `
                   -ProfileLevel "L2" -Result "Manual" -Details "Unable to check Intune compliance policy settings via Graph API: $_. Verify manually." `
                   -Remediation "Intune Admin Center > Devices > Compliance policies > Compliance policy settings > Verify 'Mark devices with no compliance policy assigned as' is set to 'Not compliant'"
    }

    # 4.2 - Ensure device enrollment for personally owned devices is blocked by default
    try {
        Write-Log "Checking 4.2 - Personal device enrollment restrictions" -Level Info
        $enrollmentRestrictions = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations" -ErrorAction Stop

        $restrictionPolicies = @($enrollmentRestrictions.value | Where-Object {
            $_.'@odata.type' -eq '#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration'
        })

        if ($restrictionPolicies.Count -gt 0) {
            # Check if personal devices are actually blocked in the restriction policies
            $personalBlocked = $true
            $platformDetails = @()

            foreach ($policy in $restrictionPolicies) {
                # Check each platform's personalDeviceEnrollmentBlocked setting
                $platforms = @('iosRestriction', 'androidRestriction', 'windowsRestriction', 'macOSRestriction', 'androidForWorkRestriction')
                foreach ($platform in $platforms) {
                    $restriction = $policy.$platform
                    if ($restriction -and $restriction.personalDeviceEnrollmentBlocked -eq $false) {
                        $personalBlocked = $false
                        $platformDetails += "$platform allows personal devices"
                    }
                }
            }

            if ($personalBlocked) {
                Add-Result -ControlNumber "4.2" -ControlTitle "Ensure device enrollment for personally owned devices is blocked by default" `
                           -ProfileLevel "L2" -Result "Pass" -Details "Personal device enrollment is blocked across all platforms ($($restrictionPolicies.Count) restriction policies)"
            }
            else {
                Add-Result -ControlNumber "4.2" -ControlTitle "Ensure device enrollment for personally owned devices is blocked by default" `
                           -ProfileLevel "L2" -Result "Fail" -Details "Personal device enrollment not blocked: $($platformDetails -join '; ')" `
                           -Remediation "Intune Admin Center > Devices > Enrollment restrictions > Edit default platform restriction > Block personally owned devices for all platforms"
            }
        }
        else {
            Add-Result -ControlNumber "4.2" -ControlTitle "Ensure device enrollment for personally owned devices is blocked by default" `
                       -ProfileLevel "L2" -Result "Fail" -Details "No enrollment restriction policies configured" `
                       -Remediation "Configure enrollment restrictions to block personally owned devices in Intune > Devices > Enrollment restrictions"
        }
    }
    catch {
        Add-Result -ControlNumber "4.2" -ControlTitle "Ensure device enrollment for personally owned devices is blocked by default" `
                   -ProfileLevel "L2" -Result "Manual" -Details "Unable to check enrollment restrictions: $_. Verify manually." `
                   -Remediation "Intune Admin Center > Devices > Enrollment restrictions > Verify personally owned devices are blocked"
    }
}

#endregion

#region Section 5: Microsoft Entra Admin Center

function Test-EntraID {
    Write-Log "Checking Section 5: Microsoft Entra Admin Center..." -Level Info

    # Pre-fetch shared data for this section
    $cachedCAPolicies = $null
    $cachedAuthPolicy = $null
    try { $cachedCAPolicies = Get-MgIdentityConditionalAccessPolicy -All } catch { Write-Log "Warning: Could not retrieve Conditional Access policies. Related checks will report errors." -Level Warning }
    try { $cachedAuthPolicy = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop } catch { Write-Log "Warning: Could not retrieve Authorization Policy. Related checks will report errors." -Level Warning }
    $cachedDeviceRegPolicy = $null
    try { $cachedDeviceRegPolicy = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/policies/deviceRegistrationPolicy" -ErrorAction Stop } catch { Write-Log "Warning: Could not retrieve Device Registration Policy. Related checks will report errors." -Level Warning }
    $cachedBetaAuthPolicy = $null
    try { $cachedBetaAuthPolicy = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/policies/authorizationPolicy" -ErrorAction Stop } catch { Write-Log "Warning: Could not retrieve beta Authorization Policy." -Level Warning }

    # 5.1.2.1 - Ensure 'Per-user MFA' is disabled
    try {
        Write-Log "Checking 5.1.2.1 - Per-user MFA disabled" -Level Info

        # Try bulk filter first (works in some tenants), fall back to sampled per-user check
        $perUserMfaUsers = @()
        $bulkWorked = $false
        try {
            $perUserUri = "https://graph.microsoft.com/beta/users?`$count=true&`$filter=perUserMfaState eq 'enforced' or perUserMfaState eq 'enabled'&`$select=id,displayName,userPrincipalName"
            $perUserResponse = Invoke-MgGraphRequest -Uri $perUserUri -Method GET -Headers @{ "ConsistencyLevel" = "eventual" }
            $perUserMfaUsers = @($perUserResponse.value)
            while ($perUserResponse.'@odata.nextLink') {
                $perUserResponse = Invoke-MgGraphRequest -Uri $perUserResponse.'@odata.nextLink' -Method GET -Headers @{ "ConsistencyLevel" = "eventual" }
                $perUserMfaUsers += $perUserResponse.value
            }
            $bulkWorked = $true
        }
        catch {
            # Bulk filter not available - sample first 50 users via per-user endpoint
            Write-Log "Bulk perUserMfaState filter unavailable, sampling users via authentication/requirements..." -Level Info
            try {
                $usersUri = "https://graph.microsoft.com/v1.0/users?`$select=id,userPrincipalName&`$top=50"
                $usersResponse = Invoke-MgGraphRequest -Uri $usersUri -Method GET
                $sampleUsers = @($usersResponse.value)

                foreach ($user in $sampleUsers) {
                    try {
                        $req = Invoke-MgGraphRequest -Method GET `
                            -Uri "https://graph.microsoft.com/beta/users/$($user.id)/authentication/requirements" `
                            -ErrorAction Stop
                        if ($req.perUserMfaState -in @('enforced','enabled')) {
                            $perUserMfaUsers += [PSCustomObject]@{
                                userPrincipalName = $user.userPrincipalName
                                perUserMfaState = $req.perUserMfaState
                            }
                        }
                    } catch { continue }
                }
                $bulkWorked = $true
            }
            catch {
                Write-Log "Per-user authentication requirements endpoint also failed: $_" -Level Warning
            }
        }

        if ($bulkWorked) {
            if ($perUserMfaUsers.Count -eq 0) {
                Add-Result -ControlNumber "5.1.2.1" -ControlTitle "Ensure 'Per-user MFA' is disabled" `
                           -ProfileLevel "L1" -Result "Pass" -Details "No per-user MFA enabled (use Conditional Access instead)"
            }
            else {
                $sample = ($perUserMfaUsers | Select-Object -First 5 | ForEach-Object { $_.userPrincipalName }) -join ", "
                Add-Result -ControlNumber "5.1.2.1" -ControlTitle "Ensure 'Per-user MFA' is disabled" `
                           -ProfileLevel "L1" -Result "Fail" -Details "$($perUserMfaUsers.Count) users have per-user MFA enabled (e.g. $sample)" `
                           -Remediation "Disable per-user MFA and use Conditional Access policies instead"
            }
        }
        else {
            Add-Result -ControlNumber "5.1.2.1" -ControlTitle "Ensure 'Per-user MFA' is disabled" `
                       -ProfileLevel "L1" -Result "Manual" `
                       -Details "Per-user MFA state could not be checked via Graph API. Verify manually in Azure Portal." `
                       -Remediation "Check Azure Portal: Entra ID > Users > Per-user MFA. Disable per-user MFA and use Conditional Access policies instead."
        }
    }
    catch {
        Add-Result -ControlNumber "5.1.2.1" -ControlTitle "Ensure 'Per-user MFA' is disabled" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 5.1.2.2 - Ensure third party integrated applications are not allowed
    try {
        Write-Log "Checking 5.1.2.2 - Third party app registration" -Level Info
        if ($null -eq $cachedAuthPolicy) { throw "Authorization policy data unavailable" }
        $authPolicy = $cachedAuthPolicy

        if ($authPolicy.DefaultUserRolePermissions.AllowedToCreateApps -eq $false) {
            Add-Result -ControlNumber "5.1.2.2" -ControlTitle "Ensure third party integrated applications are not allowed" `
                       -ProfileLevel "L2" -Result "Pass" -Details "Users cannot register apps"
        }
        else {
            Add-Result -ControlNumber "5.1.2.2" -ControlTitle "Ensure third party integrated applications are not allowed" `
                       -ProfileLevel "L2" -Result "Fail" -Details "Users can register applications" `
                       -Remediation "Update-MgPolicyAuthorizationPolicy -DefaultUserRolePermissions @{AllowedToCreateApps=`$false}"
        }
    }
    catch {
        Add-Result -ControlNumber "5.1.2.2" -ControlTitle "Ensure third party integrated applications are not allowed" `
                   -ProfileLevel "L2" -Result "Error" -Details "Error: $_"
    }

    # 5.1.2.3 - Ensure 'Restrict non-admin users from creating tenants' is set to 'Yes'
    try {
        Write-Log "Checking 5.1.2.3 - Restrict tenant creation" -Level Info
        if ($null -eq $cachedAuthPolicy) { throw "Authorization policy data unavailable" }
        $authPolicy = $cachedAuthPolicy

        if ($authPolicy.DefaultUserRolePermissions.AllowedToCreateTenants -eq $false) {
            Add-Result -ControlNumber "5.1.2.3" -ControlTitle "Ensure 'Restrict non-admin users from creating tenants' is set to 'Yes'" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Tenant creation restricted"
        }
        else {
            Add-Result -ControlNumber "5.1.2.3" -ControlTitle "Ensure 'Restrict non-admin users from creating tenants' is set to 'Yes'" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Users can create tenants" `
                       -Remediation "Update-MgPolicyAuthorizationPolicy to restrict tenant creation"
        }
    }
    catch {
        Add-Result -ControlNumber "5.1.2.3" -ControlTitle "Ensure 'Restrict non-admin users from creating tenants' is set to 'Yes'" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 5.1.2.4 - Ensure access to the Entra admin center is restricted
    try {
        Write-Log "Checking 5.1.2.4 - Restrict Entra admin center access" -Level Info
        if ($null -eq $cachedBetaAuthPolicy) { throw "Beta authorization policy data unavailable" }
        $restrictNonAdmin = $cachedBetaAuthPolicy.defaultUserRolePermissions.allowedToReadOtherUsers
        if ($restrictNonAdmin -eq $false) {
            Add-Result -ControlNumber "5.1.2.4" -ControlTitle "Ensure access to the Entra admin center is restricted" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Non-admin access to Entra admin center is restricted"
        }
        else {
            Add-Result -ControlNumber "5.1.2.4" -ControlTitle "Ensure access to the Entra admin center is restricted" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Non-admin users can access the Entra admin center" `
                       -Remediation "Restrict access in Entra Admin Center > Users > User settings > 'Restrict access to Microsoft Entra admin center' = Yes"
        }
    }
    catch {
        Add-Result -ControlNumber "5.1.2.4" -ControlTitle "Ensure access to the Entra admin center is restricted" `
                   -ProfileLevel "L1" -Result "Manual" -Details "Unable to check: $_" `
                   -Remediation "Check Entra Admin Center > Identity > Users > User settings > 'Restrict access to Microsoft Entra admin center'"
    }

    # 5.1.2.5 - Ensure the option to remain signed in is hidden
    try {
        Write-Log "Checking 5.1.2.5 - Stay signed in option hidden" -Level Info

        $kmsiHidden = $false
        $detailMsg = ""

        # Method 1: Check organization branding via Graph API
        try {
            $brandingResponse = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/organization/$($(Get-MgOrganization | Select-Object -First 1).Id)/branding" -ErrorAction Stop
            if ($brandingResponse.signInPageText.isKmsiHidden -eq $true) {
                $kmsiHidden = $true
                $detailMsg = "KMSI is hidden via organization branding (signInPageText.isKmsiHidden = true)"
            }
            elseif ($null -ne $brandingResponse.signInPageText) {
                $detailMsg = "KMSI is NOT hidden in organization branding (signInPageText.isKmsiHidden = $($brandingResponse.signInPageText.isKmsiHidden))"
            }
        }
        catch {
            Write-Log "Could not check branding v1.0 endpoint: $_" -Level Warning
        }

        # Method 2: Check via beta loginPageTextVisibilitySettings if method 1 didn't confirm
        if (-not $kmsiHidden) {
            try {
                $betaBranding = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/organization/$($(Get-MgOrganization | Select-Object -First 1).Id)/branding" -ErrorAction Stop
                if ($betaBranding.loginPageTextVisibilitySettings.hideAccountResetCredentials -eq $true -or
                    $betaBranding.loginPageTextVisibilitySettings.isKmsiHidden -eq $true) {
                    $kmsiHidden = $true
                    $detailMsg = "KMSI is hidden via organization branding (beta endpoint)"
                }
                elseif (-not $detailMsg) {
                    $detailMsg = "KMSI is NOT hidden in organization branding"
                }
            }
            catch {
                Write-Log "Could not check branding beta endpoint: $_" -Level Warning
            }
        }

        # Method 3: Check Conditional Access for persistent browser session controls
        if (-not $kmsiHidden -and $cachedCAPolicies) {
            $persistentBrowserPolicies = @($cachedCAPolicies | Where-Object {
                $_.State -eq 'enabled' -and
                $_.SessionControls.PersistentBrowser.Mode -eq 'never' -and
                $_.SessionControls.PersistentBrowser.IsEnabled -eq $true -and
                $_.Conditions.Users.IncludeUsers -contains 'All'
            })
            if ($persistentBrowserPolicies.Count -gt 0) {
                $kmsiHidden = $true
                $policyNames = ($persistentBrowserPolicies | ForEach-Object { $_.DisplayName }) -join ', '
                $detailMsg = "Persistent browser session disabled for all users via Conditional Access: $policyNames"
            }
        }

        if ($kmsiHidden) {
            Add-Result -ControlNumber "5.1.2.5" -ControlTitle "Ensure the option to remain signed in is hidden" `
                       -ProfileLevel "L2" -Result "Pass" -Details $detailMsg
        }
        else {
            if (-not $detailMsg) { $detailMsg = "Could not confirm KMSI is hidden" }
            Add-Result -ControlNumber "5.1.2.5" -ControlTitle "Ensure the option to remain signed in is hidden" `
                       -ProfileLevel "L2" -Result "Fail" -Details $detailMsg `
                       -Remediation "Hide 'Stay signed in?' option in Entra Admin Center > User experiences > Company branding > Sign-in form > 'Show option to remain signed in' = No"
        }
    }
    catch {
        Add-Result -ControlNumber "5.1.2.5" -ControlTitle "Ensure the option to remain signed in is hidden" `
                   -ProfileLevel "L2" -Result "Error" -Details "Error: $_"
    }

    # 5.1.2.6 - Ensure 'LinkedIn account connections' is disabled
    try {
        Write-Log "Checking 5.1.2.6 - LinkedIn account connections" -Level Info
        $org = Get-MgOrganization -ErrorAction Stop | Select-Object -First 1
        $linkedInSettings = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/organization/$($org.Id)/settings/microsoftApplicationDataAccess" -ErrorAction Stop

        if ($linkedInSettings.isLinkedInAccountConnectionsAllowed -eq $false) {
            Add-Result -ControlNumber "5.1.2.6" -ControlTitle "Ensure 'LinkedIn account connections' is disabled" `
                       -ProfileLevel "L2" -Result "Pass" -Details "LinkedIn account connections are disabled"
        }
        else {
            Add-Result -ControlNumber "5.1.2.6" -ControlTitle "Ensure 'LinkedIn account connections' is disabled" `
                       -ProfileLevel "L2" -Result "Fail" -Details "LinkedIn account connections are enabled" `
                       -Remediation "Disable LinkedIn account connections in Entra Admin Center > Users > User settings"
        }
    }
    catch {
        Add-Result -ControlNumber "5.1.2.6" -ControlTitle "Ensure 'LinkedIn account connections' is disabled" `
                   -ProfileLevel "L2" -Result "Manual" -Details "Unable to check LinkedIn settings: $_" `
                   -Remediation "Check Entra Admin Center > Users > User settings > LinkedIn account connections"
    }

    # 5.1.3.1 - Ensure a dynamic group for guest users is created
    try {
        Write-Log "Checking 5.1.3.1 - Dynamic group for guest users" -Level Info
        $guestGroups = Get-MgGroup -Filter "groupTypes/any(c:c eq 'DynamicMembership')" -All -ErrorAction Stop
        $guestDynamicGroup = $null

        foreach ($group in $guestGroups) {
            # Get the full group details including MembershipRule
            $groupDetails = Get-MgGroup -GroupId $group.Id -ErrorAction Stop

            # Check for various formats of the membership rule
            # Common formats: user.userType -eq "Guest", (user.userType -eq "Guest"), user.userType -eq 'Guest'
            if ($groupDetails.MembershipRule -and
                ($groupDetails.MembershipRule -match "user\.userType\s*-eq\s*[`"']?Guest[`"']?" -or
                 $groupDetails.MembershipRule -match "\(user\.userType\s*-eq\s*[`"']?Guest[`"']?\)")) {
                $guestDynamicGroup = $groupDetails
                break
            }
        }

        if ($guestDynamicGroup) {
            Add-Result -ControlNumber "5.1.3.1" -ControlTitle "Ensure a dynamic group for guest users is created" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Dynamic guest user group exists: $($guestDynamicGroup.DisplayName) (Rule: $($guestDynamicGroup.MembershipRule))"
        }
        else {
            Add-Result -ControlNumber "5.1.3.1" -ControlTitle "Ensure a dynamic group for guest users is created" `
                       -ProfileLevel "L1" -Result "Fail" -Details "No dynamic guest user group found" `
                       -Remediation "Create dynamic group with membership rule: user.userType -eq `"Guest`""
        }
    }
    catch {
        Add-Result -ControlNumber "5.1.3.1" -ControlTitle "Ensure a dynamic group for guest users is created" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 5.1.3.2 - Ensure users cannot create security groups (NEW in v6.0.0)
    try {
        Write-Log "Checking 5.1.3.2 - Users cannot create security groups" -Level Info
        if ($null -eq $cachedAuthPolicy) { throw "Authorization policy data unavailable" }

        if ($cachedAuthPolicy.DefaultUserRolePermissions.AllowedToCreateSecurityGroups -eq $false) {
            Add-Result -ControlNumber "5.1.3.2" -ControlTitle "Ensure users cannot create security groups" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Users cannot create security groups (AllowedToCreateSecurityGroups = false)"
        }
        else {
            Add-Result -ControlNumber "5.1.3.2" -ControlTitle "Ensure users cannot create security groups" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Users can create security groups (AllowedToCreateSecurityGroups = $($cachedAuthPolicy.DefaultUserRolePermissions.AllowedToCreateSecurityGroups))" `
                       -Remediation "Restrict security group creation in Entra Admin Center > Groups > General"
        }
    }
    catch {
        Add-Result -ControlNumber "5.1.3.2" -ControlTitle "Ensure users cannot create security groups" `
                   -ProfileLevel "L1" -Result "Manual" -Details "Unable to check: $_" `
                   -Remediation "Check Entra Admin Center > Groups > General > Security groups"
    }

    # 5.1.4.1 - Ensure the ability to join devices to Entra is restricted (NEW in v6.0.0)
    try {
        Write-Log "Checking 5.1.4.1 - Device join restriction" -Level Info
        if ($null -eq $cachedDeviceRegPolicy) { throw "Device registration policy data unavailable" }
        $joinSetting = $cachedDeviceRegPolicy.azureADJoin.allowedToJoin.'@odata.type'
        if ($joinSetting -ne "#microsoft.graph.allDeviceRegistrationMembership") {
            Add-Result -ControlNumber "5.1.4.1" -ControlTitle "Ensure the ability to join devices to Entra is restricted" `
                       -ProfileLevel "L2" -Result "Pass" -Details "Device join is restricted (not set to All)"
        }
        else {
            Add-Result -ControlNumber "5.1.4.1" -ControlTitle "Ensure the ability to join devices to Entra is restricted" `
                       -ProfileLevel "L2" -Result "Fail" -Details "All users can join devices to Entra" `
                       -Remediation "Set 'Users may join devices to Microsoft Entra' to 'Selected' in Entra Admin Center > Devices > Device settings"
        }
    }
    catch {
        Add-Result -ControlNumber "5.1.4.1" -ControlTitle "Ensure the ability to join devices to Entra is restricted" `
                   -ProfileLevel "L2" -Result "Manual" -Details "Unable to check: $_" `
                   -Remediation "Check Entra Admin Center > Devices > Device settings"
    }

    # 5.1.4.2 - Ensure the maximum number of devices per user is limited (NEW in v6.0.0)
    try {
        Write-Log "Checking 5.1.4.2 - Max devices per user limited" -Level Info
        if ($null -eq $cachedDeviceRegPolicy) { throw "Device registration policy data unavailable" }
        $quota = $cachedDeviceRegPolicy.userDeviceQuota
        if ($quota -and $quota -le 20) {
            Add-Result -ControlNumber "5.1.4.2" -ControlTitle "Ensure the maximum number of devices per user is limited" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Device quota per user: $quota"
        }
        else {
            Add-Result -ControlNumber "5.1.4.2" -ControlTitle "Ensure the maximum number of devices per user is limited" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Device quota per user: $quota (should be 20 or less)" `
                       -Remediation "Limit max devices per user in Entra Admin Center > Devices > Device settings"
        }
    }
    catch {
        Add-Result -ControlNumber "5.1.4.2" -ControlTitle "Ensure the maximum number of devices per user is limited" `
                   -ProfileLevel "L1" -Result "Manual" -Details "Unable to check: $_" `
                   -Remediation "Check Entra Admin Center > Devices > Device settings"
    }

    # 5.1.4.3 - Ensure the GA role is not added as a local administrator during Entra join (NEW in v6.0.0)
    try {
        Write-Log "Checking 5.1.4.3 - GA not local admin on Entra join" -Level Info
        if ($null -eq $cachedDeviceRegPolicy) { throw "Device registration policy data unavailable" }
        $gaLocalAdmin = $cachedDeviceRegPolicy.azureADJoin.localAdmins.enableGlobalAdmins
        if ($gaLocalAdmin -eq $false) {
            Add-Result -ControlNumber "5.1.4.3" -ControlTitle "Ensure the GA role is not added as a local administrator during Entra join" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Global Administrators are NOT added as local admins during Entra join"
        }
        else {
            Add-Result -ControlNumber "5.1.4.3" -ControlTitle "Ensure the GA role is not added as a local administrator during Entra join" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Global Administrators ARE added as local admins during Entra join" `
                       -Remediation "Disable GA as local admin in Entra Admin Center > Devices > Device settings > Local admin settings"
        }
    }
    catch {
        Add-Result -ControlNumber "5.1.4.3" -ControlTitle "Ensure the GA role is not added as a local administrator during Entra join" `
                   -ProfileLevel "L1" -Result "Manual" -Details "Unable to check: $_" `
                   -Remediation "Check Entra Admin Center > Devices > Device settings > Local admin settings"
    }

    # 5.1.4.4 - Ensure local administrator assignment is limited during Entra join (NEW in v6.0.0)
    try {
        Write-Log "Checking 5.1.4.4 - Local admin assignment limited" -Level Info
        if ($null -eq $cachedDeviceRegPolicy) { throw "Device registration policy data unavailable" }
        $registeringUsers = $cachedDeviceRegPolicy.azureADJoin.localAdmins.registeringUsers
        $registrationAllowed = $registeringUsers.additionalAdministratorsCount
        if ($registeringUsers -and $registeringUsers.'@odata.type' -ne "#microsoft.graph.allDeviceRegistrationMembership") {
            Add-Result -ControlNumber "5.1.4.4" -ControlTitle "Ensure local administrator assignment is limited during Entra join" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Local admin assignment during Entra join is restricted"
        }
        else {
            Add-Result -ControlNumber "5.1.4.4" -ControlTitle "Ensure local administrator assignment is limited during Entra join" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Local admin assignment during Entra join is not restricted" `
                       -Remediation "Limit local admin assignment in Entra Admin Center > Devices > Device settings > Local admin settings"
        }
    }
    catch {
        Add-Result -ControlNumber "5.1.4.4" -ControlTitle "Ensure local administrator assignment is limited during Entra join" `
                   -ProfileLevel "L1" -Result "Manual" -Details "Unable to check: $_" `
                   -Remediation "Check Entra Admin Center > Devices > Device settings > Local admin settings"
    }

    # 5.1.4.5 - Ensure Local Administrator Password Solution is enabled (NEW in v6.0.0)
    try {
        Write-Log "Checking 5.1.4.5 - LAPS enabled" -Level Info
        if ($null -eq $cachedDeviceRegPolicy) { throw "Device registration policy data unavailable" }
        $lapsEnabled = $cachedDeviceRegPolicy.localAdminPassword.isEnabled
        if ($lapsEnabled -eq $true) {
            Add-Result -ControlNumber "5.1.4.5" -ControlTitle "Ensure Local Administrator Password Solution is enabled" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Microsoft Entra LAPS is enabled"
        }
        else {
            Add-Result -ControlNumber "5.1.4.5" -ControlTitle "Ensure Local Administrator Password Solution is enabled" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Microsoft Entra LAPS is not enabled" `
                       -Remediation "Enable LAPS in Entra Admin Center > Devices > Device settings"
        }
    }
    catch {
        Add-Result -ControlNumber "5.1.4.5" -ControlTitle "Ensure Local Administrator Password Solution is enabled" `
                   -ProfileLevel "L1" -Result "Manual" -Details "Unable to check: $_" `
                   -Remediation "Check Entra Admin Center > Devices > Device settings > Enable LAPS"
    }

    # 5.1.4.6 - Ensure users are restricted from recovering BitLocker keys (NEW in v6.0.0)
    try {
        Write-Log "Checking 5.1.4.6 - BitLocker key recovery restricted" -Level Info
        if ($null -eq $cachedBetaAuthPolicy) { throw "Beta authorization policy data unavailable" }
        $bitlockerRestriction = $cachedBetaAuthPolicy.defaultUserRolePermissions.allowedToReadBitlockerKeysForOwnedDevice
        if ($bitlockerRestriction -eq $false) {
            Add-Result -ControlNumber "5.1.4.6" -ControlTitle "Ensure users are restricted from recovering BitLocker keys" `
                       -ProfileLevel "L2" -Result "Pass" -Details "Users are restricted from recovering BitLocker keys for their owned devices"
        }
        else {
            Add-Result -ControlNumber "5.1.4.6" -ControlTitle "Ensure users are restricted from recovering BitLocker keys" `
                       -ProfileLevel "L2" -Result "Fail" -Details "Users can recover BitLocker keys for their owned devices" `
                       -Remediation "Set 'Restrict users from recovering BitLocker keys' to 'Yes' in Entra Admin Center > Devices > Device settings"
        }
    }
    catch {
        Add-Result -ControlNumber "5.1.4.6" -ControlTitle "Ensure users are restricted from recovering BitLocker keys" `
                   -ProfileLevel "L2" -Result "Manual" -Details "Unable to check: $_" `
                   -Remediation "Check Entra Admin Center > Devices > Device settings > Restrict users from recovering BitLocker keys"
    }

    # 5.1.5.1 - Ensure user consent to apps accessing company data on their behalf is not allowed
    try {
        Write-Log "Checking 5.1.5.1 - User consent disabled" -Level Info
        if ($null -eq $cachedAuthPolicy) { throw "Authorization policy data unavailable" }
        $authPolicy = $cachedAuthPolicy

        # Get the permission grant policies assigned to default user role
        $consentPolicies = $authPolicy.DefaultUserRolePermissions.PermissionGrantPoliciesAssigned

        # Check if user consent is enabled
        # Empty array = consent disabled (secure)
        # Contains legacy policy or other consent-enabling policies = consent enabled (fail)
        # Policies that enable user consent include:
        # - ManagePermissionGrantsForSelf.microsoft-user-default-legacy
        # - ManagePermissionGrantsForSelf.microsoft-user-default-low
        # - Any custom policy starting with "ManagePermissionGrantsForSelf"

        $consentEnabled = $false
        $enabledPolicies = @()

        if ($consentPolicies -and $consentPolicies.Count -gt 0) {
            foreach ($policy in $consentPolicies) {
                if ($policy -like "ManagePermissionGrantsForSelf*") {
                    $consentEnabled = $true
                    $enabledPolicies += $policy
                }
            }
        }

        if ($consentEnabled) {
            Add-Result -ControlNumber "5.1.5.1" -ControlTitle "Ensure user consent to apps accessing company data on their behalf is not allowed" `
                       -ProfileLevel "L2" -Result "Fail" -Details "User consent is allowed via: $($enabledPolicies -join ', ')" `
                       -Remediation "Remove user consent policies: Update-MgPolicyAuthorizationPolicy -DefaultUserRolePermissions @{PermissionGrantPoliciesAssigned=@()}"
        }
        else {
            $details = if ($consentPolicies.Count -eq 0) { "User consent disabled (no policies assigned)" } else { "User consent disabled (no consent-enabling policies found)" }
            Add-Result -ControlNumber "5.1.5.1" -ControlTitle "Ensure user consent to apps accessing company data on their behalf is not allowed" `
                       -ProfileLevel "L2" -Result "Pass" -Details $details
        }
    }
    catch {
        Add-Result -ControlNumber "5.1.5.1" -ControlTitle "Ensure user consent to apps accessing company data on their behalf is not allowed" `
                   -ProfileLevel "L2" -Result "Error" -Details "Error: $_"
    }

    # 5.1.5.2 - Ensure the admin consent workflow is enabled
    try {
        Write-Log "Checking 5.1.5.2 - Admin consent workflow" -Level Info
        $consentPolicy = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/policies/adminConsentRequestPolicy" -ErrorAction Stop

        if ($consentPolicy.isEnabled -eq $true) {
            Add-Result -ControlNumber "5.1.5.2" -ControlTitle "Ensure the admin consent workflow is enabled" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Admin consent workflow is enabled"
        }
        else {
            Add-Result -ControlNumber "5.1.5.2" -ControlTitle "Ensure the admin consent workflow is enabled" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Admin consent workflow is disabled" `
                       -Remediation "Enable admin consent workflow in Entra Admin Center > Enterprise applications > Admin consent requests"
        }
    }
    catch {
        Add-Result -ControlNumber "5.1.5.2" -ControlTitle "Ensure the admin consent workflow is enabled" `
                   -ProfileLevel "L1" -Result "Manual" -Details "Unable to check: $_" `
                   -Remediation "Check Entra Admin Center > Enterprise applications > Admin consent requests"
    }

    # 5.1.6.1 - Ensure that collaboration invitations are sent to allowed domains only
    try {
        Write-Log "Checking 5.1.6.1 - Collaboration invitations domain restriction" -Level Info
        if ($null -eq $cachedAuthPolicy) { throw "Authorization policy data unavailable" }

        $allowInvitesFrom = $cachedAuthPolicy.AllowInvitesFrom
        $crossTenantPolicy = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/default" -ErrorAction Stop

        $invitesRestricted = ($allowInvitesFrom -eq "adminsAndGuestInviters" -or $allowInvitesFrom -eq "adminsOnly")
        $hasInboundRestriction = $crossTenantPolicy.b2bCollaborationInbound -and $crossTenantPolicy.b2bCollaborationInbound.applications

        if ($invitesRestricted) {
            Add-Result -ControlNumber "5.1.6.1" -ControlTitle "Ensure that collaboration invitations are sent to allowed domains only" `
                       -ProfileLevel "L2" -Result "Pass" -Details "Invitations restricted to: $allowInvitesFrom. Cross-tenant policy configured."
        }
        else {
            Add-Result -ControlNumber "5.1.6.1" -ControlTitle "Ensure that collaboration invitations are sent to allowed domains only" `
                       -ProfileLevel "L2" -Result "Fail" -Details "Invitations too permissive: $allowInvitesFrom" `
                       -Remediation "Configure allowed/denied domain list in External Identities > External collaboration settings"
        }
    }
    catch {
        Add-Result -ControlNumber "5.1.6.1" -ControlTitle "Ensure that collaboration invitations are sent to allowed domains only" `
                   -ProfileLevel "L2" -Result "Manual" -Details "Unable to check: $_" `
                   -Remediation "Check External Identities > External collaboration settings"
    }

    # 5.1.6.2 - Ensure that guest user access is restricted
    try {
        Write-Log "Checking 5.1.6.2 - Guest user access restricted" -Level Info
        if ($null -eq $cachedAuthPolicy) { throw "Authorization policy data unavailable" }
        $authPolicy = $cachedAuthPolicy

        # Guest user role should be restricted:
        # '10dae51f-b6af-4016-8d66-8c2a99b929b3' = Guest users have limited access to properties and memberships of directory objects
        # '2af84b1e-32c8-42b7-82bc-daa82404023b' = Guest user access is restricted to properties and memberships of their own directory objects (most restrictive)
        if (($authPolicy.GuestUserRoleId -eq "10dae51f-b6af-4016-8d66-8c2a99b929b3") -or ($authPolicy.GuestUserRoleId -eq "2af84b1e-32c8-42b7-82bc-daa82404023b")) {
            Add-Result -ControlNumber "5.1.6.2" -ControlTitle "Ensure that guest user access is restricted" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Guest user access is restricted"
        }
        else {
            Add-Result -ControlNumber "5.1.6.2" -ControlTitle "Ensure that guest user access is restricted" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Guest user access is not fully restricted" `
                       -Remediation "Set guest user access to most restrictive level"
        }
    }
    catch {
        Add-Result -ControlNumber "5.1.6.2" -ControlTitle "Ensure that guest user access is restricted" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 5.1.6.3 - Ensure guest user invitations are limited to the Guest Inviter role
    try {
        Write-Log "Checking 5.1.6.3 - Guest inviter role restriction" -Level Info
        if ($null -eq $cachedAuthPolicy) { throw "Authorization policy data unavailable" }
        $authPolicy = $cachedAuthPolicy

        # Acceptable values (in order from most restrictive to least restrictive that still passes):
        # - adminsOnly: Only Global Admins can invite (most restrictive - compliant)
        # - adminsAndGuestInviters: Admins and Guest Inviter role can invite (compliant per CIS)
        # NOT acceptable:
        # - adminsGuestInvitersAndAllMembers: All members can invite (too permissive)
        # - everyone: Anyone including guests can invite (too permissive)

        if ($authPolicy.AllowInvitesFrom -eq "adminsAndGuestInviters" -or
            $authPolicy.AllowInvitesFrom -eq "adminsOnly") {

            $restrictionLevel = if ($authPolicy.AllowInvitesFrom -eq "adminsOnly") {
                "admins only (most restrictive)"
            } else {
                "admins and guest inviters"
            }

            Add-Result -ControlNumber "5.1.6.3" -ControlTitle "Ensure guest user invitations are limited to the Guest Inviter role" `
                       -ProfileLevel "L2" -Result "Pass" -Details "Guest invitations restricted to $restrictionLevel"
        }
        else {
            Add-Result -ControlNumber "5.1.6.3" -ControlTitle "Ensure guest user invitations are limited to the Guest Inviter role" `
                       -ProfileLevel "L2" -Result "Fail" -Details "Guest invitations too permissive: $($authPolicy.AllowInvitesFrom)" `
                       -Remediation "Update-MgPolicyAuthorizationPolicy -AllowInvitesFrom adminsAndGuestInviters (or adminsOnly for more restrictive)"
        }
    }
    catch {
        Add-Result -ControlNumber "5.1.6.3" -ControlTitle "Ensure guest user invitations are limited to the Guest Inviter role" `
                   -ProfileLevel "L2" -Result "Error" -Details "Error: $_"
    }

    # 5.1.8.1 - Ensure that password hash sync is enabled for hybrid deployments
    try {
        Write-Log "Checking 5.1.8.1 - Password hash sync for hybrid" -Level Info
        $org = Get-MgOrganization -ErrorAction Stop
        $isHybrid = $org.OnPremisesSyncEnabled

        if (-not $isHybrid) {
            Add-Result -ControlNumber "5.1.8.1" -ControlTitle "Ensure that password hash sync is enabled for hybrid deployments" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Cloud-only tenant (no hybrid deployment) - control not applicable"
        }
        else {
            # Hybrid tenant - check password hash sync
            try {
                $syncConfig = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/directory/onPremisesSynchronization" -ErrorAction Stop
                $syncItems = @($syncConfig.value)
                $phsEnabled = $false
                foreach ($item in $syncItems) {
                    if ($item.features.passwordHashSyncEnabled -eq $true) {
                        $phsEnabled = $true
                        break
                    }
                }
                if ($phsEnabled) {
                    Add-Result -ControlNumber "5.1.8.1" -ControlTitle "Ensure that password hash sync is enabled for hybrid deployments" `
                               -ProfileLevel "L1" -Result "Pass" -Details "Password hash sync is enabled for hybrid deployment"
                }
                else {
                    Add-Result -ControlNumber "5.1.8.1" -ControlTitle "Ensure that password hash sync is enabled for hybrid deployments" `
                               -ProfileLevel "L1" -Result "Fail" -Details "Hybrid deployment detected but password hash sync is not enabled" `
                               -Remediation "Enable password hash synchronization in Azure AD Connect"
                }
            }
            catch {
                Add-Result -ControlNumber "5.1.8.1" -ControlTitle "Ensure that password hash sync is enabled for hybrid deployments" `
                           -ProfileLevel "L1" -Result "Manual" -Details "Hybrid deployment detected but unable to verify password hash sync: $_" `
                           -Remediation "Verify password hash sync is enabled in Azure AD Connect configuration"
            }
        }
    }
    catch {
        Add-Result -ControlNumber "5.1.8.1" -ControlTitle "Ensure that password hash sync is enabled for hybrid deployments" `
                   -ProfileLevel "L1" -Result "Manual" -Details "Unable to determine deployment type: $_" `
                   -Remediation "Enable password hash synchronization in Azure AD Connect"
    }

    # Conditional Access Policies (5.2.2.x)
    Write-Log "Checking Conditional Access policies..." -Level Info

    # 5.2.2.1 - Ensure multifactor authentication is enabled for all users in administrative roles
    try {
        Write-Log "Checking 5.2.2.1 - MFA for admin roles" -Level Info
        if ($null -eq $cachedCAPolicies) { throw "Conditional Access policy data unavailable" }
        $caPolicies = $cachedCAPolicies
        $adminMfaPolicy = $null

        # Define critical administrative role GUIDs per CIS Benchmark
        # These are the minimum roles that MUST be protected with MFA
        $criticalAdminRoles = @(
            "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
            "194ae4cb-b126-40b2-bd5b-6091b380977d",  # Security Administrator
            "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",  # Application Administrator
            "158c047a-c907-4556-b7ef-446551a6b5f7",  # Cloud Application Administrator
            "b0f54661-2d74-4c50-afa3-1ec803f12efe",  # Billing Administrator
            "729827e3-9c14-49f7-bb1b-9608f156bbb8",  # Helpdesk Administrator
            "966707d0-3269-4727-9be2-8c3a10f19b9d",  # Password Administrator
            "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",  # Privileged Authentication Administrator
            "e8611ab8-c189-46e8-94e1-60213ab1f814"   # Privileged Role Administrator
        )

        foreach ($policy in $caPolicies) {
            # Check for enabled policies (not report-only) requiring MFA
            if ($policy.State -eq "enabled" -and
                $policy.Conditions.Users.IncludeRoles -and
                $policy.GrantControls.BuiltInControls -contains "mfa") {

                # Check if policy targets ALL directory roles (best practice)
                if ($policy.Conditions.Users.IncludeRoles -contains "All") {
                    $adminMfaPolicy = $policy
                    break
                }

                # Otherwise, verify that all critical admin roles are included
                $includedRoles = $policy.Conditions.Users.IncludeRoles
                $missingRoles = $criticalAdminRoles | Where-Object { $_ -notin $includedRoles }

                if ($missingRoles.Count -eq 0) {
                    # All critical roles are covered
                    $adminMfaPolicy = $policy
                    break
                }
                # If some but not all critical roles are covered, continue checking other policies
            }
        }

        if ($adminMfaPolicy) {
            # Determine coverage type
            $coverageType = if ($adminMfaPolicy.Conditions.Users.IncludeRoles -contains "All") {
                "all directory roles"
            } else {
                "$($adminMfaPolicy.Conditions.Users.IncludeRoles.Count) administrative roles"
            }

            # Warn if policy has exclusions
            $exclusionWarning = ""
            if ($adminMfaPolicy.Conditions.Users.ExcludeUsers -or $adminMfaPolicy.Conditions.Users.ExcludeRoles) {
                $excludedRoleCount = if ($adminMfaPolicy.Conditions.Users.ExcludeRoles) { $adminMfaPolicy.Conditions.Users.ExcludeRoles.Count } else { 0 }
                $excludedUserCount = if ($adminMfaPolicy.Conditions.Users.ExcludeUsers) { $adminMfaPolicy.Conditions.Users.ExcludeUsers.Count } else { 0 }
                $totalExclusions = $excludedRoleCount + $excludedUserCount
                $exclusionWarning = " (Warning: $totalExclusions exclusions - $excludedUserCount users, $excludedRoleCount roles)"
            }

            Add-Result -ControlNumber "5.2.2.1" -ControlTitle "Ensure multifactor authentication is enabled for all users in administrative roles" `
                       -ProfileLevel "L1" -Result "Pass" -Details "CA policy requiring MFA for $coverageType$exclusionWarning"
        }
        else {
            # Check if there's a report-only policy
            $reportOnlyPolicy = $caPolicies | Where-Object {
                $_.State -eq "enabledForReportingButNotEnforced" -and
                $_.Conditions.Users.IncludeRoles -and
                $_.GrantControls.BuiltInControls -contains "mfa"
            }

            if ($reportOnlyPolicy) {
                Add-Result -ControlNumber "5.2.2.1" -ControlTitle "Ensure multifactor authentication is enabled for all users in administrative roles" `
                           -ProfileLevel "L1" -Result "Fail" -Details "CA policy exists but is in report-only mode (not enforced)" `
                           -Remediation "Change policy state from 'Report-only' to 'On' to enforce MFA for admin roles"
            }
            else {
                # Check if partial coverage exists (some but not all critical roles)
                $partialPolicy = $caPolicies | Where-Object {
                    $_.State -eq "enabled" -and
                    $_.Conditions.Users.IncludeRoles -and
                    $_.GrantControls.BuiltInControls -contains "mfa"
                } | Select-Object -First 1

                if ($partialPolicy) {
                    $coveredRoles = $criticalAdminRoles | Where-Object { $_ -in $partialPolicy.Conditions.Users.IncludeRoles }
                    $missingRoles = $criticalAdminRoles | Where-Object { $_ -notin $partialPolicy.Conditions.Users.IncludeRoles }

                    Add-Result -ControlNumber "5.2.2.1" -ControlTitle "Ensure multifactor authentication is enabled for all users in administrative roles" `
                               -ProfileLevel "L1" -Result "Fail" -Details "CA policy covers only $($coveredRoles.Count) of $($criticalAdminRoles.Count) critical admin roles. Missing: $($missingRoles.Count) roles" `
                               -Remediation "Update CA policy to target 'All directory roles' or include all critical administrative roles"
                }
                else {
                    Add-Result -ControlNumber "5.2.2.1" -ControlTitle "Ensure multifactor authentication is enabled for all users in administrative roles" `
                               -ProfileLevel "L1" -Result "Fail" -Details "No CA policy requiring MFA for admin roles" `
                               -Remediation "Create CA policy requiring MFA for all administrative roles (target 'All directory roles')"
                }
            }
        }
    }
    catch {
        Add-Result -ControlNumber "5.2.2.1" -ControlTitle "Ensure multifactor authentication is enabled for all users in administrative roles" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 5.2.2.2 - Ensure multifactor authentication is enabled for all users
    try {
        Write-Log "Checking 5.2.2.2 - MFA for all users" -Level Info
        if ($null -eq $cachedCAPolicies) { throw "Conditional Access policy data unavailable" }
        $caPolicies = $cachedCAPolicies
        $allUserMfaPolicy = $null

        foreach ($policy in $caPolicies) {
            if ($policy.State -eq "enabled" -and
                $policy.Conditions.Users.IncludeUsers -contains "All" -and
                $policy.GrantControls.BuiltInControls -contains "mfa") {
                $allUserMfaPolicy = $policy
                break
            }
        }

        if ($allUserMfaPolicy) {
            # Check for excessive exclusions
            # CIS allows for minimal exclusions (emergency access accounts, service accounts)
            # But excessive exclusions (>5 total) indicate potential security gaps
            $excludedUserCount = if ($allUserMfaPolicy.Conditions.Users.ExcludeUsers) { $allUserMfaPolicy.Conditions.Users.ExcludeUsers.Count } else { 0 }
            $excludedGroupCount = if ($allUserMfaPolicy.Conditions.Users.ExcludeGroups) { $allUserMfaPolicy.Conditions.Users.ExcludeGroups.Count } else { 0 }
            $totalExclusions = $excludedUserCount + $excludedGroupCount

            # Threshold for acceptable exclusions: 5 (typically 1-2 emergency accounts + 1-2 service accounts + 1 break-glass group)
            $maxAcceptableExclusions = 5

            if ($totalExclusions -eq 0) {
                Add-Result -ControlNumber "5.2.2.2" -ControlTitle "Ensure multifactor authentication is enabled for all users" `
                           -ProfileLevel "L1" -Result "Pass" -Details "CA policy requiring MFA for all users with no exclusions (ideal configuration)"
            }
            elseif ($totalExclusions -le $maxAcceptableExclusions) {
                Add-Result -ControlNumber "5.2.2.2" -ControlTitle "Ensure multifactor authentication is enabled for all users" `
                           -ProfileLevel "L1" -Result "Pass" -Details "CA policy requiring MFA for all users exists with $totalExclusions exclusion(s) ($excludedUserCount user(s), $excludedGroupCount group(s)). Review to ensure only emergency/service accounts are excluded."
            }
            else {
                # Excessive exclusions - FAIL
                Add-Result -ControlNumber "5.2.2.2" -ControlTitle "Ensure multifactor authentication is enabled for all users" `
                           -ProfileLevel "L1" -Result "Fail" -Details "CA policy has excessive exclusions: $totalExclusions total ($excludedUserCount user(s), $excludedGroupCount group(s)). Maximum recommended: $maxAcceptableExclusions. Excessive exclusions create security gaps." `
                           -Remediation "Review and minimize exclusions to only essential emergency access and service accounts. Consider using excluded groups instead of individual users for better management."
            }
        }
        else {
            $reportOnlyPolicy = $caPolicies | Where-Object {
                $_.State -eq "enabledForReportingButNotEnforced" -and
                $_.Conditions.Users.IncludeUsers -contains "All" -and
                $_.GrantControls.BuiltInControls -contains "mfa"
            }

            if ($reportOnlyPolicy) {
                Add-Result -ControlNumber "5.2.2.2" -ControlTitle "Ensure multifactor authentication is enabled for all users" `
                           -ProfileLevel "L1" -Result "Fail" -Details "CA policy exists but is in report-only mode (not enforced)" `
                           -Remediation "Change policy state from 'Report-only' to 'On' to enforce MFA for all users"
            }
            else {
                Add-Result -ControlNumber "5.2.2.2" -ControlTitle "Ensure multifactor authentication is enabled for all users" `
                           -ProfileLevel "L1" -Result "Fail" -Details "No CA policy requiring MFA for all users" `
                           -Remediation "Create CA policy requiring MFA for all users"
            }
        }
    }
    catch {
        Add-Result -ControlNumber "5.2.2.2" -ControlTitle "Ensure multifactor authentication is enabled for all users" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 5.2.2.3 - Enable Conditional Access policies to block legacy authentication
    try {
        Write-Log "Checking 5.2.2.3 - Block legacy authentication" -Level Info
        if ($null -eq $cachedCAPolicies) { throw "Conditional Access policy data unavailable" }
        $caPolicies = $cachedCAPolicies
        $legacyAuthBlockPolicy = $null

        # All legacy auth client app types that should be blocked
        $legacyAuthTypes = @("exchangeActiveSync", "other")

        foreach ($policy in $caPolicies) {
            if ($policy.State -eq "enabled" -and
                $policy.GrantControls.BuiltInControls -contains "block") {

                # Check if policy targets legacy auth client types
                $hasExchangeActiveSync = $policy.Conditions.ClientAppTypes -contains "exchangeActiveSync"
                $hasOther = $policy.Conditions.ClientAppTypes -contains "other"

                # Policy should block both EAS and "other" (which includes legacy protocols)
                # OR use broader client app conditions
                if (($hasExchangeActiveSync -and $hasOther) -or
                    ($policy.Conditions.ClientAppTypes.Count -ge 4)) {
                    # If 4+ client types specified, likely comprehensive policy
                    $legacyAuthBlockPolicy = $policy
                    break
                }
            }
        }

        if ($legacyAuthBlockPolicy) {
            $clientTypes = $legacyAuthBlockPolicy.Conditions.ClientAppTypes -join ", "
            Add-Result -ControlNumber "5.2.2.3" -ControlTitle "Enable Conditional Access policies to block legacy authentication" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Legacy auth blocked (Policy: $($legacyAuthBlockPolicy.DisplayName), Client types: $clientTypes)"
        }
        else {
            Add-Result -ControlNumber "5.2.2.3" -ControlTitle "Enable Conditional Access policies to block legacy authentication" `
                       -ProfileLevel "L1" -Result "Fail" -Details "No CA policy blocking legacy authentication (ExchangeActiveSync and Other)" `
                       -Remediation "Create CA policy to block legacy authentication protocols (include exchangeActiveSync and other client app types)"
        }
    }
    catch {
        Add-Result -ControlNumber "5.2.2.3" -ControlTitle "Enable Conditional Access policies to block legacy authentication" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 5.2.2.4 - Ensure Sign-in frequency is enabled and browser sessions are not persistent for Administrative users
    try {
        Write-Log "Checking 5.2.2.4 - Admin sign-in frequency" -Level Info
        if ($null -eq $cachedCAPolicies) { throw "Conditional Access policy data unavailable" }
        $caPolicies = $cachedCAPolicies
        $compliantPolicy = $null

        foreach ($policy in $caPolicies) {
            if ($policy.State -eq "enabled" -and
                $policy.Conditions.Users.IncludeRoles -and
                $policy.SessionControls.SignInFrequency -and
                $policy.SessionControls.PersistentBrowser.Mode -eq "never") {

                # Validate sign-in frequency is appropriate (4 hours or less)
                $signInFreq = $policy.SessionControls.SignInFrequency
                $isCompliant = $false

                if ($signInFreq.IsEnabled -eq $true) {
                    # Check frequency value and type
                    if ($signInFreq.Type -eq "hours" -and $signInFreq.Value -le 4) {
                        $isCompliant = $true
                    }
                    elseif ($signInFreq.Type -eq "days" -and $signInFreq.Value -eq 1) {
                        # 1 day (24 hours) is acceptable but not ideal
                        $isCompliant = $true
                    }
                    elseif ($signInFreq.FrequencyInterval -eq "everyTime") {
                        # Every time is most secure
                        $isCompliant = $true
                    }
                }

                if ($isCompliant) {
                    $compliantPolicy = $policy
                    break
                }
            }
        }

        if ($compliantPolicy) {
            $freq = $compliantPolicy.SessionControls.SignInFrequency
            $freqDetails = if ($freq.FrequencyInterval -eq "everyTime") { "Every time" } else { "$($freq.Value) $($freq.Type)" }
            Add-Result -ControlNumber "5.2.2.4" -ControlTitle "Ensure Sign-in frequency is enabled and browser sessions are not persistent for Administrative users" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Admin sign-in frequency: $freqDetails, Persistent browser: Never (Policy: $($compliantPolicy.DisplayName))"
        }
        else {
            Add-Result -ControlNumber "5.2.2.4" -ControlTitle "Ensure Sign-in frequency is enabled and browser sessions are not persistent for Administrative users" `
                       -ProfileLevel "L1" -Result "Fail" -Details "No compliant admin sign-in frequency policy found (must be ≤4 hours)" `
                       -Remediation "Create CA policy: Target admin roles > Session > Sign-in frequency ≤4 hours > Persistent browser: Never"
        }
    }
    catch {
        Add-Result -ControlNumber "5.2.2.4" -ControlTitle "Ensure Sign-in frequency is enabled and browser sessions are not persistent for Administrative users" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 5.2.2.5 - Ensure 'Phishing-resistant MFA strength' is required for Administrators
    try {
        Write-Log "Checking 5.2.2.5 - Phishing-resistant MFA for admins" -Level Info
        if ($null -eq $cachedCAPolicies) { throw "Conditional Access policy data unavailable" }
        $phishResistantPolicy = $null
        # Phishing-resistant MFA strength ID
        $phishResistantStrengthId = "00000000-0000-0000-0000-000000000004"
        # Admin role template IDs to check
        $adminRoleIds = @(
            "62e90394-69f5-4237-9190-012177145e10", # Global Administrator
            "e8611ab8-c189-46e8-94e1-60213ab1f814", # Privileged Role Administrator
            "194ae4cb-b126-40b2-bd5b-6091b380977d", # Security Administrator
            "f28a1f50-f6e7-4571-818b-6a12f2af6b6c", # SharePoint Administrator
            "29232cdf-9323-42fd-ade2-1d097af3e4de", # Exchange Administrator
            "fe930be7-5e62-47db-91af-98c3a49a38b1", # User Administrator
            "b0f54661-2d74-4c50-afa3-1ec803f12efe"  # Billing Administrator
        )

        foreach ($policy in $cachedCAPolicies) {
            if ($policy.State -ne "enabled") { continue }
            # Check if policy targets admin roles
            $includeRoles = @($policy.Conditions.Users.IncludeRoles)
            $targetsAdmins = $false
            foreach ($roleId in $adminRoleIds) {
                if ($includeRoles -contains $roleId) { $targetsAdmins = $true; break }
            }
            if (-not $targetsAdmins) { continue }
            # Check for phishing-resistant authentication strength
            $authStrength = $policy.GrantControls.AuthenticationStrength
            if ($authStrength -and $authStrength.Id -eq $phishResistantStrengthId) {
                $phishResistantPolicy = $policy
                break
            }
        }

        if ($phishResistantPolicy) {
            Add-Result -ControlNumber "5.2.2.5" -ControlTitle "Ensure 'Phishing-resistant MFA strength' is required for Administrators" `
                       -ProfileLevel "L2" -Result "Pass" -Details "CA policy '$($phishResistantPolicy.DisplayName)' requires phishing-resistant MFA for admin roles"
        }
        else {
            Add-Result -ControlNumber "5.2.2.5" -ControlTitle "Ensure 'Phishing-resistant MFA strength' is required for Administrators" `
                       -ProfileLevel "L2" -Result "Fail" -Details "No CA policy found requiring phishing-resistant MFA strength for admin roles" `
                       -Remediation "Create CA policy targeting admin roles with authentication strength set to 'Phishing-resistant MFA'"
        }
    }
    catch {
        Add-Result -ControlNumber "5.2.2.5" -ControlTitle "Ensure 'Phishing-resistant MFA strength' is required for Administrators" `
                   -ProfileLevel "L2" -Result "Manual" -Details "Unable to check: $_" `
                   -Remediation "Verify CA policy requires phishing-resistant MFA (FIDO2/certificate-based) for administrators"
    }

    # 5.2.2.6 - Enable Identity Protection user risk policies
    try {
        Write-Log "Checking 5.2.2.6 - User risk policy" -Level Info
        if ($null -eq $cachedCAPolicies) { throw "Conditional Access policy data unavailable" }
        $caPolicies = $cachedCAPolicies
        $userRiskPolicy = $null

        foreach ($policy in $caPolicies) {
            if ($policy.State -eq "enabled" -and
                $policy.Conditions.UserRiskLevels -and
                ($policy.Conditions.UserRiskLevels -contains "high" -or $policy.Conditions.UserRiskLevels -contains "medium")) {
                $userRiskPolicy = $policy
                break
            }
        }

        if ($userRiskPolicy) {
            $riskLevels = $userRiskPolicy.Conditions.UserRiskLevels -join ", "
            Add-Result -ControlNumber "5.2.2.6" -ControlTitle "Enable Identity Protection user risk policies" `
                       -ProfileLevel "L1" -Result "Pass" -Details "User risk policy enabled targeting risk levels: $riskLevels"
        }
        else {
            Add-Result -ControlNumber "5.2.2.6" -ControlTitle "Enable Identity Protection user risk policies" `
                       -ProfileLevel "L1" -Result "Fail" -Details "No user risk policy targeting high or medium risk found" `
                       -Remediation "Create CA policy based on user risk level (target high and medium risk)"
        }
    }
    catch {
        Add-Result -ControlNumber "5.2.2.6" -ControlTitle "Enable Identity Protection user risk policies" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 5.2.2.7 - Enable Identity Protection sign-in risk policies
    try {
        Write-Log "Checking 5.2.2.7 - Sign-in risk policy" -Level Info
        if ($null -eq $cachedCAPolicies) { throw "Conditional Access policy data unavailable" }
        $caPolicies = $cachedCAPolicies
        $signInRiskPolicy = $null

        foreach ($policy in $caPolicies) {
            if ($policy.State -eq "enabled" -and
                $policy.Conditions.SignInRiskLevels -and
                ($policy.Conditions.SignInRiskLevels -contains "high" -or $policy.Conditions.SignInRiskLevels -contains "medium")) {
                $signInRiskPolicy = $policy
                break
            }
        }

        if ($signInRiskPolicy) {
            $riskLevels = $signInRiskPolicy.Conditions.SignInRiskLevels -join ", "
            Add-Result -ControlNumber "5.2.2.7" -ControlTitle "Enable Identity Protection sign-in risk policies" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Sign-in risk policy enabled targeting risk levels: $riskLevels"
        }
        else {
            Add-Result -ControlNumber "5.2.2.7" -ControlTitle "Enable Identity Protection sign-in risk policies" `
                       -ProfileLevel "L1" -Result "Fail" -Details "No sign-in risk policy targeting high or medium risk found" `
                       -Remediation "Create CA policy based on sign-in risk level (target high and medium risk)"
        }
    }
    catch {
        Add-Result -ControlNumber "5.2.2.7" -ControlTitle "Enable Identity Protection sign-in risk policies" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 5.2.2.8 - Ensure 'sign-in risk' is blocked for medium and high risk
    try {
        Write-Log "Checking 5.2.2.8 - Sign-in risk blocked for medium+high" -Level Info
        if ($null -eq $cachedCAPolicies) { throw "Conditional Access policy data unavailable" }
        $blockRiskPolicy = $null

        foreach ($policy in $cachedCAPolicies) {
            if ($policy.State -eq "enabled" -and
                $policy.Conditions.SignInRiskLevels -and
                ($policy.Conditions.SignInRiskLevels -contains "medium") -and
                ($policy.Conditions.SignInRiskLevels -contains "high") -and
                $policy.GrantControls.BuiltInControls -and
                ($policy.GrantControls.BuiltInControls -contains "block")) {
                $blockRiskPolicy = $policy
                break
            }
        }

        if ($blockRiskPolicy) {
            $riskLevels = $blockRiskPolicy.Conditions.SignInRiskLevels -join ", "
            Add-Result -ControlNumber "5.2.2.8" -ControlTitle "Ensure 'sign-in risk' is blocked for medium and high risk" `
                       -ProfileLevel "L2" -Result "Pass" -Details "CA policy '$($blockRiskPolicy.DisplayName)' blocks sign-in for risk levels: $riskLevels"
        }
        else {
            Add-Result -ControlNumber "5.2.2.8" -ControlTitle "Ensure 'sign-in risk' is blocked for medium and high risk" `
                       -ProfileLevel "L2" -Result "Fail" -Details "No CA policy found that blocks sign-in for both medium and high risk levels" `
                       -Remediation "Create CA policy that blocks access when sign-in risk is medium or high"
        }
    }
    catch {
        Add-Result -ControlNumber "5.2.2.8" -ControlTitle "Ensure 'sign-in risk' is blocked for medium and high risk" `
                   -ProfileLevel "L2" -Result "Manual" -Details "Unable to check: $_" `
                   -Remediation "Configure CA policy to block sign-in risk at medium and high levels"
    }

    # 5.2.2.9 - Ensure a managed device is required for authentication
    try {
        Write-Log "Checking 5.2.2.9 - Managed device required" -Level Info
        if ($null -eq $cachedCAPolicies) { throw "Conditional Access policy data unavailable" }
        $caPolicies = $cachedCAPolicies
        $managedDevicePolicy = $null

        foreach ($policy in $caPolicies) {
            if ($policy.State -eq "enabled" -and
                ($policy.GrantControls.BuiltInControls -contains "compliantDevice" -or
                 $policy.GrantControls.BuiltInControls -contains "domainJoinedDevice") -and
                ($policy.Conditions.Users.IncludeUsers -contains "All" -or
                 $policy.Conditions.Applications.IncludeApplications -contains "All")) {
                $managedDevicePolicy = $policy
                break
            }
        }

        if ($managedDevicePolicy) {
            $deviceReq = if ($managedDevicePolicy.GrantControls.BuiltInControls -contains "compliantDevice") { "Compliant device" } else { "Domain-joined device" }
            $scope = if ($managedDevicePolicy.Conditions.Users.IncludeUsers -contains "All") { "all users" } else { "all cloud apps" }
            Add-Result -ControlNumber "5.2.2.9" -ControlTitle "Ensure a managed device is required for authentication" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Managed device requirement configured ($deviceReq for $scope)"
        }
        else {
            Add-Result -ControlNumber "5.2.2.9" -ControlTitle "Ensure a managed device is required for authentication" `
                       -ProfileLevel "L1" -Result "Fail" -Details "No CA policy requiring managed device for all users or all cloud apps" `
                       -Remediation "Create CA policy targeting all users or all cloud apps requiring compliant or Hybrid Azure AD joined device"
        }
    }
    catch {
        Add-Result -ControlNumber "5.2.2.9" -ControlTitle "Ensure a managed device is required for authentication" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 5.2.2.10 - Ensure a managed device is required to register security information
    try {
        Write-Log "Checking 5.2.2.10 - Managed device for MFA registration" -Level Info
        if ($null -eq $cachedCAPolicies) { throw "Conditional Access policy data unavailable" }
        $caPolicies = $cachedCAPolicies

        # Find policy that targets MFA registration AND requires managed device
        $mfaRegistrationPolicy = $caPolicies | Where-Object {
            $_.Conditions.Applications.IncludeUserActions -contains "urn:user:registersecurityinfo" -and
            $_.State -eq "enabled" -and
            ($_.GrantControls.BuiltInControls -contains "compliantDevice" -or
             $_.GrantControls.BuiltInControls -contains "domainJoinedDevice")
        }

        if ($mfaRegistrationPolicy) {
            $deviceRequirement = if ($mfaRegistrationPolicy.GrantControls.BuiltInControls -contains "compliantDevice") {
                "Compliant device"
            } else {
                "Domain-joined device"
            }
            Add-Result -ControlNumber "5.2.2.10" -ControlTitle "Ensure a managed device is required to register security information" `
                       -ProfileLevel "L1" -Result "Pass" -Details "MFA registration requires managed device: $deviceRequirement (Policy: $($mfaRegistrationPolicy.DisplayName))"
        }
        else {
            Add-Result -ControlNumber "5.2.2.10" -ControlTitle "Ensure a managed device is required to register security information" `
                       -ProfileLevel "L1" -Result "Fail" -Details "No CA policy requiring managed device for MFA registration" `
                       -Remediation "Create CA policy targeting 'Register security information' user action with compliant or domain-joined device requirement"
        }
    }
    catch {
        Add-Result -ControlNumber "5.2.2.10" -ControlTitle "Ensure a managed device is required to register security information" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 5.2.2.11 - Ensure sign-in frequency for Intune Enrollment is set to 'Every time'
    try {
        Write-Log "Checking 5.2.2.11 - Intune enrollment sign-in frequency" -Level Info
        if ($null -eq $cachedCAPolicies) { throw "Conditional Access policy data unavailable" }
        $caPolicies = $cachedCAPolicies

        # Find policy targeting Intune enrollment with 'every time' sign-in frequency
        $intuneEnrollmentPolicy = $caPolicies | Where-Object {
            ($_.Conditions.Applications.IncludeApplications -contains "d4ebce55-015a-49b5-a083-c84d1797ae8c" -or  # Intune Enrollment
             $_.Conditions.Applications.IncludeApplications -contains "0000000a-0000-0000-c000-000000000000") -and  # Intune
            $_.State -eq "enabled" -and
            $_.SessionControls.SignInFrequency -ne $null
        }

        if ($intuneEnrollmentPolicy) {
            $signInFreq = $intuneEnrollmentPolicy.SessionControls.SignInFrequency

            # Check if frequency is set to 'every time' (most restrictive)
            $isEveryTime = $false
            $frequencyDetails = ""

            if ($signInFreq.FrequencyInterval -eq "everyTime") {
                $isEveryTime = $true
                $frequencyDetails = "Sign-in frequency: Every time"
            }
            elseif ($signInFreq.IsEnabled -eq $true) {
                $frequencyDetails = "Sign-in frequency: $($signInFreq.Value) $($signInFreq.Type)"
            }
            else {
                $frequencyDetails = "Sign-in frequency: Not configured properly"
            }

            if ($isEveryTime) {
                Add-Result -ControlNumber "5.2.2.11" -ControlTitle "Ensure sign-in frequency for Intune Enrollment is set to 'Every time'" `
                           -ProfileLevel "L1" -Result "Pass" -Details "$frequencyDetails (Policy: $($intuneEnrollmentPolicy.DisplayName))"
            }
            else {
                Add-Result -ControlNumber "5.2.2.11" -ControlTitle "Ensure sign-in frequency for Intune Enrollment is set to 'Every time'" `
                           -ProfileLevel "L1" -Result "Fail" -Details "$frequencyDetails - Should be 'Every time' (Policy: $($intuneEnrollmentPolicy.DisplayName))" `
                           -Remediation "Update CA policy to set sign-in frequency to 'Every time' for Intune enrollment"
            }
        }
        else {
            Add-Result -ControlNumber "5.2.2.11" -ControlTitle "Ensure sign-in frequency for Intune Enrollment is set to 'Every time'" `
                       -ProfileLevel "L1" -Result "Fail" -Details "No CA policy for Intune enrollment with sign-in frequency" `
                       -Remediation "Create CA policy targeting Intune Enrollment app with 'Every time' sign-in frequency"
        }
    }
    catch {
        Add-Result -ControlNumber "5.2.2.11" -ControlTitle "Ensure sign-in frequency for Intune Enrollment is set to 'Every time'" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 5.2.2.12 - Ensure the device code sign-in flow is blocked
    try {
        Write-Log "Checking 5.2.2.12 - Device code flow blocked" -Level Info

        # Device code flow is blocked via Conditional Access policy with authentication flows condition
        if ($null -eq $cachedCAPolicies) { throw "Conditional Access policy data unavailable" }
        $caPolicies = $cachedCAPolicies

        $deviceCodeBlockPolicy = $caPolicies | Where-Object {
            $_.State -eq "enabled" -and
            $_.Conditions.AuthenticationFlows.TransferMethods -contains "deviceCodeFlow" -and
            $_.GrantControls.BuiltInControls -contains "block"
        }

        if ($deviceCodeBlockPolicy) {
            Add-Result -ControlNumber "5.2.2.12" -ControlTitle "Ensure the device code sign-in flow is blocked" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Device code flow is blocked by CA policy: $($deviceCodeBlockPolicy.DisplayName)"
        }
        else {
            Add-Result -ControlNumber "5.2.2.12" -ControlTitle "Ensure the device code sign-in flow is blocked" `
                       -ProfileLevel "L1" -Result "Fail" -Details "No active CA policy found blocking device code flow" `
                       -Remediation "Create Conditional Access policy: Target 'All users' > Conditions > Authentication flows > Device code flow > Grant > Block access"
        }
    }
    catch {
        Add-Result -ControlNumber "5.2.2.12" -ControlTitle "Ensure the device code sign-in flow is blocked" `
                   -ProfileLevel "L1" -Result "Manual" -Details "Unable to check device code flow policy. Verify manually in Entra ID > Security > Conditional Access" `
                   -Remediation "Create CA policy to block device code authentication flow"
    }

    # Authentication Methods (5.2.3.x)

    # 5.2.3.1 - Ensure Microsoft Authenticator is configured to protect against MFA fatigue
    try {
        Write-Log "Checking 5.2.3.1 - Authenticator MFA fatigue protection" -Level Info
        $authMethodPolicy = Get-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId "MicrosoftAuthenticator" -ErrorAction Stop

        $featureSettings = $authMethodPolicy.AdditionalProperties['featureSettings']

        # Access nested hashtable properties correctly - try multiple access methods
        $numberMatching = $null
        if ($null -ne $featureSettings) {
            if ($null -ne $featureSettings['numberMatchingRequiredState']) {
                $numberMatching = $featureSettings['numberMatchingRequiredState']['state']
            }
            elseif ($null -ne $featureSettings.numberMatchingRequiredState) {
                $numberMatching = $featureSettings.numberMatchingRequiredState.state
            }
        }

        $additionalContext = $null
        if ($null -ne $featureSettings) {
            if ($null -ne $featureSettings['displayAppInformationRequiredState']) {
                $additionalContext = $featureSettings['displayAppInformationRequiredState']['state']
            }
            elseif ($null -ne $featureSettings.displayAppInformationRequiredState) {
                $additionalContext = $featureSettings.displayAppInformationRequiredState.state
            }
        }

        $locationContext = $null
        if ($null -ne $featureSettings) {
            if ($null -ne $featureSettings['displayLocationInformationRequiredState']) {
                $locationContext = $featureSettings['displayLocationInformationRequiredState']['state']
            }
            elseif ($null -ne $featureSettings.displayLocationInformationRequiredState) {
                $locationContext = $featureSettings.displayLocationInformationRequiredState.state
            }
        }

        # Microsoft has made number matching "default" (on by default) as of 2025
        # When the property is missing from the API response, it means it's using the default (enabled) setting
        if (-not $numberMatching) {
            # If numberMatchingRequiredState is missing, it means it's using Microsoft's default (enabled)
            $numberMatching = "default (property absent - using Microsoft default)"
        }
        if (-not $additionalContext) { $additionalContext = "not configured" }
        if (-not $locationContext) { $locationContext = "not configured" }

        # Accept "enabled", "default", or missing property (which means default) as compliant states
        $numberMatchingCompliant = ($numberMatching -eq "enabled" -or $numberMatching -eq "default" -or $numberMatching -eq "default (property absent - using Microsoft default)")
        $additionalContextCompliant = ($additionalContext -eq "enabled" -or $additionalContext -eq "default")
        $locationContextCompliant = ($locationContext -eq "enabled" -or $locationContext -eq "default")

        # CIS 5.2.3.1 requires all three: number matching, app info, and location info
        if ($numberMatchingCompliant -eq $true -and $additionalContextCompliant -eq $true -and $locationContextCompliant -eq $true) {
            Add-Result -ControlNumber "5.2.3.1" -ControlTitle "Ensure Microsoft Authenticator is configured to protect against MFA fatigue" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Number matching: $numberMatching, App context: $additionalContext, Location: $locationContext"
        }
        else {
            Add-Result -ControlNumber "5.2.3.1" -ControlTitle "Ensure Microsoft Authenticator is configured to protect against MFA fatigue" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Number matching: $numberMatching, App context: $additionalContext, Location: $locationContext" `
                       -Remediation "Enable all three settings in Entra ID > Security > Authentication methods > Microsoft Authenticator: (1) Require number matching, (2) Show application name, (3) Show geographic location"
        }
    }
    catch {
        Add-Result -ControlNumber "5.2.3.1" -ControlTitle "Ensure Microsoft Authenticator is configured to protect against MFA fatigue" `
                   -ProfileLevel "L1" -Result "Manual" -Details "Unable to check Authenticator settings. Verify manually." `
                   -Remediation "Check Entra ID > Security > Authentication methods > Microsoft Authenticator"
    }

    # 5.2.3.2 - Ensure custom banned passwords lists are used
    try {
        Write-Log "Checking 5.2.3.2 - Custom banned passwords" -Level Info

        # Try using the authentication strength policy API first (modern approach)
        try {
            $passwordPolicy = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/settings" -ErrorAction SilentlyContinue

            # Look for password settings in directory settings
            $passwordSetting = $passwordPolicy.value | Where-Object {
                $_.displayName -eq "Password Rule Settings" -or
                $_.templateId -eq "5cf42378-d67d-4f36-ba46-e8b86229381d"
            }

            if ($passwordSetting) {
                # Extract BannedPasswordList from values array
                $bannedPasswordsValue = $passwordSetting.values | Where-Object { $_.name -eq "BannedPasswordList" }

                if ($bannedPasswordsValue -and $bannedPasswordsValue.value -and $bannedPasswordsValue.value.Trim() -ne "") {
                    # Count entries (comma or tab delimited)
                    $passwords = $bannedPasswordsValue.value -split "[,\t]" | Where-Object { $_.Trim() -ne "" }
                    $passwordCount = $passwords.Count
                    Add-Result -ControlNumber "5.2.3.2" -ControlTitle "Ensure custom banned passwords lists are used" `
                               -ProfileLevel "L1" -Result "Pass" -Details "Custom banned password list configured with $passwordCount entries"
                }
                else {
                    Add-Result -ControlNumber "5.2.3.2" -ControlTitle "Ensure custom banned passwords lists are used" `
                               -ProfileLevel "L1" -Result "Fail" -Details "Password protection configured but no custom banned passwords defined" `
                               -Remediation "Add custom banned passwords in Entra ID > Security > Authentication methods > Password protection"
                }
            }
            else {
                # Fall back to checking if ANY custom list exists via alternate method
                Add-Result -ControlNumber "5.2.3.2" -ControlTitle "Ensure custom banned passwords lists are used" `
                           -ProfileLevel "L1" -Result "Manual" -Details "Unable to verify custom banned password list via API. Please verify manually in Entra ID portal." `
                           -Remediation "Check Entra ID > Security > Authentication methods > Password protection > Custom banned passwords"
            }
        }
        catch {
            # Final fallback - mark as manual check
            Add-Result -ControlNumber "5.2.3.2" -ControlTitle "Ensure custom banned passwords lists are used" `
                       -ProfileLevel "L1" -Result "Manual" -Details "API access unavailable. Please verify manually that custom banned passwords are configured." `
                       -Remediation "Check Entra ID > Security > Authentication methods > Password protection > Add custom banned passwords (minimum 1 entry)"
        }
    }
    catch {
        Add-Result -ControlNumber "5.2.3.2" -ControlTitle "Ensure custom banned passwords lists are used" `
                   -ProfileLevel "L1" -Result "Manual" -Details "Unable to check banned password list. Verify manually." `
                   -Remediation "Check Entra ID > Security > Authentication methods > Password protection"
    }

    # 5.2.3.3 - Ensure password protection is enabled for on-prem Active Directory
    try {
        Write-Log "Checking 5.2.3.3 - Password protection on-prem AD" -Level Info
        $org = Get-MgOrganization -ErrorAction Stop
        $isHybrid = $org.OnPremisesSyncEnabled

        if (-not $isHybrid) {
            Add-Result -ControlNumber "5.2.3.3" -ControlTitle "Ensure password protection is enabled for on-prem Active Directory" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Cloud-only tenant (no hybrid deployment) - control not applicable"
        }
        else {
            # Hybrid tenant - check password protection on-prem settings via directory settings
            try {
                $passwordPolicy = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/settings" -ErrorAction Stop
                $passwordSetting = $passwordPolicy.value | Where-Object {
                    $_.displayName -eq "Password Rule Settings" -or
                    $_.templateId -eq "5cf42378-d67d-4f36-ba46-e8b86229381d"
                }

                if ($passwordSetting) {
                    $onPremEnabled = ($passwordSetting.values | Where-Object { $_.name -eq "EnableBannedPasswordCheckOnPremises" }).value
                    $onPremMode = ($passwordSetting.values | Where-Object { $_.name -eq "BannedPasswordCheckOnPremisesMode" }).value

                    if ($onPremEnabled -eq "True" -and $onPremMode -eq "Enforce") {
                        Add-Result -ControlNumber "5.2.3.3" -ControlTitle "Ensure password protection is enabled for on-prem Active Directory" `
                                   -ProfileLevel "L1" -Result "Pass" -Details "On-prem password protection enabled in Enforce mode"
                    }
                    elseif ($onPremEnabled -eq "True") {
                        Add-Result -ControlNumber "5.2.3.3" -ControlTitle "Ensure password protection is enabled for on-prem Active Directory" `
                                   -ProfileLevel "L1" -Result "Fail" -Details "On-prem password protection enabled but in '$onPremMode' mode (should be 'Enforce')" `
                                   -Remediation "Set password protection to 'Enforce' mode in Entra ID > Security > Authentication methods > Password protection"
                    }
                    else {
                        Add-Result -ControlNumber "5.2.3.3" -ControlTitle "Ensure password protection is enabled for on-prem Active Directory" `
                                   -ProfileLevel "L1" -Result "Fail" -Details "On-prem password protection is not enabled" `
                                   -Remediation "Enable password protection for on-premises AD in Entra ID > Security > Authentication methods > Password protection"
                    }
                }
                else {
                    Add-Result -ControlNumber "5.2.3.3" -ControlTitle "Ensure password protection is enabled for on-prem Active Directory" `
                               -ProfileLevel "L1" -Result "Manual" -Details "Password protection settings not found via API. Verify manually." `
                               -Remediation "Check Entra ID > Security > Authentication methods > Password protection > Enable on Windows Server Active Directory"
                }
            }
            catch {
                Add-Result -ControlNumber "5.2.3.3" -ControlTitle "Ensure password protection is enabled for on-prem Active Directory" `
                           -ProfileLevel "L1" -Result "Manual" -Details "Hybrid detected but unable to verify on-prem password protection: $_" `
                           -Remediation "Verify Azure AD Password Protection is installed and configured for on-premises AD"
            }
        }
    }
    catch {
        Add-Result -ControlNumber "5.2.3.3" -ControlTitle "Ensure password protection is enabled for on-prem Active Directory" `
                   -ProfileLevel "L1" -Result "Manual" -Details "Unable to determine deployment type: $_" `
                   -Remediation "Install and configure Azure AD Password Protection for on-premises AD"
    }

    # 5.2.3.4 - Ensure all member users are 'MFA capable'
    try {
        Write-Log "Checking 5.2.3.4 - All users MFA capable" -Level Info
        $authMethods = Get-MgReportAuthenticationMethodUserRegistrationDetail -All -ErrorAction Stop
        $nonMfaUsers = $authMethods | Where-Object { $_.IsMfaCapable -eq $false -and $_.UserType -eq "member" }

        if ($nonMfaUsers.Count -eq 0) {
            Add-Result -ControlNumber "5.2.3.4" -ControlTitle "Ensure all member users are 'MFA capable'" `
                       -ProfileLevel "L1" -Result "Pass" -Details "All member users are MFA capable"
        }
        else {
            Add-Result -ControlNumber "5.2.3.4" -ControlTitle "Ensure all member users are 'MFA capable'" `
                       -ProfileLevel "L1" -Result "Fail" -Details "$($nonMfaUsers.Count) users are not MFA capable" `
                       -Remediation "Ensure all users register MFA methods"
        }
    }
    catch {
        $errMsg = "$_"
        if ($errMsg -match "AuditLog.Read.All|Authentication_MSGraphPermissionMissing|403|Forbidden") {
            Add-Result -ControlNumber "5.2.3.4" -ControlTitle "Ensure all member users are 'MFA capable'" `
                       -ProfileLevel "L1" -Result "Error" -Details "Missing required permission: AuditLog.Read.All. Ensure admin consent is granted for this scope in Entra ID > Enterprise Applications > Microsoft Graph > Permissions." `
                       -Remediation "Grant admin consent for AuditLog.Read.All scope, then re-authenticate with Connect-CISM365Benchmark"
        }
        else {
            Add-Result -ControlNumber "5.2.3.4" -ControlTitle "Ensure all member users are 'MFA capable'" `
                       -ProfileLevel "L1" -Result "Error" -Details "Error: $errMsg"
        }
    }

    # 5.2.3.5 - Ensure weak authentication methods are disabled
    try {
        Write-Log "Checking 5.2.3.5 - Weak auth methods disabled" -Level Info
        $smsConfig = Get-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId "Sms" -ErrorAction Stop
        $voiceConfig = Get-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId "Voice" -ErrorAction Stop

        $weakMethods = @()
        if ($smsConfig.State -eq "enabled") { $weakMethods += "SMS" }
        if ($voiceConfig.State -eq "enabled") { $weakMethods += "Voice" }

        if ($weakMethods.Count -eq 0) {
            Add-Result -ControlNumber "5.2.3.5" -ControlTitle "Ensure weak authentication methods are disabled" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Weak authentication methods (SMS, Voice) are disabled"
        }
        else {
            Add-Result -ControlNumber "5.2.3.5" -ControlTitle "Ensure weak authentication methods are disabled" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Weak methods enabled: $($weakMethods -join ', ')" `
                       -Remediation "Disable SMS and Voice authentication methods in Entra ID > Security > Authentication methods"
        }
    }
    catch {
        Add-Result -ControlNumber "5.2.3.5" -ControlTitle "Ensure weak authentication methods are disabled" `
                   -ProfileLevel "L1" -Result "Manual" -Details "Unable to check authentication methods. Verify manually." `
                   -Remediation "Check Entra ID > Security > Authentication methods"
    }

    # 5.2.3.6 - Ensure system-preferred multifactor authentication is enabled
    try {
        Write-Log "Checking 5.2.3.6 - System-preferred MFA" -Level Info
        # Use direct beta API call to get systemCredentialPreferences (SDK may not deserialize it)
        $authMethodsPolicy = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy" -ErrorAction Stop

        $systemCredPrefs = $authMethodsPolicy.systemCredentialPreferences

        # Check if system-preferred MFA is enabled
        if ($systemCredPrefs -and $systemCredPrefs.state -eq "enabled") {
            Add-Result -ControlNumber "5.2.3.6" -ControlTitle "Ensure system-preferred multifactor authentication is enabled" `
                       -ProfileLevel "L1" -Result "Pass" -Details "System-preferred MFA is enabled"
        }
        elseif ($systemCredPrefs -and $systemCredPrefs.state -eq "disabled") {
            Add-Result -ControlNumber "5.2.3.6" -ControlTitle "Ensure system-preferred multifactor authentication is enabled" `
                       -ProfileLevel "L1" -Result "Fail" -Details "System-preferred MFA is disabled" `
                       -Remediation "Enable system-preferred MFA in Entra ID > Security > Authentication methods > Settings"
        }
        elseif ($systemCredPrefs -and $systemCredPrefs.state -eq "default") {
            Add-Result -ControlNumber "5.2.3.6" -ControlTitle "Ensure system-preferred multifactor authentication is enabled" `
                       -ProfileLevel "L1" -Result "Fail" -Details "System-preferred MFA is set to default (not explicitly enabled)" `
                       -Remediation "Enable system-preferred MFA in Entra ID > Security > Authentication methods > Settings"
        }
        else {
            Add-Result -ControlNumber "5.2.3.6" -ControlTitle "Ensure system-preferred multifactor authentication is enabled" `
                       -ProfileLevel "L1" -Result "Manual" -Details "Unable to determine system-preferred MFA state. Verify manually." `
                       -Remediation "Check Entra ID > Security > Authentication methods > Settings"
        }
    }
    catch {
        Add-Result -ControlNumber "5.2.3.6" -ControlTitle "Ensure system-preferred multifactor authentication is enabled" `
                   -ProfileLevel "L1" -Result "Manual" -Details "Unable to check system-preferred MFA: $_" `
                   -Remediation "Check Entra ID > Security > Authentication methods > Settings"
    }

    # 5.2.3.7 - Ensure the email OTP authentication method is disabled (NEW in v6.0.0)
    try {
        Write-Log "Checking 5.2.3.7 - Email OTP authentication method" -Level Info
        $emailOtpConfig = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/email" -ErrorAction Stop
        if ($emailOtpConfig.state -eq "disabled") {
            Add-Result -ControlNumber "5.2.3.7" -ControlTitle "Ensure the email OTP authentication method is disabled" `
                       -ProfileLevel "L2" -Result "Pass" -Details "Email OTP authentication method is disabled"
        }
        else {
            Add-Result -ControlNumber "5.2.3.7" -ControlTitle "Ensure the email OTP authentication method is disabled" `
                       -ProfileLevel "L2" -Result "Fail" -Details "Email OTP authentication method is '$($emailOtpConfig.state)'" `
                       -Remediation "Disable email OTP: Entra ID > Protection > Authentication methods > Policies > Email OTP > Disable"
        }
    }
    catch {
        Add-Result -ControlNumber "5.2.3.7" -ControlTitle "Ensure the email OTP authentication method is disabled" `
                   -ProfileLevel "L2" -Result "Manual" -Details "Unable to check email OTP status: $_" `
                   -Remediation "Navigate to Entra ID > Protection > Authentication methods > Policies and disable the Email OTP method"
    }

    # Password Reset

    # 5.2.4.1 - Ensure 'Self service password reset enabled' is set to 'All'
    # NOTE: This is a MANUAL control - Microsoft does not provide a Graph API to check SSPR scope (All vs Selected)
    # The authorizationPolicy.allowedToUseSSPR only applies to ADMINISTRATORS, not regular users
    # Per Microsoft: "There is no method currently, be it via API or PowerShell, to change the SSPR settings for enabling SSPR for all users vs. selected users/groups"
    Add-Result -ControlNumber "5.2.4.1" -ControlTitle "Ensure 'Self service password reset enabled' is set to 'All'" `
               -ProfileLevel "L1" -Result "Manual" -Details "Check Entra ID > Password reset > Properties > 'Self service password reset enabled' should be set to 'All'" `
               -Remediation "Navigate to Entra ID > Password reset > Properties and verify 'Self service password reset enabled' is set to 'All' (not 'Selected' or 'None')"

    # Identity Governance (5.3.x)

    # 5.3.1 - Ensure 'Privileged Identity Management' is used to manage roles
    try {
        Write-Log "Checking 5.3.1 - PIM configured" -Level Info
        $pimRoles = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules"

        if ($pimRoles.value.Count -gt 0) {
            Add-Result -ControlNumber "5.3.1" -ControlTitle "Ensure 'Privileged Identity Management' is used to manage roles" `
                       -ProfileLevel "L2" -Result "Pass" -Details "PIM role assignments found: $($pimRoles.value.Count) eligible assignments"
        }
        else {
            Add-Result -ControlNumber "5.3.1" -ControlTitle "Ensure 'Privileged Identity Management' is used to manage roles" `
                       -ProfileLevel "L2" -Result "Fail" -Details "No PIM role assignments found" `
                       -Remediation "Configure Privileged Identity Management for all admin roles"
        }
    }
    catch {
        Add-Result -ControlNumber "5.3.1" -ControlTitle "Ensure 'Privileged Identity Management' is used to manage roles" `
                   -ProfileLevel "L2" -Result "Manual" -Details "Unable to check PIM configuration. Verify manually." `
                   -Remediation "Check PIM configuration in Entra ID > Identity Governance > Privileged Identity Management"
    }

    # 5.3.2 - Ensure 'Access reviews' for Guest Users are configured
    try {
        Write-Log "Checking 5.3.2 - Guest user access reviews" -Level Info
        $accessReviews = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/identityGovernance/accessReviews/definitions"

        $guestReviews = $accessReviews.value | Where-Object {
            $_.scope.query -match "userType" -or $_.scope.query -match "guest"
        }

        if ($guestReviews.Count -gt 0) {
            Add-Result -ControlNumber "5.3.2" -ControlTitle "Ensure 'Access reviews' for Guest Users are configured" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Guest user access reviews configured: $($guestReviews.Count) reviews"
        }
        else {
            Add-Result -ControlNumber "5.3.2" -ControlTitle "Ensure 'Access reviews' for Guest Users are configured" `
                       -ProfileLevel "L1" -Result "Fail" -Details "No guest user access reviews configured" `
                       -Remediation "Configure recurring access reviews for guest users"
        }
    }
    catch {
        Add-Result -ControlNumber "5.3.2" -ControlTitle "Ensure 'Access reviews' for Guest Users are configured" `
                   -ProfileLevel "L1" -Result "Manual" -Details "Unable to check access reviews. Verify manually." `
                   -Remediation "Check Entra ID > Identity Governance > Access reviews"
    }

    # 5.3.3 - Ensure 'Access reviews' for privileged roles are configured
    try {
        Write-Log "Checking 5.3.3 - Privileged role access reviews" -Level Info
        $pimAccessReviews = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/identityGovernance/accessReviews/definitions" -ErrorAction SilentlyContinue

        $roleReviews = $pimAccessReviews.value | Where-Object {
            $_.scope.'@odata.type' -match "principalResourceMembershipsScope" -or
            $_.scope.query -match "roleDefinition"
        }

        if ($roleReviews.Count -gt 0) {
            Add-Result -ControlNumber "5.3.3" -ControlTitle "Ensure 'Access reviews' for privileged roles are configured" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Privileged role access reviews configured: $($roleReviews.Count) reviews"
        }
        else {
            Add-Result -ControlNumber "5.3.3" -ControlTitle "Ensure 'Access reviews' for privileged roles are configured" `
                       -ProfileLevel "L1" -Result "Fail" -Details "No privileged role access reviews configured" `
                       -Remediation "Configure access reviews for all privileged roles in PIM"
        }
    }
    catch {
        Add-Result -ControlNumber "5.3.3" -ControlTitle "Ensure 'Access reviews' for privileged roles are configured" `
                   -ProfileLevel "L1" -Result "Manual" -Details "Unable to check role access reviews. Verify manually." `
                   -Remediation "Check PIM > Access reviews"
    }

    # 5.3.4 - Ensure approval is required for Global Administrator role activation
    try {
        Write-Log "Checking 5.3.4 - Global Admin approval requirement" -Level Info
        $globalAdminRole = Get-MgDirectoryRole -All -ErrorAction Stop | Where-Object { $_.DisplayName -eq "Global Administrator" }
        $pimPolicyGlobalAdmin = Get-MgPolicyRoleManagementPolicyAssignment -Filter "scopeId eq '/' and scopeType eq 'Directory' and RoleDefinitionId eq '$($globalAdminRole.RoleTemplateId)'" -ExpandProperty "policy(`$expand=rules)" -ErrorAction Stop
        $globalAdminApprovalRule = $pimPolicyGlobalAdmin.Policy.Rules | Where-Object { $_.Id -eq "Approval_EndUser_Assignment" }

        if ($globalAdminApprovalRule.AdditionalProperties.setting.isApprovalRequired -eq $true) {
            Add-Result -ControlNumber "5.3.4" -ControlTitle "Ensure approval is required for Global Administrator role activation" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Approval required for Global Administrator activation"
        }
        else {
            Add-Result -ControlNumber "5.3.4" -ControlTitle "Ensure approval is required for Global Administrator role activation" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Approval not required for Global Administrator activation" `
                       -Remediation "Require approval for Global Administrator role activation in PIM"
        }
    }
    catch {
        Add-Result -ControlNumber "5.3.4" -ControlTitle "Ensure approval is required for Global Administrator role activation" `
                   -ProfileLevel "L1" -Result "Manual" -Details "Unable to check Global Admin PIM settings. Verify manually." `
                   -Remediation "Check PIM > Azure AD roles > Role settings > Global Administrator"
    }

    # 5.3.5 - Ensure approval is required for Privileged Role Administrator activation
    try {
        Write-Log "Checking 5.3.5 - Privileged Role Admin approval requirement" -Level Info
        $privilegedRoleAdmin = Get-MgDirectoryRole -All -ErrorAction Stop | Where-Object { $_.DisplayName -eq "Privileged Role Administrator" }
        $pimPolicyPrivRoleAdmin = Get-MgPolicyRoleManagementPolicyAssignment -Filter "scopeId eq '/' and scopeType eq 'Directory' and RoleDefinitionId eq '$($privilegedRoleAdmin.RoleTemplateId)'" -ExpandProperty "policy(`$expand=rules)" -ErrorAction Stop
        $privRoleAdminApprovalRule = $pimPolicyPrivRoleAdmin.Policy.Rules | Where-Object { $_.Id -eq "Approval_EndUser_Assignment" }

        if ($privRoleAdminApprovalRule.AdditionalProperties.setting.isApprovalRequired -eq $true) {
            Add-Result -ControlNumber "5.3.5" -ControlTitle "Ensure approval is required for Privileged Role Administrator activation" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Approval required for Privileged Role Administrator activation"
        }
        else {
            Add-Result -ControlNumber "5.3.5" -ControlTitle "Ensure approval is required for Privileged Role Administrator activation" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Approval not required for Privileged Role Administrator activation" `
                       -Remediation "Require approval for Privileged Role Administrator activation in PIM"
        }
    }
    catch {
        Add-Result -ControlNumber "5.3.5" -ControlTitle "Ensure approval is required for Privileged Role Administrator activation" `
                   -ProfileLevel "L1" -Result "Manual" -Details "Unable to check Privileged Role Admin PIM settings. Verify manually." `
                   -Remediation "Check PIM > Azure AD roles > Role settings > Privileged Role Administrator"
    }
}

#endregion

#region Section 6: Exchange Admin Center

function Test-ExchangeOnline {
    Write-Log "Checking Section 6: Exchange Admin Center..." -Level Info

    # Pre-fetch shared data for this section
    $cachedOrgConfig = $null
    try { $cachedOrgConfig = Get-OrganizationConfig } catch { Write-Log "Warning: Could not retrieve OrganizationConfig. Related checks will report errors." -Level Warning }

    # 6.1.1 - Ensure 'AuditDisabled' organizationally is set to 'False'
    try {
        Write-Log "Checking 6.1.1 - Organization audit enabled" -Level Info
        if ($null -eq $cachedOrgConfig) { throw "OrganizationConfig data unavailable" }
        $orgConfig = $cachedOrgConfig

        if ($orgConfig.AuditDisabled -eq $false) {
            Add-Result -ControlNumber "6.1.1" -ControlTitle "Ensure 'AuditDisabled' organizationally is set to 'False'" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Organization auditing is enabled"
        }
        else {
            Add-Result -ControlNumber "6.1.1" -ControlTitle "Ensure 'AuditDisabled' organizationally is set to 'False'" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Organization auditing is disabled" `
                       -Remediation "Set-OrganizationConfig -AuditDisabled `$false"
        }
    }
    catch {
        Add-Result -ControlNumber "6.1.1" -ControlTitle "Ensure 'AuditDisabled' organizationally is set to 'False'" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 6.1.2 - Ensure mailbox audit actions are configured
    try {
        Write-Log "Checking 6.1.2 - Mailbox audit actions" -Level Info
        if ($null -eq $cachedOrgConfig) { throw "OrganizationConfig data unavailable" }
        $orgConfig = $cachedOrgConfig

        # Required audit actions per CIS Benchmark v6.0.0
        $requiredOwnerActions = @("Create", "HardDelete", "MailboxLogin", "Move", "MoveToDeletedItems", "SoftDelete", "Update")
        $requiredDelegateActions = @("Create", "HardDelete", "Move", "MoveToDeletedItems", "SendAs", "SendOnBehalf", "SoftDelete", "Update")
        $requiredAdminActions = @("Copy", "Create", "HardDelete", "Move", "MoveToDeletedItems", "SendAs", "SendOnBehalf", "SoftDelete", "Update")

        # Sample mailboxes to verify audit actions
        $sampleSize = 50
        $mailboxes = Get-Mailbox -ResultSize $sampleSize | Select-Object UserPrincipalName, AuditEnabled, AuditOwner, AuditDelegate, AuditAdmin, DefaultAuditSet

        $compliantMailboxes = 0
        $nonCompliantDetails = @()

        foreach ($mbx in $mailboxes) {
            if ($mbx.AuditEnabled -eq $true) {
                # DefaultAuditSet indicates which sign-in types use Microsoft's default audit actions.
                # Microsoft's defaults meet or exceed CIS requirements, so if a type is in DefaultAuditSet,
                # it is compliant even if AuditOwner/AuditDelegate/AuditAdmin properties appear empty.
                # See: https://learn.microsoft.com/en-us/purview/audit-mailboxes
                $defaultSet = @($mbx.DefaultAuditSet)
                $usingOwnerDefaults = $defaultSet -contains "Owner"
                $usingDelegateDefaults = $defaultSet -contains "Delegate"
                $usingAdminDefaults = $defaultSet -contains "Admin"

                # Only check specific actions when NOT using defaults for that sign-in type
                $ownerMissing = if ($usingOwnerDefaults) { @() } else { @($requiredOwnerActions | Where-Object { $mbx.AuditOwner -notcontains $_ }) }
                $delegateMissing = if ($usingDelegateDefaults) { @() } else { @($requiredDelegateActions | Where-Object { $mbx.AuditDelegate -notcontains $_ }) }
                $adminMissing = if ($usingAdminDefaults) { @() } else { @($requiredAdminActions | Where-Object { $mbx.AuditAdmin -notcontains $_ }) }

                if ($ownerMissing.Count -eq 0 -and $delegateMissing.Count -eq 0 -and $adminMissing.Count -eq 0) {
                    $compliantMailboxes++
                }
                else {
                    $nonCompliantDetails += "$($mbx.UserPrincipalName): Missing owner:$($ownerMissing.Count), delegate:$($delegateMissing.Count), admin:$($adminMissing.Count) actions"
                }
            }
            else {
                $nonCompliantDetails += "$($mbx.UserPrincipalName): Auditing disabled"
            }
        }

        $mailboxCount = @($mailboxes).Count
        if ($orgConfig.AuditDisabled -eq $false -and $compliantMailboxes -eq $mailboxCount) {
            Add-Result -ControlNumber "6.1.2" -ControlTitle "Ensure mailbox audit actions are configured" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Mailbox auditing enabled org-wide with proper audit actions (sampled $mailboxCount of $sampleSize requested mailboxes)"
        }
        elseif ($orgConfig.AuditDisabled -eq $true) {
            Add-Result -ControlNumber "6.1.2" -ControlTitle "Ensure mailbox audit actions are configured" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Mailbox auditing disabled at organization level" `
                       -Remediation "Set-OrganizationConfig -AuditDisabled `$false"
        }
        else {
            # Show up to 5 examples of non-compliant mailboxes
            $exampleCount = [Math]::Min(5, $nonCompliantDetails.Count)
            $detailsStr = $nonCompliantDetails[0..($exampleCount-1)] -join "; "
            $complianceRate = if ($mailboxCount -gt 0) { [Math]::Round(($compliantMailboxes / $mailboxCount) * 100, 1) } else { 0 }

            Add-Result -ControlNumber "6.1.2" -ControlTitle "Ensure mailbox audit actions are configured" `
                       -ProfileLevel "L1" -Result "Fail" -Details "$($nonCompliantDetails.Count) of $mailboxCount sampled mailboxes ($complianceRate% compliant) missing required audit actions. Examples: $detailsStr" `
                       -Remediation "Ensure default mailbox auditing is enabled and not overridden. Run: Get-Mailbox <user> | Select DefaultAuditSet to check if defaults are in use. To restore defaults: Set-Mailbox <user> -DefaultAuditSet Admin,Delegate,Owner"
        }
    }
    catch {
        Add-Result -ControlNumber "6.1.2" -ControlTitle "Ensure mailbox audit actions are configured" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_ - Verify auditing configuration manually" `
                   -Remediation "Check mailbox audit settings in Purview compliance portal"
    }

    # 6.1.3 - Ensure 'AuditBypassEnabled' is not enabled on mailboxes
    try {
        Write-Log "Checking 6.1.3 - Mailbox audit bypass" -Level Info
        # Note: AuditBypassEnabled property may not be available in all Exchange Online versions
        # Using Get-Mailbox instead of Get-EXOMailbox for better compatibility
        try {
            $bypassMailboxes = Get-MailboxAuditBypassAssociation -ResultSize Unlimited |
                               Where-Object { $_.AuditBypassEnabled -eq $true }

            if ($null -eq $bypassMailboxes -or @($bypassMailboxes).Count -eq 0) {
                Add-Result -ControlNumber "6.1.3" -ControlTitle "Ensure 'AuditBypassEnabled' is not enabled on mailboxes" `
                           -ProfileLevel "L1" -Result "Pass" -Details "No mailboxes have audit bypass enabled"
            }
            else {
                $mbList = ($bypassMailboxes | Select-Object -ExpandProperty Identity -First 10) -join ', '
                Add-Result -ControlNumber "6.1.3" -ControlTitle "Ensure 'AuditBypassEnabled' is not enabled on mailboxes" `
                           -ProfileLevel "L1" -Result "Fail" -Details "$($bypassMailboxes.Count) mailboxes have bypass enabled: $mbList" `
                           -Remediation "Disable audit bypass: Set-MailboxAuditBypassAssociation -Identity <mailbox> -AuditBypassEnabled `$false"
            }
        }
        catch {
            # If cmdlet not available, mark as Manual
            Add-Result -ControlNumber "6.1.3" -ControlTitle "Ensure 'AuditBypassEnabled' is not enabled on mailboxes" `
                       -ProfileLevel "L1" -Result "Manual" -Details "Unable to check audit bypass status. Verify manually in Exchange Admin Center." `
                       -Remediation "Check Exchange Admin Center > Recipients > Mailboxes > Audit settings"
        }
    }
    catch {
        Add-Result -ControlNumber "6.1.3" -ControlTitle "Ensure 'AuditBypassEnabled' is not enabled on mailboxes" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 6.2.1 - Ensure all forms of mail forwarding are blocked and/or disabled
    try {
        Write-Log "Checking 6.2.1 - Mail forwarding blocked" -Level Info
        $outboundSpamPolicies = @(Get-HostedOutboundSpamFilterPolicy)
        $nonCompliantPolicies = @()

        foreach ($policy in $outboundSpamPolicies) {
            if ($policy.AutoForwardingMode -ne "Off") {
                $nonCompliantPolicies += "$($policy.Name): AutoForwardingMode=$($policy.AutoForwardingMode)"
            }
        }

        if ($nonCompliantPolicies.Count -eq 0) {
            Add-Result -ControlNumber "6.2.1" -ControlTitle "Ensure all forms of mail forwarding are blocked and/or disabled" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Auto-forwarding is disabled in all $($outboundSpamPolicies.Count) outbound spam policies"
        }
        else {
            Add-Result -ControlNumber "6.2.1" -ControlTitle "Ensure all forms of mail forwarding are blocked and/or disabled" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Auto-forwarding not disabled in: $($nonCompliantPolicies -join '; ')" `
                       -Remediation "Set-HostedOutboundSpamFilterPolicy -Identity <PolicyName> -AutoForwardingMode Off for each non-compliant policy"
        }
    }
    catch {
        Add-Result -ControlNumber "6.2.1" -ControlTitle "Ensure all forms of mail forwarding are blocked and/or disabled" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 6.2.2 - Ensure mail transport rules do not whitelist specific domains
    try {
        Write-Log "Checking 6.2.2 - Transport rules whitelisting" -Level Info
        $transportRules = Get-TransportRule
        $whitelistingRules = @()

        foreach ($rule in $transportRules) {
            if ($rule.SetSCL -eq -1 -or $rule.SetSpamConfidenceLevel -eq -1) {
                $whitelistingRules += $rule.Name
            }
        }

        if ($whitelistingRules.Count -eq 0) {
            Add-Result -ControlNumber "6.2.2" -ControlTitle "Ensure mail transport rules do not whitelist specific domains" `
                       -ProfileLevel "L1" -Result "Pass" -Details "No whitelisting transport rules found"
        }
        else {
            Add-Result -ControlNumber "6.2.2" -ControlTitle "Ensure mail transport rules do not whitelist specific domains" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Whitelisting rules found: $($whitelistingRules -join ', ')" `
                       -Remediation "Remove or modify transport rules that whitelist domains"
        }
    }
    catch {
        Add-Result -ControlNumber "6.2.2" -ControlTitle "Ensure mail transport rules do not whitelist specific domains" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 6.2.3 - Ensure email from external senders is identified
    try {
        Write-Log "Checking 6.2.3 - External email identification" -Level Info
        $externalInOutlook = Get-ExternalInOutlook

        if ($externalInOutlook.Enabled -eq $true) {
            Add-Result -ControlNumber "6.2.3" -ControlTitle "Ensure email from external senders is identified" `
                       -ProfileLevel "L1" -Result "Pass" -Details "External email tagging is enabled"
        }
        else {
            Add-Result -ControlNumber "6.2.3" -ControlTitle "Ensure email from external senders is identified" `
                       -ProfileLevel "L1" -Result "Fail" -Details "External email tagging is disabled" `
                       -Remediation "Enable-ExternalInOutlook"
        }
    }
    catch {
        Add-Result -ControlNumber "6.2.3" -ControlTitle "Ensure email from external senders is identified" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 6.3.1 - Ensure users installing Outlook add-ins is not allowed
    try {
        Write-Log "Checking 6.3.1 - Outlook add-ins restricted" -Level Info
        $roleAssignmentPolicy = Get-RoleAssignmentPolicy -Identity "Default Role Assignment Policy"
        $myMarketplaceApps = Get-ManagementRoleAssignment -RoleAssignee $roleAssignmentPolicy.Identity |
                             Where-Object { $_.Role -eq "My Marketplace Apps" }

        if (-not $myMarketplaceApps) {
            Add-Result -ControlNumber "6.3.1" -ControlTitle "Ensure users installing Outlook add-ins is not allowed" `
                       -ProfileLevel "L2" -Result "Pass" -Details "User add-in installation is restricted"
        }
        else {
            Add-Result -ControlNumber "6.3.1" -ControlTitle "Ensure users installing Outlook add-ins is not allowed" `
                       -ProfileLevel "L2" -Result "Fail" -Details "Users can install add-ins" `
                       -Remediation "Remove 'My Marketplace Apps' role from default policy"
        }
    }
    catch {
        Add-Result -ControlNumber "6.3.1" -ControlTitle "Ensure users installing Outlook add-ins is not allowed" `
                   -ProfileLevel "L2" -Result "Error" -Details "Error: $_"
    }

    # 6.5.1 - Ensure modern authentication for Exchange Online is enabled
    try {
        Write-Log "Checking 6.5.1 - Modern authentication enabled" -Level Info
        if ($null -eq $cachedOrgConfig) { throw "OrganizationConfig data unavailable" }
        $orgConfig = $cachedOrgConfig

        if ($orgConfig.OAuth2ClientProfileEnabled -eq $true) {
            Add-Result -ControlNumber "6.5.1" -ControlTitle "Ensure modern authentication for Exchange Online is enabled" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Modern authentication is enabled"
        }
        else {
            Add-Result -ControlNumber "6.5.1" -ControlTitle "Ensure modern authentication for Exchange Online is enabled" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Modern authentication is disabled" `
                       -Remediation "Set-OrganizationConfig -OAuth2ClientProfileEnabled `$true"
        }
    }
    catch {
        Add-Result -ControlNumber "6.5.1" -ControlTitle "Ensure modern authentication for Exchange Online is enabled" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 6.5.2 - Ensure MailTips are enabled for end users
    try {
        Write-Log "Checking 6.5.2 - MailTips enabled" -Level Info
        if ($null -eq $cachedOrgConfig) { throw "OrganizationConfig data unavailable" }
        $orgConfig = $cachedOrgConfig

        if ($orgConfig.MailTipsAllTipsEnabled -eq $true) {
            Add-Result -ControlNumber "6.5.2" -ControlTitle "Ensure MailTips are enabled for end users" `
                       -ProfileLevel "L1" -Result "Pass" -Details "MailTips are enabled"
        }
        else {
            Add-Result -ControlNumber "6.5.2" -ControlTitle "Ensure MailTips are enabled for end users" `
                       -ProfileLevel "L1" -Result "Fail" -Details "MailTips are not fully enabled" `
                       -Remediation "Set-OrganizationConfig -MailTipsAllTipsEnabled `$true"
        }
    }
    catch {
        Add-Result -ControlNumber "6.5.2" -ControlTitle "Ensure MailTips are enabled for end users" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 6.5.3 - Ensure additional storage providers are restricted in Outlook on the web
    try {
        Write-Log "Checking 6.5.3 - OWA storage providers restricted" -Level Info

        # Get all OWA mailbox policies and check them
        $owaPolicies = Get-OwaMailboxPolicy
        $policiesWithStorageProviders = @()

        foreach ($policy in $owaPolicies) {
            if ($policy.AdditionalStorageProvidersAvailable -eq $true) {
                $policiesWithStorageProviders += $policy.Name
            }
        }

        if ($policiesWithStorageProviders.Count -eq 0) {
            Add-Result -ControlNumber "6.5.3" -ControlTitle "Ensure additional storage providers are restricted in Outlook on the web" `
                       -ProfileLevel "L2" -Result "Pass" -Details "Third-party storage providers are disabled in all OWA policies"
        }
        else {
            Add-Result -ControlNumber "6.5.3" -ControlTitle "Ensure additional storage providers are restricted in Outlook on the web" `
                       -ProfileLevel "L2" -Result "Fail" -Details "Third-party storage providers enabled in policies: $($policiesWithStorageProviders -join ', ')" `
                       -Remediation "Set-OwaMailboxPolicy -Identity <PolicyName> -AdditionalStorageProvidersAvailable `$false for each policy"
        }
    }
    catch {
        Add-Result -ControlNumber "6.5.3" -ControlTitle "Ensure additional storage providers are restricted in Outlook on the web" `
                   -ProfileLevel "L2" -Result "Error" -Details "Error: $_"
    }

    # 6.5.4 - Ensure SMTP AUTH is disabled
    try {
        Write-Log "Checking 6.5.4 - SMTP AUTH disabled" -Level Info
        $transportConfig = Get-TransportConfig

        if ($transportConfig.SmtpClientAuthenticationDisabled -eq $true) {
            Add-Result -ControlNumber "6.5.4" -ControlTitle "Ensure SMTP AUTH is disabled" `
                       -ProfileLevel "L1" -Result "Pass" -Details "SMTP AUTH is disabled"
        }
        else {
            Add-Result -ControlNumber "6.5.4" -ControlTitle "Ensure SMTP AUTH is disabled" `
                       -ProfileLevel "L1" -Result "Fail" -Details "SMTP AUTH is enabled" `
                       -Remediation "Set-TransportConfig -SmtpClientAuthenticationDisabled `$true"
        }
    }
    catch {
        Add-Result -ControlNumber "6.5.4" -ControlTitle "Ensure SMTP AUTH is disabled" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }
    # 6.5.5 - Ensure Direct Send submissions are rejected (NEW in v6.0.0)
    try {
        Write-Log "Checking 6.5.5 - Direct Send submissions rejected" -Level Info
        if ($null -eq $cachedOrgConfig) { throw "OrganizationConfig data unavailable" }
        # RejectDirectSend property was added in 2025 Exchange module updates
        $rejectDirectSendProp = $cachedOrgConfig | Get-Member -Name "RejectDirectSend" -ErrorAction SilentlyContinue
        if ($rejectDirectSendProp) {
            if ($cachedOrgConfig.RejectDirectSend -eq $true) {
                Add-Result -ControlNumber "6.5.5" -ControlTitle "Ensure Direct Send submissions are rejected" `
                           -ProfileLevel "L2" -Result "Pass" -Details "Direct Send submissions are rejected"
            }
            else {
                Add-Result -ControlNumber "6.5.5" -ControlTitle "Ensure Direct Send submissions are rejected" `
                           -ProfileLevel "L2" -Result "Fail" -Details "Direct Send submissions are not rejected" `
                           -Remediation "Set-OrganizationConfig -RejectDirectSend `$true"
            }
        }
        else {
            Add-Result -ControlNumber "6.5.5" -ControlTitle "Ensure Direct Send submissions are rejected" `
                       -ProfileLevel "L2" -Result "Manual" -Details "RejectDirectSend property not available (requires latest EXO module). Verify manually." `
                       -Remediation "Update ExchangeOnlineManagement module and run: Set-OrganizationConfig -RejectDirectSend `$true"
        }
    }
    catch {
        Add-Result -ControlNumber "6.5.5" -ControlTitle "Ensure Direct Send submissions are rejected" `
                   -ProfileLevel "L2" -Result "Manual" -Details "Unable to check: $_" `
                   -Remediation "Configure Exchange Online to reject Direct Send submissions"
    }
}

#endregion

#region Section 7: SharePoint Admin Center

function Test-SharePointOnline {
    Write-Log "Checking Section 7: SharePoint Admin Center..." -Level Info

    # Pre-fetch shared data for this section
    $cachedSPOTenant = $null
    try { $cachedSPOTenant = Get-SPOTenant } catch { Write-Log "Warning: Could not retrieve SPO Tenant configuration. Related checks will report errors." -Level Warning }

    # 7.2.1 - Ensure modern authentication for SharePoint applications is required
    try {
        Write-Log "Checking 7.2.1 - SharePoint modern authentication" -Level Info
        if ($null -eq $cachedSPOTenant) { throw "SPO Tenant data unavailable" }
        $spoTenant = $cachedSPOTenant

        if ($spoTenant.LegacyAuthProtocolsEnabled -eq $false) {
            Add-Result -ControlNumber "7.2.1" -ControlTitle "Ensure modern authentication for SharePoint applications is required" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Legacy authentication is disabled"
        }
        else {
            Add-Result -ControlNumber "7.2.1" -ControlTitle "Ensure modern authentication for SharePoint applications is required" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Legacy authentication is enabled" `
                       -Remediation "Set-SPOTenant -LegacyAuthProtocolsEnabled `$false"
        }
    }
    catch {
        Add-Result -ControlNumber "7.2.1" -ControlTitle "Ensure modern authentication for SharePoint applications is required" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 7.2.2 - Ensure SharePoint and OneDrive integration with Azure AD B2B is enabled
    try {
        Write-Log "Checking 7.2.2 - SharePoint Azure AD B2B integration" -Level Info
        if ($null -eq $cachedSPOTenant) { throw "SPO Tenant data unavailable" }
        $spoTenant = $cachedSPOTenant

        if ($spoTenant.EnableAzureADB2BIntegration -eq $true) {
            Add-Result -ControlNumber "7.2.2" -ControlTitle "Ensure SharePoint and OneDrive integration with Azure AD B2B is enabled" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Azure AD B2B integration is enabled"
        }
        else {
            Add-Result -ControlNumber "7.2.2" -ControlTitle "Ensure SharePoint and OneDrive integration with Azure AD B2B is enabled" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Azure AD B2B integration is disabled" `
                       -Remediation "Set-SPOTenant -EnableAzureADB2BIntegration `$true"
        }
    }
    catch {
        Add-Result -ControlNumber "7.2.2" -ControlTitle "Ensure SharePoint and OneDrive integration with Azure AD B2B is enabled" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 7.2.3 - Ensure external content sharing is restricted
    try {
        Write-Log "Checking 7.2.3 - External sharing restricted" -Level Info
        if ($null -eq $cachedSPOTenant) { throw "SPO Tenant data unavailable" }
        $spoTenant = $cachedSPOTenant

        # Normalize the sharing capability value (trim whitespace and handle string type)
        $sharingValue = $spoTenant.SharingCapability.ToString().Trim()

        # Acceptable values per CIS Benchmark:
        # - ExternalUserSharingOnly (New and existing guests) - Recommended for secure collaboration
        # - ExistingExternalUserSharingOnly (Existing guests only) - More restrictive
        # - Disabled (Only people in your organization) - Most restrictive
        # NOT acceptable: ExternalUserAndGuestSharing (Anyone)

        $acceptableValues = @("ExternalUserSharingOnly", "ExistingExternalUserSharingOnly", "Disabled")

        if ($sharingValue -in $acceptableValues) {
            Add-Result -ControlNumber "7.2.3" -ControlTitle "Ensure external content sharing is restricted" `
                       -ProfileLevel "L1" -Result "Pass" -Details "External sharing: $sharingValue (compliant)"
        }
        else {
            Add-Result -ControlNumber "7.2.3" -ControlTitle "Ensure external content sharing is restricted" `
                       -ProfileLevel "L1" -Result "Fail" -Details "External sharing too permissive: $sharingValue" `
                       -Remediation "Set-SPOTenant -SharingCapability ExternalUserSharingOnly"
        }
    }
    catch {
        Add-Result -ControlNumber "7.2.3" -ControlTitle "Ensure external content sharing is restricted" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 7.2.4 - Ensure OneDrive content sharing is restricted
    try {
        Write-Log "Checking 7.2.4 - OneDrive sharing restricted" -Level Info
        if ($null -eq $cachedSPOTenant) { throw "SPO Tenant data unavailable" }
        $spoTenant = $cachedSPOTenant

        # L2: Accept ExistingExternalUserSharingOnly, ExternalUserSharingOnly (New and existing guests), or Disabled
        # OneDrive sharing should be restrictive but can allow collaboration with external users
        if ($spoTenant.OneDriveSharingCapability -eq "ExistingExternalUserSharingOnly" -or
            $spoTenant.OneDriveSharingCapability -eq "ExternalUserSharingOnly" -or
            $spoTenant.OneDriveSharingCapability -eq "Disabled") {
            Add-Result -ControlNumber "7.2.4" -ControlTitle "Ensure OneDrive content sharing is restricted" `
                       -ProfileLevel "L2" -Result "Pass" -Details "OneDrive sharing: $($spoTenant.OneDriveSharingCapability)"
        }
        else {
            Add-Result -ControlNumber "7.2.4" -ControlTitle "Ensure OneDrive content sharing is restricted" `
                       -ProfileLevel "L2" -Result "Fail" -Details "OneDrive sharing too permissive: $($spoTenant.OneDriveSharingCapability)" `
                       -Remediation "Set-SPOTenant -OneDriveSharingCapability ExternalUserSharingOnly or more restrictive"
        }
    }
    catch {
        Add-Result -ControlNumber "7.2.4" -ControlTitle "Ensure OneDrive content sharing is restricted" `
                   -ProfileLevel "L2" -Result "Error" -Details "Error: $_"
    }

    # 7.2.5 - Ensure that SharePoint guest users cannot share items they don't own
    try {
        Write-Log "Checking 7.2.5 - Guest re-sharing prevented" -Level Info
        if ($null -eq $cachedSPOTenant) { throw "SPO Tenant data unavailable" }
        $spoTenant = $cachedSPOTenant

        if ($spoTenant.PreventExternalUsersFromResharing -eq $true) {
            Add-Result -ControlNumber "7.2.5" -ControlTitle "Ensure that SharePoint guest users cannot share items they don't own" `
                       -ProfileLevel "L2" -Result "Pass" -Details "Guest re-sharing is prevented"
        }
        else {
            Add-Result -ControlNumber "7.2.5" -ControlTitle "Ensure that SharePoint guest users cannot share items they don't own" `
                       -ProfileLevel "L2" -Result "Fail" -Details "Guests can re-share content" `
                       -Remediation "Set-SPOTenant -PreventExternalUsersFromResharing `$true"
        }
    }
    catch {
        Add-Result -ControlNumber "7.2.5" -ControlTitle "Ensure that SharePoint guest users cannot share items they don't own" `
                   -ProfileLevel "L2" -Result "Error" -Details "Error: $_"
    }

    # 7.2.6 - Ensure SharePoint external sharing is managed through domain whitelist/blacklists
    try {
        Write-Log "Checking 7.2.6 - SharePoint domain restrictions" -Level Info
        if ($null -eq $cachedSPOTenant) { throw "SPO Tenant data unavailable" }
        $spoTenant = $cachedSPOTenant

        if ($spoTenant.SharingDomainRestrictionMode -ne "None") {
            Add-Result -ControlNumber "7.2.6" -ControlTitle "Ensure SharePoint external sharing is managed through domain whitelist/blacklists" `
                       -ProfileLevel "L2" -Result "Pass" -Details "Domain restrictions configured: $($spoTenant.SharingDomainRestrictionMode)"
        }
        else {
            Add-Result -ControlNumber "7.2.6" -ControlTitle "Ensure SharePoint external sharing is managed through domain whitelist/blacklists" `
                       -ProfileLevel "L2" -Result "Fail" -Details "No domain restrictions configured" `
                       -Remediation "Configure domain allow or deny list for external sharing"
        }
    }
    catch {
        Add-Result -ControlNumber "7.2.6" -ControlTitle "Ensure SharePoint external sharing is managed through domain whitelist/blacklists" `
                   -ProfileLevel "L2" -Result "Error" -Details "Error: $_"
    }

    # 7.2.7 - Ensure link sharing is restricted in SharePoint and OneDrive
    try {
        Write-Log "Checking 7.2.7 - Link sharing restricted" -Level Info
        if ($null -eq $cachedSPOTenant) { throw "SPO Tenant data unavailable" }
        $spoTenant = $cachedSPOTenant

        # DefaultSharingLinkType should be Direct (most restrictive)
        if ($spoTenant.DefaultSharingLinkType -eq "Direct") {
            Add-Result -ControlNumber "7.2.7" -ControlTitle "Ensure link sharing is restricted in SharePoint and OneDrive" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Default link type is 'Specific people'"
        }
        else {
            Add-Result -ControlNumber "7.2.7" -ControlTitle "Ensure link sharing is restricted in SharePoint and OneDrive" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Default link type: $($spoTenant.DefaultSharingLinkType)" `
                       -Remediation "Set-SPOTenant -DefaultSharingLinkType Direct"
        }
    }
    catch {
        Add-Result -ControlNumber "7.2.7" -ControlTitle "Ensure link sharing is restricted in SharePoint and OneDrive" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 7.2.8 - Ensure external sharing is restricted by security group
    try {
        Write-Log "Checking 7.2.8 - External sharing restricted by security group" -Level Info
        if ($null -eq $cachedSPOTenant) { throw "SPO Tenant data unavailable" }
        $spoTenant = $cachedSPOTenant

        $allowList = $spoTenant.GuestSharingGroupAllowListInTenantByPrincipalIdentity
        if ($allowList -and $allowList.Trim() -ne "") {
            Add-Result -ControlNumber "7.2.8" -ControlTitle "Ensure external sharing is restricted by security group" `
                       -ProfileLevel "L2" -Result "Pass" -Details "External sharing restricted to security group(s): $allowList"
        }
        else {
            Add-Result -ControlNumber "7.2.8" -ControlTitle "Ensure external sharing is restricted by security group" `
                       -ProfileLevel "L2" -Result "Fail" -Details "External sharing is not restricted to any security group - all users can share externally" `
                       -Remediation "In SharePoint Admin Center > Policies > Sharing > Advanced settings, enable 'Allow only users in specific security groups to share externally' and select a security group"
        }
    }
    catch {
        Add-Result -ControlNumber "7.2.8" -ControlTitle "Ensure external sharing is restricted by security group" `
                   -ProfileLevel "L2" -Result "Error" -Details "Error: $_"
    }

    # 7.2.9 - Ensure guest access to a site or OneDrive will expire automatically
    try {
        Write-Log "Checking 7.2.9 - Guest link expiration" -Level Info
        if ($null -eq $cachedSPOTenant) { throw "SPO Tenant data unavailable" }
        $spoTenant = $cachedSPOTenant

        if ($spoTenant.ExternalUserExpirationRequired -eq $true) {
            Add-Result -ControlNumber "7.2.9" -ControlTitle "Ensure guest access to a site or OneDrive will expire automatically" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Guest link expiration configured: $($spoTenant.ExternalUserExpireInDays) days"
        }
        else {
            Add-Result -ControlNumber "7.2.9" -ControlTitle "Ensure guest access to a site or OneDrive will expire automatically" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Guest link expiration not configured" `
                       -Remediation "Set-SPOTenant -ExternalUserExpirationRequired `$true -ExternalUserExpireInDays 30"
        }
    }
    catch {
        Add-Result -ControlNumber "7.2.9" -ControlTitle "Ensure guest access to a site or OneDrive will expire automatically" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 7.2.10 - Ensure reauthentication with verification code is restricted
    try {
        Write-Log "Checking 7.2.10 - Email verification required" -Level Info
        if ($null -eq $cachedSPOTenant) { throw "SPO Tenant data unavailable" }
        $spoTenant = $cachedSPOTenant

        if ($spoTenant.EmailAttestationRequired -eq $true) {
            Add-Result -ControlNumber "7.2.10" -ControlTitle "Ensure reauthentication with verification code is restricted" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Email verification required for guests"
        }
        else {
            Add-Result -ControlNumber "7.2.10" -ControlTitle "Ensure reauthentication with verification code is restricted" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Email verification not required" `
                       -Remediation "Set-SPOTenant -EmailAttestationRequired `$true"
        }
    }
    catch {
        Add-Result -ControlNumber "7.2.10" -ControlTitle "Ensure reauthentication with verification code is restricted" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 7.2.11 - Ensure the SharePoint default sharing link permission is set
    try {
        Write-Log "Checking 7.2.11 - Default sharing link permission" -Level Info
        if ($null -eq $cachedSPOTenant) { throw "SPO Tenant data unavailable" }
        $spoTenant = $cachedSPOTenant

        if ($spoTenant.DefaultLinkPermission -eq "View") {
            Add-Result -ControlNumber "7.2.11" -ControlTitle "Ensure the SharePoint default sharing link permission is set" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Default permission is 'View'"
        }
        else {
            Add-Result -ControlNumber "7.2.11" -ControlTitle "Ensure the SharePoint default sharing link permission is set" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Default permission: $($spoTenant.DefaultLinkPermission)" `
                       -Remediation "Set-SPOTenant -DefaultLinkPermission View"
        }
    }
    catch {
        Add-Result -ControlNumber "7.2.11" -ControlTitle "Ensure the SharePoint default sharing link permission is set" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 7.3.1 - Ensure Office 365 SharePoint infected files are disallowed for download
    try {
        Write-Log "Checking 7.3.1 - Infected file download blocked" -Level Info
        if ($null -eq $cachedSPOTenant) { throw "SPO Tenant data unavailable" }
        $spoTenant = $cachedSPOTenant

        if ($spoTenant.DisallowInfectedFileDownload -eq $true) {
            Add-Result -ControlNumber "7.3.1" -ControlTitle "Ensure Office 365 SharePoint infected files are disallowed for download" `
                       -ProfileLevel "L2" -Result "Pass" -Details "Infected file download is blocked"
        }
        else {
            Add-Result -ControlNumber "7.3.1" -ControlTitle "Ensure Office 365 SharePoint infected files are disallowed for download" `
                       -ProfileLevel "L2" -Result "Fail" -Details "Infected files can be downloaded" `
                       -Remediation "Set-SPOTenant -DisallowInfectedFileDownload `$true"
        }
    }
    catch {
        Add-Result -ControlNumber "7.3.1" -ControlTitle "Ensure Office 365 SharePoint infected files are disallowed for download" `
                   -ProfileLevel "L2" -Result "Error" -Details "Error: $_"
    }

    # 7.3.2 - Ensure OneDrive sync is restricted for unmanaged devices
    try {
        Write-Log "Checking 7.3.2 - OneDrive sync restriction" -Level Info
        $syncRestriction = Get-SPOTenantSyncClientRestriction -ErrorAction Stop

        if ($syncRestriction.TenantRestrictionEnabled -eq $true) {
            Add-Result -ControlNumber "7.3.2" -ControlTitle "Ensure OneDrive sync is restricted for unmanaged devices" `
                       -ProfileLevel "L2" -Result "Pass" -Details "OneDrive sync restricted for unmanaged devices (TenantRestrictionEnabled: True)"
        }
        else {
            Add-Result -ControlNumber "7.3.2" -ControlTitle "Ensure OneDrive sync is restricted for unmanaged devices" `
                       -ProfileLevel "L2" -Result "Fail" -Details "Unmanaged device sync not restricted (TenantRestrictionEnabled: $($syncRestriction.TenantRestrictionEnabled))" `
                       -Remediation "Set-SPOTenantSyncClientRestriction -Enable -DomainGuids <your-AAD-domain-GUID>"
        }
    }
    catch {
        Add-Result -ControlNumber "7.3.2" -ControlTitle "Ensure OneDrive sync is restricted for unmanaged devices" `
                   -ProfileLevel "L2" -Result "Error" -Details "Error: $_"
    }

    # Controls 7.3.3 and 7.3.4 were removed in CIS Benchmark v6.0.0
}

#endregion

#region Section 8: Microsoft Teams Admin Center

function Test-MicrosoftTeams {
    Write-Log "Checking Section 8: Microsoft Teams Admin Center..." -Level Info

    # Pre-fetch shared data for this section
    $cachedTeamsMeetingPolicy = $null
    $cachedTenantFedConfig = $null
    $cachedTeamsClientConfig = $null

    # Ensure MicrosoftTeams ConfigAPI submodules are fully loaded
    # The nested Microsoft.Teams.ConfigAPI.Cmdlets module may not auto-load in all contexts
    Import-Module MicrosoftTeams -Force -ErrorAction SilentlyContinue

    try { $cachedTeamsMeetingPolicy = Get-CsTeamsMeetingPolicy -Identity Global -ErrorAction Stop } catch { Write-Log "Warning: Could not retrieve Teams meeting policy: $_" -Level Warning }
    try { $cachedTenantFedConfig = Get-CsTenantFederationConfiguration -ErrorAction Stop } catch { Write-Log "Warning: Could not retrieve tenant federation configuration: $_" -Level Warning }
    try { $cachedTeamsClientConfig = Get-CsTeamsClientConfiguration -Identity Global -ErrorAction Stop } catch { Write-Log "Warning: Could not retrieve Teams client configuration: $_" -Level Warning }

    # 8.1.1 - Ensure external file sharing in Teams is enabled for only approved cloud storage services
    try {
        Write-Log "Checking 8.1.1 - Teams external file sharing" -Level Info
        if ($null -eq $cachedTeamsClientConfig) { throw "Teams client configuration data unavailable" }
        $teamsClientConfig = $cachedTeamsClientConfig

        $approvedOnly = $true
        if ($teamsClientConfig.AllowDropbox -eq $true -or
            $teamsClientConfig.AllowBox -eq $true -or
            $teamsClientConfig.AllowGoogleDrive -eq $true -or
            $teamsClientConfig.AllowShareFile -eq $true -or
            $teamsClientConfig.AllowEgnyte -eq $true) {
            $approvedOnly = $false
        }

        if ($approvedOnly) {
            Add-Result -ControlNumber "8.1.1" -ControlTitle "Ensure external file sharing in Teams is enabled for only approved cloud storage services" `
                       -ProfileLevel "L2" -Result "Pass" -Details "Third-party storage restricted"
        }
        else {
            Add-Result -ControlNumber "8.1.1" -ControlTitle "Ensure external file sharing in Teams is enabled for only approved cloud storage services" `
                       -ProfileLevel "L2" -Result "Fail" -Details "Third-party storage services enabled" `
                       -Remediation "Disable unapproved third-party storage providers"
        }
    }
    catch {
        Add-Result -ControlNumber "8.1.1" -ControlTitle "Ensure external file sharing in Teams is enabled for only approved cloud storage services" `
                   -ProfileLevel "L2" -Result "Error" -Details "Error: $_"
    }

    # 8.1.2 - Ensure users can't send emails to a channel email address
    try {
        Write-Log "Checking 8.1.2 - Channel email disabled" -Level Info
        if ($null -eq $cachedTeamsClientConfig) { throw "Teams client configuration data unavailable" }
        $teamsClientConfig = $cachedTeamsClientConfig

        if ($teamsClientConfig.AllowEmailIntoChannel -eq $false) {
            Add-Result -ControlNumber "8.1.2" -ControlTitle "Ensure users can't send emails to a channel email address" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Channel email is disabled"
        }
        else {
            Add-Result -ControlNumber "8.1.2" -ControlTitle "Ensure users can't send emails to a channel email address" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Channel email is enabled" `
                       -Remediation "Set-CsTeamsClientConfiguration -Identity Global -AllowEmailIntoChannel `$false"
        }
    }
    catch {
        Add-Result -ControlNumber "8.1.2" -ControlTitle "Ensure users can't send emails to a channel email address" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 8.2.1 - Ensure external domains are restricted in the Teams admin center
    try {
        Write-Log "Checking 8.2.1 - External domains restricted" -Level Info
        $externalAccessPolicy = Get-CsExternalAccessPolicy -Identity Global -ErrorAction Stop
        if ($null -eq $cachedTenantFedConfig) { throw "Tenant federation configuration data unavailable" }
        $tenantFedConfig = $cachedTenantFedConfig

        # Check if external access is disabled OR if using an allowlist approach
        $isRestricted = $false
        $details = ""

        if ($externalAccessPolicy.EnableFederationAccess -eq $false) {
            $isRestricted = $true
            $details = "Federation access is disabled"
        }
        elseif ($tenantFedConfig.AllowFederatedUsers -eq $false) {
            $isRestricted = $true
            $details = "Federated users are blocked"
        }
        elseif ($tenantFedConfig.AllowedDomains -and
                $tenantFedConfig.AllowedDomains.AllowedDomain -and
                $tenantFedConfig.AllowedDomains.AllowedDomain.Count -gt 0) {
            # Allowlist is configured (restrictive mode)
            $isRestricted = $true
            $details = "External access restricted to allowlist ($($tenantFedConfig.AllowedDomains.AllowedDomain.Count) domains)"
        }
        elseif ($tenantFedConfig.BlockedDomains -and
                $tenantFedConfig.BlockedDomains.Count -eq 0 -and
                $tenantFedConfig.AllowPublicUsers -eq $true) {
            # Open federation - not restricted
            $isRestricted = $false
            $details = "External access is open to all domains (not restricted)"
        }
        else {
            $details = "External access configuration unclear - verify manually"
        }

        if ($isRestricted) {
            Add-Result -ControlNumber "8.2.1" -ControlTitle "Ensure external domains are restricted in the Teams admin center" `
                       -ProfileLevel "L2" -Result "Pass" -Details $details
        }
        else {
            Add-Result -ControlNumber "8.2.1" -ControlTitle "Ensure external domains are restricted in the Teams admin center" `
                       -ProfileLevel "L2" -Result "Fail" -Details $details `
                       -Remediation "Restrict external access: either disable federation or configure allowed domains list"
        }
    }
    catch {
        Add-Result -ControlNumber "8.2.1" -ControlTitle "Ensure external domains are restricted in the Teams admin center" `
                   -ProfileLevel "L2" -Result "Error" -Details "Error: $_"
    }

    # 8.2.2 - Ensure communication with unmanaged Teams users is disabled
    try {
        Write-Log "Checking 8.2.2 - Unmanaged Teams users blocked" -Level Info
        if ($null -eq $cachedTenantFedConfig) { throw "Tenant federation configuration data unavailable" }
        $tenantFedConfig = $cachedTenantFedConfig

        if ($tenantFedConfig.AllowTeamsConsumer -eq $false) {
            Add-Result -ControlNumber "8.2.2" -ControlTitle "Ensure communication with unmanaged Teams users is disabled" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Communication with unmanaged Teams users disabled"
        }
        else {
            Add-Result -ControlNumber "8.2.2" -ControlTitle "Ensure communication with unmanaged Teams users is disabled" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Unmanaged Teams communication allowed" `
                       -Remediation "Set-CsTenantFederationConfiguration -AllowTeamsConsumer `$false"
        }
    }
    catch {
        Add-Result -ControlNumber "8.2.2" -ControlTitle "Ensure communication with unmanaged Teams users is disabled" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 8.2.3 - Ensure external Teams users cannot initiate conversations
    try {
        Write-Log "Checking 8.2.3 - External Teams cannot initiate contact" -Level Info
        if ($null -eq $cachedTenantFedConfig) { throw "Tenant federation configuration data unavailable" }
        $tenantFedConfig = $cachedTenantFedConfig

        if ($tenantFedConfig.AllowTeamsConsumerInbound -eq $false) {
            Add-Result -ControlNumber "8.2.3" -ControlTitle "Ensure external Teams users cannot initiate conversations" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Inbound contact from unmanaged Teams blocked"
        }
        else {
            Add-Result -ControlNumber "8.2.3" -ControlTitle "Ensure external Teams users cannot initiate conversations" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Unmanaged Teams can initiate contact" `
                       -Remediation "Set-CsTenantFederationConfiguration -AllowTeamsConsumerInbound `$false"
        }
    }
    catch {
        Add-Result -ControlNumber "8.2.3" -ControlTitle "Ensure external Teams users cannot initiate conversations" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 8.2.4 - Ensure communication with Skype users is disabled
    try {
        Write-Log "Checking 8.2.4 - Skype communication disabled" -Level Info
        if ($null -eq $cachedTenantFedConfig) { throw "Tenant federation configuration data unavailable" }
        $tenantFedConfig = $cachedTenantFedConfig

        # AllowPublicUsers can be $true, $false, or $null (empty = not configured = disabled)
        if ($tenantFedConfig.AllowPublicUsers -ne $true) {
            Add-Result -ControlNumber "8.2.4" -ControlTitle "Ensure communication with Skype users is disabled" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Skype federation disabled (AllowPublicUsers: $($tenantFedConfig.AllowPublicUsers))"
        }
        else {
            Add-Result -ControlNumber "8.2.4" -ControlTitle "Ensure communication with Skype users is disabled" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Skype federation enabled (AllowPublicUsers: True)" `
                       -Remediation "Set-CsTenantFederationConfiguration -AllowPublicUsers `$false"
        }
    }
    catch {
        Add-Result -ControlNumber "8.2.4" -ControlTitle "Ensure communication with Skype users is disabled" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 8.4.1 - Ensure app permission policies are configured
    try {
        Write-Log "Checking 8.4.1 - Teams app permission policies" -Level Info
        $appPermissionPolicies = Get-CsTeamsAppPermissionPolicy -ErrorAction Stop

        # Check global policy for third-party and custom app restrictions
        $globalPolicy = $appPermissionPolicies | Where-Object { $_.Identity -eq "Global" }

        if ($globalPolicy) {
            # GlobalCatalogAppsType = third-party apps, PrivateCatalogAppsType = custom/org apps
            $thirdPartyRestricted = ($globalPolicy.GlobalCatalogAppsType -eq "BlockedAppList" -or
                                      $globalPolicy.GlobalCatalogAppsType -eq "AllowedAppList")
            $customAppsRestricted = ($globalPolicy.PrivateCatalogAppsType -eq "BlockedAppList" -or
                                     $globalPolicy.PrivateCatalogAppsType -eq "AllowedAppList")

            if ($thirdPartyRestricted -or $customAppsRestricted) {
                Add-Result -ControlNumber "8.4.1" -ControlTitle "Ensure app permission policies are configured" `
                           -ProfileLevel "L1" -Result "Pass" -Details "App permissions restricted (Third-party: $($globalPolicy.GlobalCatalogAppsType), Custom: $($globalPolicy.PrivateCatalogAppsType))"
            }
            else {
                Add-Result -ControlNumber "8.4.1" -ControlTitle "Ensure app permission policies are configured" `
                           -ProfileLevel "L1" -Result "Fail" -Details "App permissions too permissive (Third-party: $($globalPolicy.GlobalCatalogAppsType), Custom: $($globalPolicy.PrivateCatalogAppsType))" `
                           -Remediation "Configure app permission policies to restrict third-party and custom apps using allowlist or blocklist"
            }
        }
        else {
            Add-Result -ControlNumber "8.4.1" -ControlTitle "Ensure app permission policies are configured" `
                       -ProfileLevel "L1" -Result "Fail" -Details "No global app permission policy found" `
                       -Remediation "Configure app permission policies to restrict third-party and custom apps"
        }
    }
    catch {
        Add-Result -ControlNumber "8.4.1" -ControlTitle "Ensure app permission policies are configured" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 8.5.1 - Ensure anonymous users can't join a meeting
    try {
        Write-Log "Checking 8.5.1 - Anonymous meeting join blocked" -Level Info
        if ($null -eq $cachedTeamsMeetingPolicy) { throw "Teams meeting policy data unavailable" }
        $teamsMeetingPolicy = $cachedTeamsMeetingPolicy

        if ($teamsMeetingPolicy.AllowAnonymousUsersToJoinMeeting -eq $false) {
            Add-Result -ControlNumber "8.5.1" -ControlTitle "Ensure anonymous users can't join a meeting" `
                       -ProfileLevel "L2" -Result "Pass" -Details "Anonymous meeting join blocked"
        }
        else {
            Add-Result -ControlNumber "8.5.1" -ControlTitle "Ensure anonymous users can't join a meeting" `
                       -ProfileLevel "L2" -Result "Fail" -Details "Anonymous users can join meetings" `
                       -Remediation "Set-CsTeamsMeetingPolicy -Identity Global -AllowAnonymousUsersToJoinMeeting `$false"
        }
    }
    catch {
        Add-Result -ControlNumber "8.5.1" -ControlTitle "Ensure anonymous users can't join a meeting" `
                   -ProfileLevel "L2" -Result "Error" -Details "Error: $_"
    }

    # 8.5.2 - Ensure anonymous users and dial-in callers can't start a meeting
    try {
        Write-Log "Checking 8.5.2 - Anonymous cannot start meetings" -Level Info
        if ($null -eq $cachedTeamsMeetingPolicy) { throw "Teams meeting policy data unavailable" }
        $teamsMeetingPolicy = $cachedTeamsMeetingPolicy

        if ($teamsMeetingPolicy.AllowAnonymousUsersToStartMeeting -eq $false) {
            Add-Result -ControlNumber "8.5.2" -ControlTitle "Ensure anonymous users and dial-in callers can't start a meeting" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Anonymous users cannot start meetings"
        }
        else {
            Add-Result -ControlNumber "8.5.2" -ControlTitle "Ensure anonymous users and dial-in callers can't start a meeting" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Anonymous users can start meetings" `
                       -Remediation "Set-CsTeamsMeetingPolicy -Identity Global -AllowAnonymousUsersToStartMeeting `$false"
        }
    }
    catch {
        Add-Result -ControlNumber "8.5.2" -ControlTitle "Ensure anonymous users and dial-in callers can't start a meeting" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 8.5.3 - Ensure only people in my org can bypass the lobby
    try {
        Write-Log "Checking 8.5.3 - Lobby bypass restricted" -Level Info
        if ($null -eq $cachedTeamsMeetingPolicy) { throw "Teams meeting policy data unavailable" }
        $teamsMeetingPolicy = $cachedTeamsMeetingPolicy

        if ($teamsMeetingPolicy.AutoAdmittedUsers -eq "EveryoneInCompanyExcludingGuests" -or
            $teamsMeetingPolicy.AutoAdmittedUsers -eq "InvitedUsers") {
            Add-Result -ControlNumber "8.5.3" -ControlTitle "Ensure only people in my org can bypass the lobby" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Lobby bypass restricted: $($teamsMeetingPolicy.AutoAdmittedUsers)"
        }
        else {
            Add-Result -ControlNumber "8.5.3" -ControlTitle "Ensure only people in my org can bypass the lobby" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Lobby bypass too permissive: $($teamsMeetingPolicy.AutoAdmittedUsers)" `
                       -Remediation "Set-CsTeamsMeetingPolicy -AutoAdmittedUsers EveryoneInCompanyExcludingGuests"
        }
    }
    catch {
        Add-Result -ControlNumber "8.5.3" -ControlTitle "Ensure only people in my org can bypass the lobby" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 8.5.4 - Ensure users dialing in can't bypass the lobby
    try {
        Write-Log "Checking 8.5.4 - Dial-in lobby bypass blocked" -Level Info
        if ($null -eq $cachedTeamsMeetingPolicy) { throw "Teams meeting policy data unavailable" }
        $teamsMeetingPolicy = $cachedTeamsMeetingPolicy

        if ($teamsMeetingPolicy.AllowPSTNUsersToBypassLobby -eq $false) {
            Add-Result -ControlNumber "8.5.4" -ControlTitle "Ensure users dialing in can't bypass the lobby" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Dial-in users must wait in lobby"
        }
        else {
            Add-Result -ControlNumber "8.5.4" -ControlTitle "Ensure users dialing in can't bypass the lobby" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Dial-in users can bypass lobby" `
                       -Remediation "Set-CsTeamsMeetingPolicy -Identity Global -AllowPSTNUsersToBypassLobby `$false"
        }
    }
    catch {
        Add-Result -ControlNumber "8.5.4" -ControlTitle "Ensure users dialing in can't bypass the lobby" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 8.5.5 - Ensure meeting chat does not allow anonymous users
    try {
        Write-Log "Checking 8.5.5 - Anonymous chat restricted" -Level Info
        if ($null -eq $cachedTeamsMeetingPolicy) { throw "Teams meeting policy data unavailable" }
        $teamsMeetingPolicy = $cachedTeamsMeetingPolicy

        if ($teamsMeetingPolicy.MeetingChatEnabledType -eq "EnabledExceptAnonymous") {
            Add-Result -ControlNumber "8.5.5" -ControlTitle "Ensure meeting chat does not allow anonymous users" `
                       -ProfileLevel "L2" -Result "Pass" -Details "Anonymous users cannot use meeting chat"
        }
        else {
            Add-Result -ControlNumber "8.5.5" -ControlTitle "Ensure meeting chat does not allow anonymous users" `
                       -ProfileLevel "L2" -Result "Fail" -Details "Chat setting: $($teamsMeetingPolicy.MeetingChatEnabledType)" `
                       -Remediation "Set-CsTeamsMeetingPolicy -MeetingChatEnabledType EnabledExceptAnonymous"
        }
    }
    catch {
        Add-Result -ControlNumber "8.5.5" -ControlTitle "Ensure meeting chat does not allow anonymous users" `
                   -ProfileLevel "L2" -Result "Error" -Details "Error: $_"
    }

    # 8.5.6 - Ensure only organizers and co-organizers can present
    try {
        Write-Log "Checking 8.5.6 - Presenter role restricted" -Level Info
        if ($null -eq $cachedTeamsMeetingPolicy) { throw "Teams meeting policy data unavailable" }
        $teamsMeetingPolicy = $cachedTeamsMeetingPolicy

        if ($teamsMeetingPolicy.DesignatedPresenterRoleMode -eq "OrganizerOnlyUserOverride") {
            Add-Result -ControlNumber "8.5.6" -ControlTitle "Ensure only organizers and co-organizers can present" `
                       -ProfileLevel "L2" -Result "Pass" -Details "Presenter role restricted to organizers"
        }
        else {
            Add-Result -ControlNumber "8.5.6" -ControlTitle "Ensure only organizers and co-organizers can present" `
                       -ProfileLevel "L2" -Result "Fail" -Details "Presenter mode: $($teamsMeetingPolicy.DesignatedPresenterRoleMode)" `
                       -Remediation "Set-CsTeamsMeetingPolicy -DesignatedPresenterRoleMode OrganizerOnlyUserOverride"
        }
    }
    catch {
        Add-Result -ControlNumber "8.5.6" -ControlTitle "Ensure only organizers and co-organizers can present" `
                   -ProfileLevel "L2" -Result "Error" -Details "Error: $_"
    }

    # 8.5.7 - Ensure external participants can't give or request control
    try {
        Write-Log "Checking 8.5.7 - External control restricted" -Level Info
        if ($null -eq $cachedTeamsMeetingPolicy) { throw "Teams meeting policy data unavailable" }
        $teamsMeetingPolicy = $cachedTeamsMeetingPolicy

        if ($teamsMeetingPolicy.AllowExternalParticipantGiveRequestControl -eq $false) {
            Add-Result -ControlNumber "8.5.7" -ControlTitle "Ensure external participants can't give or request control" `
                       -ProfileLevel "L1" -Result "Pass" -Details "External control is restricted"
        }
        else {
            Add-Result -ControlNumber "8.5.7" -ControlTitle "Ensure external participants can't give or request control" `
                       -ProfileLevel "L1" -Result "Fail" -Details "External users can request/give control" `
                       -Remediation "Set-CsTeamsMeetingPolicy -AllowExternalParticipantGiveRequestControl `$false"
        }
    }
    catch {
        Add-Result -ControlNumber "8.5.7" -ControlTitle "Ensure external participants can't give or request control" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 8.5.8 - Ensure external meeting chat is off
    try {
        Write-Log "Checking 8.5.8 - External meeting chat disabled" -Level Info
        if ($null -eq $cachedTeamsMeetingPolicy) { throw "Teams meeting policy data unavailable" }
        $teamsMeetingPolicy = $cachedTeamsMeetingPolicy

        if ($teamsMeetingPolicy.AllowExternalNonTrustedMeetingChat -eq $false) {
            Add-Result -ControlNumber "8.5.8" -ControlTitle "Ensure external meeting chat is off" `
                       -ProfileLevel "L2" -Result "Pass" -Details "External meeting chat disabled"
        }
        else {
            Add-Result -ControlNumber "8.5.8" -ControlTitle "Ensure external meeting chat is off" `
                       -ProfileLevel "L2" -Result "Fail" -Details "External meeting chat enabled" `
                       -Remediation "Set-CsTeamsMeetingPolicy -AllowExternalNonTrustedMeetingChat `$false"
        }
    }
    catch {
        Add-Result -ControlNumber "8.5.8" -ControlTitle "Ensure external meeting chat is off" `
                   -ProfileLevel "L2" -Result "Error" -Details "Error: $_"
    }

    # 8.5.9 - Ensure meeting recording is off by default
    try {
        Write-Log "Checking 8.5.9 - Meeting recording default setting" -Level Info
        if ($null -eq $cachedTeamsMeetingPolicy) { throw "Teams meeting policy data unavailable" }
        $teamsMeetingPolicy = $cachedTeamsMeetingPolicy

        if ($teamsMeetingPolicy.AllowCloudRecording -eq $false) {
            Add-Result -ControlNumber "8.5.9" -ControlTitle "Ensure meeting recording is off by default" `
                       -ProfileLevel "L2" -Result "Pass" -Details "Recording disabled in default policy"
        }
        else {
            Add-Result -ControlNumber "8.5.9" -ControlTitle "Ensure meeting recording is off by default" `
                       -ProfileLevel "L2" -Result "Fail" -Details "Recording enabled in default policy" `
                       -Remediation "Disable recording in Global policy, enable in specific policies as needed"
        }
    }
    catch {
        Add-Result -ControlNumber "8.5.9" -ControlTitle "Ensure meeting recording is off by default" `
                   -ProfileLevel "L2" -Result "Error" -Details "Error: $_"
    }

    # 8.6.1 - Ensure users can report security concerns in Teams
    try {
        Write-Log "Checking 8.6.1 - Teams message reporting enabled" -Level Info
        $teamsMessagingPolicy = Get-CsTeamsMessagingPolicy -Identity Global -ErrorAction Stop

        if ($teamsMessagingPolicy.AllowSecurityEndUserReporting -eq $true) {
            Add-Result -ControlNumber "8.6.1" -ControlTitle "Ensure users can report security concerns in Teams" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Security reporting enabled"
        }
        else {
            Add-Result -ControlNumber "8.6.1" -ControlTitle "Ensure users can report security concerns in Teams" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Security reporting not enabled" `
                       -Remediation "Set-CsTeamsMessagingPolicy -AllowSecurityEndUserReporting `$true"
        }
    }
    catch {
        Add-Result -ControlNumber "8.6.1" -ControlTitle "Ensure users can report security concerns in Teams" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }
}

#endregion

#region Section 9: Microsoft Fabric (Power BI)

function Test-PowerBI {
    Write-Log "Checking Section 9: Microsoft Fabric (Power BI)..." -Level Info

    # Helper function to find a Fabric tenant setting by settingName (primary) or title (fallback)
    function Get-FabricSetting {
        param([string]$SettingName, [array]$Settings, [string]$Title)
        $result = $Settings | Where-Object { $_.settingName -eq $SettingName } | Select-Object -First 1
        if ($null -eq $result -and $Title) {
            $result = $Settings | Where-Object { $_.title -eq $Title } | Select-Object -First 1
        }
        return $result
    }

    # Try to fetch Fabric tenant settings via direct REST API call
    $fabricSettings = $null
    if ($Script:PowerBIConnected -and $Script:PowerBIAccessToken) {
        try {
            $pbiHeaders = @{
                "Authorization" = "Bearer $($Script:PowerBIAccessToken)"
                "Content-Type"  = "application/json"
            }
            $response = Invoke-RestMethod -Uri "https://api.fabric.microsoft.com/v1/admin/tenantsettings" `
                -Method Get -Headers $pbiHeaders -ErrorAction Stop
            $fabricSettings = @($response.tenantSettings)
            Write-Log "Retrieved $($fabricSettings.Count) Fabric tenant settings" -Level Info
            # Log all setting names for diagnostic purposes
            $allSettingNames = ($fabricSettings | ForEach-Object { $_.settingName }) -join ", "
            Write-Log "Available settings: $allSettingNames" -Level Info
        }
        catch {
            $errMsg = $_.Exception.Message
            if ($_ -match "403" -or $_ -match "Forbidden" -or $_ -match "Unauthorized") {
                Write-Log "Warning: Fabric admin API returned 403. Your account needs the Fabric Administrator role." -Level Warning
            }
            else {
                Write-Log "Warning: Could not retrieve Fabric tenant settings: $errMsg" -Level Warning
            }
            $fabricSettings = $null
        }
    }

    if ($null -eq $fabricSettings -or $fabricSettings.Count -eq 0) {
        # Fall back to manual for all Power BI controls
        Write-Log "Power BI API not available - all Section 9 controls will be Manual" -Level Warning
        $pbiDetail = if ($Script:PowerBIConnected) {
            "Power BI connected but admin API returned no data. Ensure your account has the Fabric Administrator role."
        } else {
            "Power BI not connected. Install MicrosoftPowerBIMgmt.Profile and re-run."
        }

        $pbiControls = @(
            @{ Num = "9.1.1"; Title = "Ensure guest user access is restricted"; Level = "L1"; Sub = "Tenant settings" }
            @{ Num = "9.1.2"; Title = "Ensure external user invitations are restricted"; Level = "L1"; Sub = "Tenant settings" }
            @{ Num = "9.1.3"; Title = "Ensure guest access to content is restricted"; Level = "L1"; Sub = "Tenant settings" }
            @{ Num = "9.1.4"; Title = "Ensure 'Publish to web' is restricted"; Level = "L1"; Sub = "Tenant settings > Export and sharing" }
            @{ Num = "9.1.5"; Title = "Ensure 'Interact with and share R and Python' visuals is 'Disabled'"; Level = "L2"; Sub = "Tenant settings" }
            @{ Num = "9.1.6"; Title = "Ensure 'Allow users to apply sensitivity labels for content' is 'Enabled'"; Level = "L1"; Sub = "Tenant settings > Information protection" }
            @{ Num = "9.1.7"; Title = "Ensure shareable links are restricted"; Level = "L1"; Sub = "Tenant settings" }
            @{ Num = "9.1.8"; Title = "Ensure enabling of external data sharing is restricted"; Level = "L1"; Sub = "Tenant settings" }
            @{ Num = "9.1.9"; Title = "Ensure 'Block ResourceKey Authentication' is 'Enabled'"; Level = "L1"; Sub = "Tenant settings" }
            @{ Num = "9.1.10"; Title = "Ensure access to APIs by Service Principals is restricted"; Level = "L1"; Sub = "Tenant settings > Developer" }
            @{ Num = "9.1.11"; Title = "Ensure Service Principals cannot create and use profiles"; Level = "L1"; Sub = "Tenant settings" }
            @{ Num = "9.1.12"; Title = "Ensure service principals ability to create workspaces, connections and deployment pipelines is restricted"; Level = "L1"; Sub = "Tenant settings" }
        )
        foreach ($ctrl in $pbiControls) {
            Add-Result -ControlNumber $ctrl.Num -ControlTitle $ctrl.Title `
                       -ProfileLevel $ctrl.Level -Result "Manual" -Details "$pbiDetail Check Power BI Admin Portal > $($ctrl.Sub)" `
                       -Remediation "Assign Fabric Administrator role to your account, or check Power BI Admin Portal manually"
        }
        return
    }

    # Power BI API is available - automate all controls

    # 9.1.1 - Ensure guest user access is restricted
    try {
        Write-Log "Checking 9.1.1 - Guest user access restricted" -Level Info
        $setting = Get-FabricSetting -SettingName "AllowGuestUserToAccessSharedContent" -Settings $fabricSettings -Title "Guest users can access Microsoft Fabric"
        if ($null -eq $setting) {
            Add-Result -ControlNumber "9.1.1" -ControlTitle "Ensure guest user access is restricted" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Guest user access setting not found (disabled by default)"
        }
        elseif ($setting.enabled -eq $false) {
            Add-Result -ControlNumber "9.1.1" -ControlTitle "Ensure guest user access is restricted" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Guest user access to shared content is disabled"
        }
        else {
            Add-Result -ControlNumber "9.1.1" -ControlTitle "Ensure guest user access is restricted" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Guest user access to shared content is enabled" `
                       -Remediation "Disable 'Allow guest users to access Microsoft Fabric' in Power BI Admin Portal > Tenant settings"
        }
    }
    catch {
        Add-Result -ControlNumber "9.1.1" -ControlTitle "Ensure guest user access is restricted" `
                   -ProfileLevel "L1" -Result "Manual" -Details "Unable to check: $_" `
                   -Remediation "Check Power BI Admin Portal > Tenant settings > Guest user access"
    }

    # 9.1.2 - Ensure external user invitations are restricted
    try {
        Write-Log "Checking 9.1.2 - External user invitations restricted" -Level Info
        $setting = Get-FabricSetting -SettingName "ExternalSharingV2" -Settings $fabricSettings -Title "Users can invite guest users to collaborate through item sharing and permissions"
        if ($null -eq $setting) {
            Add-Result -ControlNumber "9.1.2" -ControlTitle "Ensure external user invitations are restricted" `
                       -ProfileLevel "L1" -Result "Pass" -Details "External user invitation setting not found (disabled by default)"
        }
        elseif ($setting.enabled -eq $false) {
            Add-Result -ControlNumber "9.1.2" -ControlTitle "Ensure external user invitations are restricted" `
                       -ProfileLevel "L1" -Result "Pass" -Details "External user invitations are restricted"
        }
        else {
            Add-Result -ControlNumber "9.1.2" -ControlTitle "Ensure external user invitations are restricted" `
                       -ProfileLevel "L1" -Result "Fail" -Details "External user invitations are allowed" `
                       -Remediation "Disable 'Invite external users to your organization' in Power BI Admin Portal > Tenant settings"
        }
    }
    catch {
        Add-Result -ControlNumber "9.1.2" -ControlTitle "Ensure external user invitations are restricted" `
                   -ProfileLevel "L1" -Result "Manual" -Details "Unable to check: $_" `
                   -Remediation "Check Power BI Admin Portal > Tenant settings > External user invitations"
    }

    # 9.1.3 - Ensure guest access to content is restricted
    try {
        Write-Log "Checking 9.1.3 - Guest access to content restricted" -Level Info
        $setting = Get-FabricSetting -SettingName "ElevatedGuestsTenant" -Settings $fabricSettings -Title "Guest users can browse and access Fabric content"
        if ($null -eq $setting) {
            Add-Result -ControlNumber "9.1.3" -ControlTitle "Ensure guest access to content is restricted" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Guest content browsing setting not found (disabled by default)"
        }
        elseif ($setting.enabled -eq $false) {
            Add-Result -ControlNumber "9.1.3" -ControlTitle "Ensure guest access to content is restricted" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Guest access to browse content is disabled"
        }
        else {
            Add-Result -ControlNumber "9.1.3" -ControlTitle "Ensure guest access to content is restricted" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Guest users can browse Fabric content" `
                       -Remediation "Disable 'Show Microsoft Entra guests in lists of suggested people' in Power BI Admin Portal > Tenant settings"
        }
    }
    catch {
        Add-Result -ControlNumber "9.1.3" -ControlTitle "Ensure guest access to content is restricted" `
                   -ProfileLevel "L1" -Result "Manual" -Details "Unable to check: $_" `
                   -Remediation "Check Power BI Admin Portal > Tenant settings > Guest content browsing"
    }

    # 9.1.4 - Ensure 'Publish to web' is restricted
    try {
        Write-Log "Checking 9.1.4 - Publish to web restricted" -Level Info
        $setting = Get-FabricSetting -SettingName "PublishToWeb" -Settings $fabricSettings -Title "Publish to web"
        if ($null -eq $setting) {
            Add-Result -ControlNumber "9.1.4" -ControlTitle "Ensure 'Publish to web' is restricted" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Publish to web setting not found (disabled by default)"
        }
        elseif ($setting.enabled -eq $false) {
            Add-Result -ControlNumber "9.1.4" -ControlTitle "Ensure 'Publish to web' is restricted" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Publish to web is disabled"
        }
        elseif ($setting.enabled -eq $true -and $setting.enabledSecurityGroups -and $setting.enabledSecurityGroups.Count -gt 0) {
            $groups = ($setting.enabledSecurityGroups | ForEach-Object { $_.name }) -join ", "
            Add-Result -ControlNumber "9.1.4" -ControlTitle "Ensure 'Publish to web' is restricted" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Publish to web restricted to security groups: $groups"
        }
        else {
            Add-Result -ControlNumber "9.1.4" -ControlTitle "Ensure 'Publish to web' is restricted" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Publish to web is enabled for the entire organization" `
                       -Remediation "Disable or restrict 'Publish to web' in Power BI Admin Portal > Tenant settings > Export and sharing"
        }
    }
    catch {
        Add-Result -ControlNumber "9.1.4" -ControlTitle "Ensure 'Publish to web' is restricted" `
                   -ProfileLevel "L1" -Result "Manual" -Details "Unable to check: $_" `
                   -Remediation "Check Power BI Admin Portal > Tenant settings > Publish to web"
    }

    # 9.1.5 - Ensure 'Interact with and share R and Python' visuals is 'Disabled'
    try {
        Write-Log "Checking 9.1.5 - R and Python visuals disabled" -Level Info
        $setting = Get-FabricSetting -SettingName "RScriptVisual" -Settings $fabricSettings -Title "Interact with and share R and Python visuals"
        if ($null -eq $setting) {
            Add-Result -ControlNumber "9.1.5" -ControlTitle "Ensure 'Interact with and share R and Python' visuals is 'Disabled'" `
                       -ProfileLevel "L2" -Result "Pass" -Details "R and Python visual setting not found (disabled by default)"
        }
        elseif ($setting.enabled -eq $false) {
            Add-Result -ControlNumber "9.1.5" -ControlTitle "Ensure 'Interact with and share R and Python' visuals is 'Disabled'" `
                       -ProfileLevel "L2" -Result "Pass" -Details "R and Python visuals are disabled"
        }
        else {
            Add-Result -ControlNumber "9.1.5" -ControlTitle "Ensure 'Interact with and share R and Python' visuals is 'Disabled'" `
                       -ProfileLevel "L2" -Result "Fail" -Details "R and Python visuals are enabled" `
                       -Remediation "Disable 'Interact with and share R and Python visuals' in Power BI Admin Portal > Tenant settings > R and Python visuals"
        }
    }
    catch {
        Add-Result -ControlNumber "9.1.5" -ControlTitle "Ensure 'Interact with and share R and Python' visuals is 'Disabled'" `
                   -ProfileLevel "L2" -Result "Manual" -Details "Unable to check: $_" `
                   -Remediation "Check Power BI Admin Portal > Tenant settings > R and Python visuals"
    }

    # 9.1.6 - Ensure 'Allow users to apply sensitivity labels for content' is 'Enabled'
    try {
        Write-Log "Checking 9.1.6 - Sensitivity labels enabled" -Level Info
        $setting = Get-FabricSetting -SettingName "EimInformationProtectionEdit" -Settings $fabricSettings -Title "Allow users to apply sensitivity labels for content"
        if ($null -ne $setting -and $setting.enabled -eq $true) {
            Add-Result -ControlNumber "9.1.6" -ControlTitle "Ensure 'Allow users to apply sensitivity labels for content' is 'Enabled'" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Sensitivity labels for Power BI content are enabled"
        }
        else {
            Add-Result -ControlNumber "9.1.6" -ControlTitle "Ensure 'Allow users to apply sensitivity labels for content' is 'Enabled'" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Sensitivity labels for Power BI content are not enabled" `
                       -Remediation "Enable 'Allow users to apply sensitivity labels for content' in Power BI Admin Portal > Tenant settings > Information protection"
        }
    }
    catch {
        Add-Result -ControlNumber "9.1.6" -ControlTitle "Ensure 'Allow users to apply sensitivity labels for content' is 'Enabled'" `
                   -ProfileLevel "L1" -Result "Manual" -Details "Unable to check: $_" `
                   -Remediation "Check Power BI Admin Portal > Tenant settings > Information protection > Sensitivity labels"
    }

    # 9.1.7 - Ensure shareable links are restricted
    try {
        Write-Log "Checking 9.1.7 - Shareable links restricted" -Level Info
        $setting = Get-FabricSetting -SettingName "ShareLinkToEntireOrg" -Settings $fabricSettings -Title "Allow shareable links to grant access to everyone in your organization"
        if ($null -eq $setting) {
            Add-Result -ControlNumber "9.1.7" -ControlTitle "Ensure shareable links are restricted" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Shareable links to entire organization setting not found (disabled by default)"
        }
        elseif ($setting.enabled -eq $false) {
            Add-Result -ControlNumber "9.1.7" -ControlTitle "Ensure shareable links are restricted" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Shareable links to entire organization are disabled"
        }
        else {
            Add-Result -ControlNumber "9.1.7" -ControlTitle "Ensure shareable links are restricted" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Shareable links can grant access to everyone in the organization" `
                       -Remediation "Disable 'Allow shareable links to grant access to everyone in your organization' in Power BI Admin Portal > Tenant settings > Export and sharing"
        }
    }
    catch {
        Add-Result -ControlNumber "9.1.7" -ControlTitle "Ensure shareable links are restricted" `
                   -ProfileLevel "L1" -Result "Manual" -Details "Unable to check: $_" `
                   -Remediation "Check Power BI Admin Portal > Tenant settings > Shareable links"
    }

    # 9.1.8 - Ensure enabling of external data sharing is restricted
    try {
        Write-Log "Checking 9.1.8 - External data sharing restricted" -Level Info
        $setting = Get-FabricSetting -SettingName "AllowExternalDataSharingSwitch" -Settings $fabricSettings -Title "External data sharing"
        if ($null -eq $setting) {
            Add-Result -ControlNumber "9.1.8" -ControlTitle "Ensure enabling of external data sharing is restricted" `
                       -ProfileLevel "L1" -Result "Pass" -Details "External data sharing setting not found (disabled by default)"
        }
        elseif ($setting.enabled -eq $false) {
            Add-Result -ControlNumber "9.1.8" -ControlTitle "Ensure enabling of external data sharing is restricted" `
                       -ProfileLevel "L1" -Result "Pass" -Details "External data sharing is disabled"
        }
        else {
            Add-Result -ControlNumber "9.1.8" -ControlTitle "Ensure enabling of external data sharing is restricted" `
                       -ProfileLevel "L1" -Result "Fail" -Details "External data sharing is enabled" `
                       -Remediation "Disable external data sharing in Power BI Admin Portal > Tenant settings"
        }
    }
    catch {
        Add-Result -ControlNumber "9.1.8" -ControlTitle "Ensure enabling of external data sharing is restricted" `
                   -ProfileLevel "L1" -Result "Manual" -Details "Unable to check: $_" `
                   -Remediation "Check Power BI Admin Portal > Tenant settings > External data sharing"
    }

    # 9.1.9 - Ensure 'Block ResourceKey Authentication' is 'Enabled'
    try {
        Write-Log "Checking 9.1.9 - Block ResourceKey Authentication" -Level Info
        $setting = Get-FabricSetting -SettingName "BlockResourceKeyAuthentication" -Settings $fabricSettings -Title "Block ResourceKey Authentication"
        if ($null -ne $setting -and $setting.enabled -eq $true) {
            Add-Result -ControlNumber "9.1.9" -ControlTitle "Ensure 'Block ResourceKey Authentication' is 'Enabled'" `
                       -ProfileLevel "L1" -Result "Pass" -Details "ResourceKey authentication is blocked"
        }
        elseif ($null -ne $setting -and $setting.enabled -eq $false) {
            Add-Result -ControlNumber "9.1.9" -ControlTitle "Ensure 'Block ResourceKey Authentication' is 'Enabled'" `
                       -ProfileLevel "L1" -Result "Fail" -Details "ResourceKey authentication is not blocked" `
                       -Remediation "Enable 'Block ResourceKey Authentication' in Power BI Admin Portal > Tenant settings > Developer settings"
        }
        else {
            Add-Result -ControlNumber "9.1.9" -ControlTitle "Ensure 'Block ResourceKey Authentication' is 'Enabled'" `
                       -ProfileLevel "L1" -Result "Manual" -Details "BlockResourceKey setting not found. Verify manually." `
                       -Remediation "Check Power BI Admin Portal > Tenant settings > Developer settings > Block ResourceKey Authentication"
        }
    }
    catch {
        Add-Result -ControlNumber "9.1.9" -ControlTitle "Ensure 'Block ResourceKey Authentication' is 'Enabled'" `
                   -ProfileLevel "L1" -Result "Manual" -Details "Unable to check: $_" `
                   -Remediation "Check Power BI Admin Portal > Tenant settings > Block ResourceKey Authentication"
    }

    # 9.1.10 - Ensure access to APIs by Service Principals is restricted
    try {
        Write-Log "Checking 9.1.10 - Service Principal API access restricted" -Level Info
        $setting = Get-FabricSetting -SettingName "ServicePrincipalAccess" -Settings $fabricSettings -Title "Service principals can call Fabric public APIs"
        if ($null -eq $setting) {
            Add-Result -ControlNumber "9.1.10" -ControlTitle "Ensure access to APIs by Service Principals is restricted" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Service principal API access setting not found (disabled by default)"
        }
        elseif ($setting.enabled -eq $false) {
            Add-Result -ControlNumber "9.1.10" -ControlTitle "Ensure access to APIs by Service Principals is restricted" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Service principal API access is disabled"
        }
        elseif ($setting.enabled -eq $true -and $setting.enabledSecurityGroups -and $setting.enabledSecurityGroups.Count -gt 0) {
            $groups = ($setting.enabledSecurityGroups | ForEach-Object { $_.name }) -join ", "
            Add-Result -ControlNumber "9.1.10" -ControlTitle "Ensure access to APIs by Service Principals is restricted" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Service principal API access restricted to security groups: $groups"
        }
        else {
            Add-Result -ControlNumber "9.1.10" -ControlTitle "Ensure access to APIs by Service Principals is restricted" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Service principal API access is enabled for the entire organization" `
                       -Remediation "Restrict service principal API access to specific security groups in Power BI Admin Portal > Tenant settings > Developer settings"
        }
    }
    catch {
        Add-Result -ControlNumber "9.1.10" -ControlTitle "Ensure access to APIs by Service Principals is restricted" `
                   -ProfileLevel "L1" -Result "Manual" -Details "Unable to check: $_" `
                   -Remediation "Check Power BI Admin Portal > Tenant settings > Developer settings > Service principals"
    }

    # 9.1.11 - Ensure Service Principals cannot create and use profiles
    try {
        Write-Log "Checking 9.1.11 - Service Principal profiles restricted" -Level Info
        $setting = Get-FabricSetting -SettingName "AllowServicePrincipalsCreateAndUseProfiles" -Settings $fabricSettings -Title "Allow service principals to create and use profiles"
        if ($null -eq $setting) {
            Add-Result -ControlNumber "9.1.11" -ControlTitle "Ensure Service Principals cannot create and use profiles" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Service principal profile setting not found (disabled by default)"
        }
        elseif ($setting.enabled -eq $false) {
            Add-Result -ControlNumber "9.1.11" -ControlTitle "Ensure Service Principals cannot create and use profiles" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Service principal profile creation is disabled"
        }
        else {
            Add-Result -ControlNumber "9.1.11" -ControlTitle "Ensure Service Principals cannot create and use profiles" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Service principals can create and use profiles" `
                       -Remediation "Disable 'Allow service principals to create and use profiles' in Power BI Admin Portal > Tenant settings"
        }
    }
    catch {
        Add-Result -ControlNumber "9.1.11" -ControlTitle "Ensure Service Principals cannot create and use profiles" `
                   -ProfileLevel "L1" -Result "Manual" -Details "Unable to check: $_" `
                   -Remediation "Check Power BI Admin Portal > Tenant settings > Service principal profiles"
    }

    # 9.1.12 - Ensure service principals ability to create workspaces, connections and deployment pipelines is restricted
    try {
        Write-Log "Checking 9.1.12 - Service principal workspace/connection/pipeline restrictions" -Level Info
        $spSetting = Get-FabricSetting -SettingName "ServicePrincipalCreateWorkspace" -Settings $fabricSettings -Title "Service principals can create workspaces, connections, and deployment pipelines"

        if ($null -eq $spSetting) {
            Add-Result -ControlNumber "9.1.12" -ControlTitle "Ensure service principals ability to create workspaces, connections and deployment pipelines is restricted" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Service principal workspace/pipeline setting not found (disabled by default)"
        }
        elseif ($spSetting.enabled -eq $false) {
            Add-Result -ControlNumber "9.1.12" -ControlTitle "Ensure service principals ability to create workspaces, connections and deployment pipelines is restricted" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Service principal workspace/pipeline creation is disabled"
        }
        elseif ($spSetting.enabled -eq $true -and $spSetting.enabledSecurityGroups -and $spSetting.enabledSecurityGroups.Count -gt 0) {
            $groups = ($spSetting.enabledSecurityGroups | ForEach-Object { $_.name }) -join ", "
            Add-Result -ControlNumber "9.1.12" -ControlTitle "Ensure service principals ability to create workspaces, connections and deployment pipelines is restricted" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Service principal workspace/pipeline creation restricted to security groups: $groups"
        }
        else {
            Add-Result -ControlNumber "9.1.12" -ControlTitle "Ensure service principals ability to create workspaces, connections and deployment pipelines is restricted" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Service principal workspace/pipeline creation is enabled for the entire organization" `
                       -Remediation "Restrict service principal workspace and pipeline creation to specific security groups in Power BI Admin Portal > Tenant settings"
        }
    }
    catch {
        Add-Result -ControlNumber "9.1.12" -ControlTitle "Ensure service principals ability to create workspaces, connections and deployment pipelines is restricted" `
                   -ProfileLevel "L1" -Result "Manual" -Details "Unable to check: $_" `
                   -Remediation "Check Power BI Admin Portal > Tenant settings > Service principal workspace/pipeline restrictions"
    }
}

#endregion

#region Report Generation

function Export-HtmlReport {
    param([string]$OutputPath)

    $logoBase64 = "iVBORw0KGgoAAAANSUhEUgAABAAAAAQACAMAAABIw9uxAAADAFBMVEVHcEwDF1ADFk4DGVMDEksED0EDFUz+/v4DEEYDEUgCCjgDCzwEHFUDHlj8/f0ZHkkDJF8GM4QeIk0EIlsFFEdVdKwHNokFVJcCBjIDPX0DOXcER4gTGUQmLFcGL30Hxfb+/v0KR6EDNHEiJ1EEUJMDLmsDQoMMVbQGvPRbea4CGFgDHV0JQ5sHOo8MWboFX6cKzvf7XgAEVpwFZa0LTKgEKmQIP5U0OmX2/f4Fqu8GsvLY/f7+ywM7QmwMEz+v9vzN+/0Hf8sGbroFW6H5WAEtM10Nmt8MXsEFabQGdL8GesUuwvMJi9QDImft/v4LkdrA+v0FTozj/f4Ihc9mg7RI1Pbs8fgMo+f19/tFZqADSY5hfrDc4+8dt/AVrOqjs87U3etCSXO6xdn+wwL+/v4BBChObqbl6vSquNEYpt1d2ffO1uYhwfQW1/nBy92e8/yyvtUtuuv+uAIkseOQpMY+x/EKfLsOkss4WZUzz/b+0gMRnNNtibeXqMfF3PDH0OOovN20xuO91ez9gwOKoMMkre0IcrObrcws3/v8ZwL9/f0Lh8PQ5vX+nwKbtNhw4PiC5fj9rAP2UQBA5Pq77/v8dQUhnevd7viJ8fv39/r7+/z9kgJk7vscNmkCBjGt0ewOIVEpSX3r6/EFDTv29/pIVoCj5Ph7lb2gyOdWx+5ZZ4xsd5d8h6Xx8fVCtuf+5geRmLLDxNXExdbx8fU7jcVFTnKAhqFUXH+mqMAwcrApNF1vdZN5rdVdnMs8RWqgpLrMzdl9yekhWpqUmbGrrsAOGEP4+PrCWxewssWAhqTjaBBhaYyZciO+jB7blBL5+vvcshjuxRXIyNQtMlUEDj4EDToCDUACD0QBDEQCEU7+1JYQctb+zpH+0pIPbdH9y44OZ8wReNwOZMbynF8Rf+P2pWgMUa8EKHMUiOv7wYH9yYfrk1n2sHbghU8+MTokIjbrnmv8uWz94KRZQDtrUlSMZlz+7Lupb1h5UCjYkmnDgWD+9tScSiLJcEizkn3duZXy2vReAAAA1HRSTlMA/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/gP+/v7+/v7+/v7//v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+C/7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v4W/v7+/v7+/v7+/v7+/v4zI/7+/vf+/v5Z8kP+/v7+/v7+/m7+/v2ISYf+7tPdcP7m3f7+16Wq/v7L/eKg/sGg/rn+/v7M/v7fl4xdHtcAACAASURBVHja7N29bttYGsbxKYaBQhYCBBankAECvohUOZ1vYbHFNgFIYMu9g+l5B2TBguQ23iEwiiDRkABLgCJBhosAMZW9nT0fpCR7Y0/skYsg/9/kA4kRJ0jwvOc97znk/PILAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADxLEPB3APys6Q8pAMBPGv+4TNKYAgD8lPlPN19mN0nI3wTwM+Z/PO8Xo/SlHQCdA/DjCpPRTDhFHr4syEFA5wD8uMt/NS9c5+u6fGH+wzjlbxH4MeMf56vzqHEc933yogIQxh+vcvYAwI/Y/KfV9p0QzlfPiebxiwpIkt/dUgCAV16ptRN/yjAdb99FavlvPO+rO3rRTj7eXK9vSgoA8KrxT8okDoNTfsYwqVYXkfB7juN4jjh7UYrD6rJY31IAgFfdqFef5+uPp7uooxb/fDy9EK7/9q3Kv9OoHcBLJnlBMnXfFLcJBQB4tfirtXo6yG7SE3UAQRiX4209FF7Pf9tzdAfQNNnyBSOAIN46jp9RAIBXEyab6TrLZqdJmUp/Ui3nZ0J87Vm6A3DEuyp8Qf4XxX+dXnSbUgCA19n8p+PVmXCK4io8wSdTa3+1nV+4keuo5OsvpgFQIZ4+/x5wkC6KdvdAAQBeZfOfq/i7vu9d/9VBm0p/Wo62tVr7XcfG/lABPLl89oAhLLfSjg+mPEUEvMbyn4xmkXD0PnvxV1ZZvfQn+XI6KYRe+51Wr/umF9XlcwcMYT7NPAoA8Gr51xnT8ZfO7uylF/Xtyl+p8J97kWja6Df7EmCrQfbcSwBBXNXCfCJVAFYUAOD07X9V6zu6KmN+NH8wAgzC8PvCr1f+VX2mwu85vt+t/U1XAWwZENfP7C+CZDmLul8eLSgAwKnzn44uRJtWKe5nLAiTcR7+WfZ1+Bfz+mLoujr8/j77jWZ+oDbxPfU1e+aEMSxXvvAPBSCkAACnzX+yKEz+G9lIb3jvkC6Iy9H6Jnwy+2k5WtSzQeZ6jQ6/33N8E/jG1ICm6bYB0jQAzzoC0K2J2f63xIgCAJxUN2LTcfWkmByfAQTlZrF+5FRAP5ub5KPFdHImPdcx2bd6bQmwHYCj6oI06dcTxlES6kcNwu96K2BYbi+iQ/ybXkQBAE66/IfVZJ+xxrt/0h7mnyfZ+v9e32MSHCejxXwykG3T7+uz/va6j20AzNTObgGkND8j/ey2TNNY9QzVuPyz5w30A0RzVxzl33GGFS8EAU6Y/1ht//2jAiAWh4iF1ZdBJOrq/uBNz/rVjv92VnTZ93XcHV+q5Ovlvyd92/FLHX0ph0NpCoL6ifVH1TWU1ebzp8vr/On7xmFarc7F8QSxcdx3FADghPlPlwPXP0TMaw6ndGr/Pc12TrFMjoJqZv2j+aRQTb9t9317xqe/U1+lTn/PtgAq+VY7AVANwCpP8vFyNVln0XUZP7ELCOJ8OdHXiI7irwtAzg4AOFn+k+2wO6nTe3XP84ZdxIJ0U2fSF/reTrBPf1mt6rOdfrZHrfvtQt+u7nrG7zvmwr8Nf78/7Ov86w83egogP3zebJZ1kWVFcZ0/caAXhOWy9sT9+KtPIWqeBQJOl/+VbHfr+kUdnqoA7qCb+CWfP0RvfL8Y2aDqbX+ab+tzIdq23yz5etE3x3vtIq//kzr72j7/jf1g8c+/f5lkkc7/3aP5179Rspz7wl4cavbLvx5QTJ98jpABIfCM/Jcrd58uUwC8xr2wa6xa/9+LN7++yW7NsZ295nM7c2zjb0Lpm9H+vgkwPzqEX6ff5t9EWErpu5e/TaIok66IrqtHrgOZMrOsu/h3FaBRfz65k2L71AggyBkQAN+f/2nWntGrfO120tvtHDExBSCIxzNXJf1NMUr1sZ1+rrfum5GfDaa0gz+93pvge05jwz/o9/cVQJcAuR/jecPLIipU/x9l0+rbA0D1G6k9xsQTTZf/xrxDqNFXFLymefIQIIhXMf+qwPfmf25v2Nv1fzeUqgNw7EVgm/+efOPVeRKHYTLeTqTZ99tjPtk77P3NtF/P+vvH6W/jv8+/ngqcqdZ/rdxd6VeOBd9Y/JNqW/fFYfVv5xPSdACNfPptwkE+41lh4Hv3//Oovahn+uuhLgD6aRvV8gdxNTEv8POLUank2/eud3TDxzna8nvevZV/cKgCOv/dNcBGNwAm/nd3cXj00tGgY08XLlzhHcdf/0JziUD3KI546m3CQXp9xogQ+M78T23+7QRAqryaApCNkjgI8zoy+XfrMs3HN7PMa6/46Y2/o9Z/m31pF/6B0n9IdwCyexCoUVsG2c9UAbg76v3b5If6SYKyWtRnWbR/fcChykhdAPR9wt29OwoPhelN9p43hgKHkD/xsXSRmWN/S+e/b7YAaslPw/Q2cnqmu19W1baLf8+e8bfD+UP2B0ed/3EhGO4fBNR3AfXmv5jdlF0BMIt+nOprQePldj67//qAQ/zbUwTzx9wfUX5DOVpnk4R/dGC/pX48LvGoMPm3ewBpAit3qgKs87JMrjITRV9c/m1TZ2439dd3/Hp206+7fhX984GtACb4gwfrf+Ptz/AcJ7teTVfLcZWXZqhoHiMYbzafv3z6/fLci/QTxN+gbxOYHYDjOd6TI4B4uS6ymv9vGGDjr5bXx2/ahKOi6dlVVQ/XBm0BcBv3Wq3Io7WnI99zh//47SKyZ336xF/aqz+N1OE/11/OH3YAhzogVWKb7oRBFDdVVY2VSpWAJC2rzebLH//594cLlf3I7fqE5kH+h+01gnZUKR6/BRBUF6rFmHMKANgtfnVz9eiOOMxnXq+9+6vy3+8KwM4Td2m+mWW/mo+6f/xrKOykX3/jS33yrxb/Nvfntgjo/Lc14PgQoNnf4Gk8Od/kSVnmo6vFzc3t7d317KIvXaG4jePf7/vbW4m6L7H3iGV3EaDZPfouoaCshe9nU+4BAKYj3qzWV481zCou7f1/vf7v+uc2sqYA3CbjSWbe4tvzzi7lbn/c31OtuD7qH7Rs/M8f7ADaEnA4/dffi/ef5tcq9et1UehRgKJfHXC/2W/2N5LMqYTZZRwVAN0AvHusogXpVOhHjVcUAEAv8dXv2bp8ZAug49Iuuzpq/bPzftcBNOKmqrP2/Z09RzQq/z3f3vPXJ/n9btc/MOH/H3tXk9pIkoVnhspCzlgkJFrkIhMS4hC5ytjFQQTSZXQDeyEK27VrL4yxq5Ggq0DU4GJ2M5nuY8wVJt5fRKR+5gCd8VTGjSSXVTTfe9/7+55G/u8JgM8BJvAfXGpR5QD9h+whSAReM6xJ4gphQfgXBnBdEBTxv3AO4D05gGTJgOIfqpv9Nemd7fed0G6HfwAyR22llPlx3A1ex5fWemnqzxhGP8CdGIBUAMpoCMB9+e7fICEdmoDL7M8s+/gAl0O9h9Oq3wDThAO1FgP+4S/jQYIraqJt+/hGggbJASRLhvh/q/5+83olA1g/PyxEsy9TZaObQNur/viQU5Cmgp+h8G+mwR/Cf4B/SbhHN1BC+B9COW/w84I+vCt2AJzpT4I/gh+iPvgRLgGKA6iuzPk5b7ehm0PqR3IAyZKBxNfyH+rbZby0j3svADAg/rUv2yn1BcTBGJVLYAEGOn8Mf4S8bqyzhrP/iAAQ/OtB8D/4OWNQBzTcy1e8dTgMsZ/IOPYT54cyoxYHoMhXDMvNxSkgGFrcsEMzL236v59s7tY+Hnefl5+v9Mzau0MQADIu/28a6dsBK4fJgEzwb5bU9K+R7WPNr+m6vu8arf0IABUBKTEoCK/eOAlw0HbBXRmO/94DZMrzAmOk6AfwB68kWiJCFlRxqQTY3v3Yy79n0E/JASSbPf5vj7vl5+WyuhIwv+d8oxMw5ZDchAxAmfNpHIf/QhPeXex36Af4l3E6INy/LGsjkwVKdgwc7B3wR/jmwe9dAL6Px/2k5G/w17lf6AmAlAD/tb1Edt6/eD6T5IKSJXMh0eDgbn6xZLZ+0h8LycbrBgiADoO7wyDE3aMfwz8SgAbQ3/dWT4oBwahfh4EdNoSgogh834zgA0b3cM+M8Bjpi1cJwIqA/xrhrxt2AB/8kbLh4Rzd7fblkCk/RlC9pl2gZHPH//b5C5L35cWa+WQCALDmPAD3AMABGEzYo07dAPEYG34B/lP8F578y9gfp/mK3ADyCgWIH3O0ES1Q/siw1NAQASg4AfDoPitptOvHf/eV8roBpnpL28DJZm7bl332GbZ2F+YSH7475r4BaFz0d/FfCIDxu8EQyQ3cCMnQR5QT+OtL4Z/hHycA6AVGRL4xhqv703B/ZkWJHwgphoiJiQsQZbKI6ry8mYrmFejftHlPZ8OSzdvWT6/5pwUWxYsLDmD9XMsI8JCVyP+RAJQOlagJjr14L8TD6bjAH5J/agScwN8HfxYWpoA/cpCfigQg2bgOf4z/JREAaSi6P4vq22SqAWUDu42KpwiyPHUBk808Abg/VJ9RsydTzYWc+fFVEgAoAHK4lRIgyoIMmAKAnv/g0vEmhr/VIfrrOPVXKkK/UrlAn5eFBfr/JYkQCu38JZygYPiDR8LfUvAIEHcSTglAe/d0GCs/sESbC6kJkGzmdnusljeA/0Wm7LkD2B7DCaCao604AGTtWJUfsGvvwj+WCBvbE/snb4ErADwFpJH6jzjXgwohkPdHqqAyHsTTQqWP/zjqR+N+AP1iCn9NWYm0FNC1VG+3QUKsbbf3Rx00w5dSA0xyIMnmXQD8YXBpH87wXnAA63vuAEB9XwvceAiAunRG+gBDjeBvKPx3nW1w9gddgNTpC4S8oiY+6wF7pCPzF7IQNw6Kc+2gmuEvDqCUoiTPDC7y/b1oG6Bq8NHiyRDqIUq/YnNIagDJ5l0A2IcZn/wsBWjvvlU3QgC0z7cJhL50Ty18l/1z+F+tgP3T7F9kTVnzKQEO+4X3DBr/bpkV1KIcoEt92kCcwh/AHz5SHdoJgyQAJCTydNxvKjpl7JUJndda/j+9sGTJ/voE4PbgAQ4Z8akDWD/vcARokAJA5ABq6dthRB9rgn8D8Af0dx1WABjcMDwI94Qca4C+Hm4J4UQRvRMzhpUzGhngR/SnvBz9Of43+Hot/cRxzLPdL75Nst7ePr33eU66JAN2Klg41CU1qQSQbM62/REENYchL0/w0N6+5jeE/7Fu9KQEWBgJ/9C7y+ll3SGKqQLYUXhmoOKxP4Xor2k3AKHf9e7R8U/EVcPIEfjQX3LubwP6OScpi7KWhqL7JWP+8xauCMJdspfjPkf9ILxDABnLaKgDmVX7NAaUbM4E4L7Pb8KRz7w42YzZvucLmdTTzNHRAUChzvgJ3THPiR5YjOKr1dcV0gAfpm3jcn+H/tEUBQwHnxo6AYs1w3LSN9B+n8jHf+3hL+hvSGFIRgrcxxnV5vvddruGg0GHpqqCcNAA44QGHYAjA5ukB5Zszvi/O1aL6MrvOE674s4/qE8EHEb4WQbg8Q/+oVtFFvBvrXbOIleOucfYt/zoCPuxkSuYdA+pQaCbJn4rZh0U/wuSBYK6pHMAm2/3cFL8/v2b2eTx+uCIbQTDA8ypBJBs1hXAly+SACgszm8m+ljt3Xt+Q68rI5DDKSCIuOwAXETN8xKz+T7Gf28JqlAKdGTB0X4LkT5GP/2H9ei3mBjIC/yKXyDUkkwE9PueBCsKYEXCOQC12z/dbR+f3/a7TT7VDzGiGAbFgPHS4FOyZHMhAGHIH+f8HXGeUOL2aU8EIMvyEvGJAZcW+SgDwHH9EfHvw38vBMDSzzS1qUsbgX/KAgJPsBP89/QT3ElozsCvJQXA2gCGfkP1iHH3858v97//5+euYi0hj38vGYizgtVrWgRINucKYNiKQ+o8TnbjIgKQ1YhmAKuVkDwQ+R9zE+G/X/U9eQAI3/DH/UChQQ8AvwjYbPDGnt6Db6VXBf7iAmyjmxPWr2MXgFPJ032Czetv+4cHPGIKqwVn+K8V3R2p0mHQZHMmAHt1k3kdbrj1WxVRGwB0wD8tSAhAA0i7BgpwvM1XE/6dB4Dh/6YX+BOw+wBsafL1HvlUJwRbdYRu6QhMC4PdVfj7b7yVwL1/HgJwSQkm/vJsxoNKhmYIo+Ojz6kEkGy+BOCXWkx0dR1yqvdwGWj7ni8R/iaDGeCm8w4Ax/kZ/zlk54T/VRTauyn2I2PwU5sAWws2vCuuEiDh4NnCqOTnOQA8Q0PBPIukWEoAg74K8B/oULgpZLGA1QardBYw2YwrgPc6OADunw2bg9+faR0BoMNemdGQAPQdgpEdgIHiX14R/ifw5zWgrj/xCZgeIPoJ+5TbR+iPqgQnXYEmnvsLPqBE/Mso0iAzCYpWDXxOQAIDtb8+XtM20PKqZHiyZH/9BCDo/JmhxiKgcwBVdysUAAgAiQRkBfD5Hh1AI535kQgATPNa6vszhBn3E/Rjto+1ga/QHpDlAN4aCE6iv9QTbOQJPc0AOPwzysVIR4yeGUlcDJoYtb8+DkvMlNjUz+vkAJLNlQA8FV4YpyjNx0AjtDteoW1hCBC3hM0CCIDtVuAAaFrfOYECHUBVC/59BO+lDRBqAoRtfLajpF1jQ5/fHHsAO0W/le5gjH/Nxf+aVUkHP4+ImYD7YIM8aOlwDPDHxcLsT3AAy6QGlmzWBGAjS0AOxebjg3MAlshq18+4JWiIAFjbr5gB0LBenQP+Dcj+9Tj2J6W7aBIAn/X1fkA/SnagSHiY/ufkgAqHNgY/NRKsnxRgqQHc/hdJoiAbakaM/o7xI/BZPhREBOvJ/eFiCQRgsVjmaQoo2XwdwJNWkgFATR/xD1XA/eMaCQBkCIiTzDSI/9XKyiigM5NP8W+hp9/1cfxfdTzs39OST4H6fZD0d31cGvBVg8b3++2J+SEkXv3jqwKGZ38HEg81GPBHNfhLQiAuWvMFAi05AGYAi+Ul8YNkyWZi26MQADzdWQ+cAoyUA7Trx8YRgCUc+AAC0NFsn8e/pgIASP/gK7zTF9P/Lqz7WNDrZfRjd7/vzuGvUUK8C40ACw4EJ4N8G2CyFlhnKhwNGNF/ZdwLAB4A8DcC/4JkzIALeAKQSoDJ5ksAHq0MAaIiR53xUp/aHFwO0LbbX7slMgAkAMTshQHAYTAgADUU8fteoB5IPcoBUIPPRe+SFP049sssECcHHbf+rJX04aQfwEVB3Wi5KszR31DnX2GtLzofMBqhAMD92V/AOJK4jYzkj8r7lAEkm20J8LvfAiIHwKt9+Vj9hOb4+vYPRRWAZY34/7r6ygwAs3MoAcACsGXlL2sF/hjWO6nd0erQZBa4lyGfCcyj2kHYEZaOoMh+y15gjR/Xg37EqwFYAxiFE4TMH+aWGyunjJAAgCRYdUhjwMlmSwBu9yL1bQp2AEIBdt/Xf2u3vz9g+HcsoXTRHfBPDEBrzMlNPhrdcPz3szxU60eHQLvDcK4P4K9PVwGmk3+TLaIVe4dQGBAhQoE/bBZ7NSJo+odvOPqrYOSvjOFvreYn6oz0T7OHNAWYbL4E4Dn/MxAAdACMp1xVf9y17d2v3Q2MACwMZACOAIAHsIJ/q//H3tWtuI1kYVjQ4pEuBIUvdCGBoR5CV6o7PUiD/TJ6A/tCZG33TYghnSbp0A3pQNbNhFwsJLLzOlvnr6pk9+4DRHV6kknPdDIJzPednzrn+1JjVIuv+HXtRUAB/3WlNF/qKTbr0kHaZ/jX8jLwWlyMBWXswG4CiSgJX8WJMn8Zmg/nfMWEn6v8zZx2AObFQywAYkw2AqU/TJPKQEsNl71QAnxe2A6gZ/eMHFYAbqUCYCkf24GXNXf90ggIZiv6KoQ/NP9qrAHwSsp/nQTkDMDBH6oJcw3/AZf/UedDFEa9wHDVUoEiJgMlOpjbP1ofl4BiTLcD2JYi9VvmXAEYrqLToXhYdtsju4EajQUAbPDetDYb01Te8kXbiPGPw3/Nvb+m7A/Vf5lXLvW3vuK/5Q8nH3QN//HLH7GJ4a3l0cxvrCuulNcWB3eCmxoFSeCfvlEwAZjDamMsAGJMObrvbgSYewIgA75T1u/W6+fdTKwA2hYXeKEC0JoG+9qYXIT/KtznpS3eVk71c8XS4a75x6a/5eyP2L8l8N++lv5bWfj1BQA0KWwkBjRlgwv+wFEgV8E3fFPkkoTdiBH/OAWME4AYcQTII0AS1KESABhg6L8fnnpWAsIOwGK/vsEKgCQ7bGavbwT/1M83bevwr3Js/nNM/9L0B1oAjgFeA/8Njf0rv/ULEiRG1n0TlPy+BP6FqwgLDwonuSeAckb1/7x4ilvAMaZLAHe75LcQADpsCQGcUqCA9PHlJnVeIEAANar9Vprw3+ZG34zgj0t/UrID/PDq1nX/gciP/Ul4D3gT/hWgn/V/vJw4W4kMAP0EvpkyDy0C1CX84T/v2w7cRoDNQWwADDLA7LyLOwAxJtwBfCpm5zOdAQkBlMgA+AxgS4D3bYoWOmAGBlcAlYbnPX4CqNvS1PjarzUPAsP0X6pKo5ufvhj80X4P8EnzavoXJ+HA7AM6k5SA791Egvf9y+wPG79tsGFA+Ne8OTzHqeZsNlt9jxOAGJPuAH4jAQwJOWqHBADZNs2TDEXzTjk+8dW48V9jBwB4tp9CaNXy6L/FkT2kbJv36e3Plv983MsMQBKfVUscwNO/W384BAzgrIQUL/uQnhf/ttyoj0WJrsp/xYQUrhCigkH+hlYA4GEzmWfVOj4BxJhsLO+ycwLXfzbBa64AsAcIGCCzBGH/faaQAGztD/ik8zy3pqNzXt2H8p+TNpEJPv6RPaBDIh0RivBfg20Abf3wsQ9OCTX5AMNvZSD5fuj7nWV4CHYWC5bPqetvxiuEqCXAX/WPGemAmL/6524RCSDGZDuApyLJzhm6fWmpANSoBEhEXgM0OyDjt7ThazM0VdjQ/5cVw79t5UoPFvAk/QdluDiE0RARP6efGD7zgwUAGAgZg84dGFloGR6C3/2Q3MWctVDt8O+kBORrDWR/WALuP+4F/5EGYkyvA9g/pjRWGxJ8q8eqXQclQKCuU2lHANijK8js9LzGWr+4GChPdYR/o1gNMAA/4R9e5DAqTvvBoh9UCFggcL2Am78y2kN6kF9GIewF9zw+kDMjTv9ytNBC+n+DAwDRPz561+DYCcSYYAfAKhpDVmoq2BFbUALIgg3jH/wAW7L5xkvfWgMBYAnf5gqH+tDiB/hH0W1cv2vR54/8vWSmDzI+yDetq9ED+MOHkwZviVpIDaAVkYCKzUSvxATCw6Km5gsC5CZ/BMixe+YJINgGRwKIMTkC+FbwVC3JNZ3qKsQmlgChlu5wypEAoJHGsb8tADTf86u8ZdhVcqiHituY/knKR7ukrfxgD04DCNXutJ+afrpJaMMs7g3EJEKZYacj5Pp+d3BAyiLX+M/sR/99j4IH6BoetwFiTKbyl//XNw8rIQCCILltUwmQuAV7FAhR8NCHYMaZHkCZTvl1XjUebKQTbtts+0tUPBTQ7OsnNIDvDPYLcrwSZo0AYARjZIlfXyiCjM1DWTrAuws4+Ic+ArWkfzYlg7AdwIyXiJPiy7qDwn+xXHb7z4e4DhBjIvjfUL+7WKzbgit9o0glp9TUdZugCaA1e5yt2/Tf4lAfSvoKAQgDAEKcc/ItEeElC/lV3tgXqYByP/UH2g/vccJXktegJq3AEZYvrITqkYKw6wBGpMF7hKP8T/jPhlOS7u6WCywAuvX2+fg1OgPFmEZ0d5slEcChTBnfJREAFuVoshmUAKStAy/r8PJXWeBDAaDx702d5y1V59ov5Vn825bBPb0HkYsjF6wH0aP8vLQfJrHfs10nTfcrbw0YdPTN/w4uARwJhI7kHv+G3AFtB9A/rxdIAN36/vn44yVWADGmUQCsHz4QASy/ppLl5XROCEC5l3dHALpyBEDFPswAa53zUYD2KzkWyWkpx0CX8Cc/jn+Wcwr2IjHJIEoe9AABkwBdXVFAEzoHvSIn2nBv4DWF2xD/5AQG/X+yetp2C4hu//LpePwcnYFiTKQAeO7p/m3RfZMRgHQAjgBsCZCMCUArNgXVFQ77lQJAVqUiWQAxCiZ7LsQ/PdPRjg7DH4uM+bi4gJVj+h7cBeG2DxQ8U/uBbcTlDcF1CxDaDTUXyT98/wfmgY0H5Jz+YWs7Idv+L/cvD6v+cR9fAWJMIpbrLyvqd8EPgJCYGuUqADjxhVm9TeOB2kZaEgEg9vkqHzR+y5wghvinhr7MTqnhAz4Pf6wLIOHLBS+FfML7vbTgW7rtPgUDBpr+8wExHRG9VgIQAVy4CeEQwk8Z0N8ctgD7HzgAXCy79dfHVWY/jR1AjGkUANsdEcBiufnoKgAdEgC17SMCOIUEQCM9gCbKbFXj/G+TuNEu/fO2Hgl4mIwJh9GPST8VAR9BPUp+yE5Anrej1/3m/5UAdPKvxwRQjfI/nj2Y/se+W0IBsDl82/VJJiZIMWL84QOAxeauX/0N+y+L5brmR4BT6QhA1Ty3h9vboFIH3X8cAThRXksAVY6+XjzMp/wPRbyit37Ev0KJEfAVtoV/MgxeuxMoYMBX/6BPoDUgWReEfaDm1sWl7WgTOg42PPXXngJQktT5AIGMCLb/s92P7bqD2P78uEqTJH08RAKIMQkCWK4/9av3MPFadHvNQ8A09wQAEz0u3TNPAKccKwCYAXJhD48CUADwoE/yP6T0kmS7HPzd5i0LeOF3iZPt8+ETv+ZMjooBYQAH/Ot6/i8Ww04/RBjAjf9KnP8PSTbfHT+sN123WW8PT/0qO59nq0/72AHEmAQBdNuHtHgLWy/2hyVl49Mpdw/yCmR6W27As7ACUNTsC/4tAdBiD+3x0RsAezyVcQAAIABJREFU5n/jd/cJ/pD8If8P8D3O/L2SRzglVP5UgA97UDAkQP/tK+bjmPjp57JycHUNf57/w/rv8Zet/pddtz48H1dFds6S3+ZrFAWIMY0CYHP/mKX1vSWAZbdNxAIk9we16OvBj/fl6YoAqACgg3tFpzj+ENcA/otAjZfgTw/vMANg8HNxkHvoS/XvLoFaJxfsNMNGwiGCfL4UCqiD5UOh/neXgqXgPzsef22WMPvbPj/2Kxw+zormPhJAjIl0AC9vzkP50sEAfGvTH1UAeJWnsYsnhw9GpiwKMQG0QADkx2O/viICcAsAivBvpPWHuX9i5kkiE4BArfsqpO5n81EvExwAX2aBdDtMLYPyUuEqvDSEY0NZLixl/cdWH/2v7X69Obx8e1ytCvvbHc7DX8W7OAKIMYmwme+nhUHxcwPFwJYHcvgKqHGXN8/Z4otBbHhKQDMAHAHgMq+B7p9gq7jbt/kfX/FLHghI728o9WeBho8ap36lQw/g5vZaGLzmHp/rFBkYqOvyQdRDQYsMl45k/WfAF0DzdG/j+aEE+FsCgKHgLP25jcfAMabRAex/prNZ8W4NT2DbNCSA5gY18ytS0tI81j/xUeAlAZS6Qn8OJaAE/JNPME0DZfJPFACFP2Z/L/nh5v6kLtbKpR+JhXtvsOBYMHwopApATgyCWoDUg3O/ceymkINJ62/ff3w59qsCIwUxlCSrXuIWQIyJFADb98U8KZrtYtGNCaACoS+w0OAtG02ZtkwdAWh+H4A7gZMhg55S4G/rf1QRtr8W+fXalA9nxBb7NvfSha+r1nMZETo9j9Yf+gaqPlTvoyoIrRH7YSEXAK4R8BSApwwh/Ada/wVVg6Tvj7u+7232LwpaP8pmq7eRAGJMIP3j1fv2nSWAbH4Pn3wostQRQAuS/8oRQNNSD6DYYbskiQ4858O7XcAg6H5yLjd0M3iyHQAK+DpFIcz+lOlDyS9K/DzFkxagDjqBiysAOhyWYYF/LhTkB2+Iqgwj4eUf+FOYU9pb/HP6L0gMJVn9+z4qg8b4o6EPS+8W/Xsbb8EKsPgbPv/QEwFkQgANCPmLpl7FO7yQJ4cTE0BF1kEpEoDts/n8R4l8SHYqc94gNDhehEpgDFdGP8n1BCd7FxHcAoqREAuLKDf0C3QGVCgq4gK2GRH+mP8zHFKmlP6LAu4Csuyclv+5j5cAMf7gxI+Z/7A93N8ftvuPxWxIiqflcrMWAsC5XYuenznIezUs9Ump2tb2masA/sve9fzEcSVhMUwPM92Yxm3WmkTdHJjlwmyOVu9l3m2Oc0VIHilgZTKWkKwccsglaznak2XtFYFkhPmhlYJHioXAu2Z3g0RsscoByduN4S/g6H9h66t673UPSY5JbKsLI4+xZVBr6quvqr6qiigVIAKQEgAwAdDXt8KEtwdQ4E94iW+q9G0x+lSNaPiqbxRl+/rtbq/M7X+JA/A8cDuPJQ2b/Q9NGg75PwoQEv5Fe8i+zzggssTU6e2fDrbXCgpQ2AdK+8n3945ODl68Pj199WqwGXmOl9RbUMIRAFBQBAD4wgCWWoEGAECATPg3fBB5LwwMA/BVGBIAgNKb0xyhEOwkhdhfIn/qMga4rq+3BMsEgSz6aNldH7K+40rsj4erAHF+ENCcC9ClP7OCQC8SYBB4a9zf0c3/RJn4L6GfaQBTFpQFerung83VAgEK+wC9f22bfH935/G1cm93/hQIcMS3dVy1ukYfWwiKAgB+JKc4fT+2m3Xa4rYh+1DAW/oiWfbpqZQAIBQAwD9IkPVjd7AHwkCfymX3D406b6jVl/l0rtivV/6B7beWlvKSv2z7V7ZZfHjJgNLu7/tvbe1P6w8z/s89Cpfdn6hJ4qUe1wV7353uETcaFBBQ2IeV869u7p0cLG2ULy7mmnMb/YkFQoDT5/UqIl/vH6urq2tbZzyM76K8LgBAFEBHWkBAFMiW8DMBgMgCADOAQB/nCtnDFHu/l4D2S/Sn34LMXSOr3B1K8lu2158n//ZEUG7Lh0gBAnMuyIwfmnI/3P+tecV3BBJHfyR6BEkyAKQA/EeeTEic3henr05fHb8+GmBCuACBwt5776ecfxvOvz9ZK5eazc5kc/Li27EJQoCFk3Uc+aEc4H/bq2sCAC5qAAQALfa5yOcTn7Ec1ZQ0G7E9tQCgZHWvj40BoWzZIoqtUAEgDEDiDxKQKmL/+Witd/O2f7rfN1voab4YxVfYv+4D6OXhQcPuHrDO/zZP/T3T+HeyK+KedP545UhK9ESmkogIhF3CxQefXM7uH2sMKECgsPea9g+OTg73o1q1Nto0Vr4HAFjohuus/0/Tl8+21x5u6alcBoCYD2u0/Lac/eBz3qz7QYvPYSlgjOFaAIBLDCDQC7wVM3+0/ZkCiGt5HP7zoh9fr/sLfN31yzl1217wja0WQJJ9o+tt60NCckEkGDoPJHI/c0jMwRZjTkfE9ZGdINa7BFl+qsUKKZIA/jGdeozc6C9fTU9fNjtPDk8G9FyKZKCw97XiN9g7OWxteGfV0Wswcf/O6JOJsTECgP2e7PpNvfUfKdq91ACgAABtuawTM/9u+1yti5hx+xRRZSMIJoAV1wAUqAAAIJS7QZ6mACwGAAyonFwn+OnpTkEB3QZomyPeVgxEf4kWw9X2YZC7HsA7xEXqq78iPi8x30EKoET+k4CShL4SCuDqBoWMQTi93YX+af/Bn6Zhnebo5P5BkQwU9n7y/gHR/g3Pq46Mj18bHx0dn9MAMHn+HRGAiYkfein4P2XDav3l3urD/9RlO48AQJw70Bv7DbnXxZ6HTRqK+4CaAaQEABAEcgNAcfBnGpCKHgiu2RDaH+WWBfssHPazMQDZ/i+dwBwDACNoxTxw0NC7xVg/CCd3pbqoeIdgyt+Kv+amnj1iBrdnMEo8/oOU+0H7JeobBMDLpP4pAOBvn5D7X+Kzc+E50fODZ0wEChQo7L1w/s/WVjefHT9vO2dwfvJ9sTmTAdzojxEDmLdnADx3a/1g++GPda4CEjvGaq84N25LABBFttseipwHA8F+aBiAAADrfRFj4XJK4iqa//qepwGEbP5f6/nsLIDGgLwGQCqDseQYgd0O1Gjo3eX4b13+VuT40tbP5pbx0/AxE84D8NKKlJidSBbA/o9X9UZ/fr678u/r18EALmcuZ5vjI+Vzh0Dg+NmmoEDxHivs3Q79mwNK+jeq55UR9v2REe3/JgOo7cL/J572uOolQXD95eDhf3s6BWAAaOUG8OIgMNEbfYCUTwMRBYik7ka+zQAQoPznSPjXtT8tAqYojQ/2zBS9d736S4aHdXFA5gGYB2RKYNsEXIojXTjQ43651h/LjYkHpG6qk3pXB3Xj7UwAktwSInH8LAPgp+AhA+h3H/1zmgFg+nK2M06PjzC04jhb7ecnR5tFOlDYu+v8a+j1kfOfn1VLJu5bABg1ADByn/x/rB/gFLCR7GIx9kld1nEnvNsrxwAgAdAVd87Yybd5bVikAQDTQT7iMwi27gAID4Cb8S+m3BKDk0QCdaojem4RkK0ImMagufBrgMhcFuOav0afrNUvy0WR2qepaxP7hLFIvrNnagBe5vR4oVgZRBhyf54A4Js/MgOYIQbAADDCD7FUPvPC+PBkrwCBwt7FyG+c3zsv8zs2Z0MpwByXAMee9rgDqAQEUrX+/etU7+XVAMBRN5bTf7zuD84X+g1QAFcRGDAAgIRzUc0LTfWf/YzdjIKylgC6hpmLCIcV+CjDqfxYYGZ8d0jkiCwL0Ce/7AaQhl0yxHcFlVJ24k8DAXMOzfSFh5hCAHr+nJpY9m8JwM58nzKAf01f1wxgpjNSKuWeY/ncdUPUBbfXPitqAoW9I+7PFb+j4+dRFc4vVhopXQUADv/NzsVTrgBELtTvSl8EJwd4+a0nq7nT0DCAnVjO8SBVN4u5FfT/9K/IAxtYs2MBwOGRX4gEEmH+AgGuBQDtbbguLhqceq/e69WVb2SBkUnrUR/EDr92Jg2M40wDZKYGGo38dbEMAvgYmWb3Hqc5okZgINCEQO6cyv0Bq1d274IAPPrD9E0GgJnp2Y55jCW2Cn1Wz9z1BkoCBREo7F0I/lD4nhy+qLhelaIVvUkrlZK1HACMSwugM3JnbGJi7AdMAWEnnwYASgLWHb2an+vt7Hwx2HiM0wB2eUeoUAaEXCgMItYBhWj7+Ura/zwChBBLwR9tAJNrGwAQHS5XBVNAQM8NGrr+b8Z8JROAVIgQIGP/7avHwaVFoLUA5tCQRQJTGswZ8/5EmEnCgwpAQDwDLlIQAVhZWemuPKAMQCjAzGWzUjLuT8+1zEa/O2596wWrBAqRQGG/a+xf5dBPnlvGW5TfnnkA0CCgAWCy2Ry9uDVPCcDYkjvl8G4OlcghPvILc6dHDvHx9r1IojMWahodTxgGvgJKhCFmAYUBKB7780Rlw1UAHXRTlWUAorhLDF23rUCzVzwT+fGCscjKgCUbaeQug5kOYSTSocioggJz9UOIgOfIIiIlyIS5RGlHiCXSnhCM8urqCyIAKyt/v3nzphQBpmfHy3iYAIAyHm5NDGcMa5TGEBE42iwwoLDfKfTD+w/2w3r9vFwy4QkQwCAgZjAAQqC5kXL5xpPP76ACsOxUqwAAz9etca6GiUjWAAAHXinItRuhRQBIchQKZpT1y7YNT9ZrIOYLAVAi/2EcyPyf46/SEj3sBAzsJG/DtABl0Edv/ctvA0YpMsTpwdy0oHb8dk4dmEsktBowyfzd6IWUmlKCC3L3nH/G1K3vzq/0V7qPbn+M6P/R9MfTl7dKNTzESlmervb/WrVaJRSo1M7qddU6YAwoQKCw35r4D04O46m6W6PQj/dmObPKkIEClKtvajee7H55rzsxxiXAOi7xop8fevrml5TMXMh2KbYzA8BeMJ2gk0MZAZ4fBrrCx6s9wzDRvXUEWCb+qdTaDAGXgpy8MuE/g4CgEVgkYNGPGQWIRBactSPjkH60IJsjHDr5pSXD7WxhkKwdC3glGWsRJD/IBX8RDMpqkLQeLc73uwQA97/8/MlHs53O5eXMrQpF+woeaM16v4GAao1QoPzGq0+9OCwKAoX9xt7/DMTfO68hPP2CVcr05qW/r507lcc7t7++t7jSXVxcmCD/X2h7uMzpIJNPHC3XT13BATdFqNXzgLHI79so9+WU/LwYCJwfTiW9NZVgqFaltv5Hr3Had10IgJK+n5+b22Vpjx0PCjQEtJaWhiAgL0jwcUCMQICPk0dXrv4N7xHI9o5IhQBFBzGVim5YkoSUyxQgAF+DAPS73e6j7vK9u3+9/dXjWxfeG6T+U7Wfsyob/c5Vwe9ZMVy8Owv79dP+TSL+Fe+sSt59cfGzvs+JKqJ/7cw721h6ene52+8uLi8v31/8MwjAHXeKUgAnSbHRI3f1U0MBOTtSgB0eBNIHf7H93yIAWv8ssFcKJXdd2aOPBEU2zgCQU6AhhzgbZjvA/SDb303/DfINrQWwLCDO5gH5W7fMUQD61VZyQ1DaBFcgoG3XCBh60LALQ/KrgfRPwrdL4P/0f6ZJb4ecf/7O1yuLeE7Li2T3Pn26tOHW8aAreZ9nr89bufbGdbf2j/eKZKCwXz3tJ+Jf+T97V9PaRpZFIehpSu9BCopa1KIKBupHaKW3018wXggsG4QMBUKL3oaagYb8hwGDZyZmwHaDh+AOdG8C7kX/gCop+8HbeEICmWQ17368j5KVnunpzK6eE0dyiNqd6J537r3nnis3gydfvvpHkA8MR9uNUueG9tcm+Ku6risEgKecAURgjqsMAIhw66ctAuToCAA+AGMewYOM2kvvgOWD6M8EeU40GsvrLfoAYQFAoxOAdQmK47zr5c06YIjnlrQAicsHCl76becDPQKAJFjBAH8j0jwJN/8xARh798BpEbqPlUnnv03fkLYqYKmyuD4w8V8Uc8OS5lW9Mqeu5tXp9UURKSWidCfou2c0Go6UTLEg0CcD/fl/BP/vcb7nVSHUm1+IfrinDPmPTDJ/Pr68OTHvZxv8VW0ezVAGfKwQABqY+8m14Bl5hwAtUPUJVN6hLEfxhdM3uYsfrPYTByCJPzykHEDxiGGr8s6ELtz+WMQrWfcPV3+uwZMnSAW4JcD2YFTs93vBoCqRIwmAvd5QrLTrf4PwNz/PxpxClMGCUbs5zLYKNCsBW5gCujk08T9dpCsCADgAAquqPnl2dXxu/j630ZcxAOoBJldQmZpyd7DHgP583bT/Ly/vXsFw3xOO/pGr+9lHyFKH6WgjZXqGwT+b4zu5ch/1kmTAm4hrgCYsFY3Ne+E8jgPExTHSf07FYbmGdmM8MSQBbPqDYiLFw3asAWhIBPjo9i8LNPYBj2E29YYVQqAIbF0qYCFgEjgEjo87kwkKbLwUIhgWEr2TMEHAWdBPLHchwH1T2uU8rcqOgf8X2RsHACvzYSDgxBzzYH19MU1hdVD0CxAwgM6A+d6S27u/v+gLAv35atEPaf/dbZxJKEmN0pHvSIW1aSj7jd4oNTq7/Nu6mkHOT7Tf/LDxTwCwgiYgAAB4f5Czf8M6fS6Kg9geLv8SvT+x1Qa3NVT9OH/WmAK0TvkDrYCWVDboAwiPchv9vAEUL/MJqntp0QCLC8mbFwd+gw0/Y7cKZFqMO9vBpjn6eAH7ENxNKIquebitIYYbxotO+AsUJRLomQRgeXBULjbKAsCKPhAACAROnkE2gCAw2ksF8Itpmg63MtO3MELc84D+fIW0H+7+22GWRVDxx5gfDB7XpA0oRBu5Pb+Aih8W/Cztx/C35wAA4EZG6JHVkJcWxBDs6w7KgBqXgkyxKFdwr70sc0X1c0yhse2HPX/4sw1Z72hy3LEvxTaBINOzEU2qfpwwYgiAnYM4xNtCcc9RALQlGjtTINcMwC5BKTPEGs01xtyigFMVl+GKcd4UwPsBc1wQ2OrAH+zZ4fJagR8CAkBVYQkAPpnQ9xhQr78x2YCQcuOyge22CwARll+fjAADoCjYE4H+/LaiH9z951KZ6H9i4n6wtxUFyjRhkv7J1bOV4f1B7Fc29C0SHAIAXDIAaF74hS1y7VOAlnzBSFSDEMAOfMAUFC/2hP4hNv00hT7PACIV4ClgLBTkDgKsqyc5fILQOOdiQA4IABEtCAIYGbw7wDSUBMCvUw0kwE4B0dbfmCsN5+5RHLoFk2iBrn9yCwH/QpMAgA9QdYH7QbO4QgZA4R8wgJOTtfk4MV84urkcD2WmNhj+5gix9RhgtYLDJ5GS+e1dXxTsz29s+KUm72cl2iMAoDddKpQU1Ozjq9/n/O4BosCqgibA07EkAqBpspbl89pWAXBOHqKnoM19iQMAtNfGpR8657k/3v9BAaVYBsCCYBw2bAkCoIkA6T9jAAXzNOGiQg4EgIy5eb2IW+5nFT7TUBVkXiDJMvpGUu4y2nAnh2D/KY6TTgsQF4Q1tCNYQCdjMZ3dJAvcEZAV0P+b1wEDsOGPEGAOPDBEoAQisEUKIKJdAIhILxzJ7K+3vVKwP/9b9H/3+scfIqlGgcp3l/fDm0yoja/3U9ZPeT//sAyAfgEZ0EGpeEUGXbaxG6CxRTG2BSkLS6Q5CUg04oYinW/jr31Q28OYX4Me+zxyBw2BRttMwLw+LRr7M3t8I5kv2RhEw0oCNvGilR6JzdwLr/r1GDBBEkCzvnnuO4y8naxz/IwQOQjZ/WCacECP1xfoD2g+LSZLBwCrEABM1K8ZAdan8PDo+nJPWXD332cUqUxMwFewx4D+/Brm/93r78fKRP9gOPhi+KMIDa7+o3rum32u7OcvfwcCq/lTbAJ4AIjZo5eZtEY5YEszgSD/54u15IJaDvMD2OXXbP7JHxD2GreAaTL+YDcOiumWDDtzXDTk7P1xxB/tPmHpoHQ2fg15fQQQ4EU/pBa2VoXmD7WtLTXQ/0uyL/i9b4jm258YACwLkcXNZKF4R8jiIgSAMAVYWwYACABnfXJ6czWB/qDYKQV6HgDPByPAgF4k1J9fwfxf3k2E3AyGw0c9/uDyF0pxt29OAc9Vf3v3150KIH2e4yRQviEAgC2AsbXW470+CAEo3s05NO3+XqrY02Rdq9zoX4vhT70AVALqln+/5blbhAOS3sYFJwATu+kDKgHw8rllAFxlIAgobJc/mPjDij/5A0xzpSVsN9NO4Oe9gl3cuzqhoOXgEP4gI0AtgeEocsH/x1m7uDqYm7/PRwyAw98yAESAoyPz4JuriwKrgntZAD3HXCC/vXvZ9wX68x8v/z+9eHl3a6JhMExduX839zfvqEYquPrDgr8P/0d3vz0rBICfsohWZeQY31COzxkB4AuaF2ZIbLDZjb9cmofqeasbO/zfanLabFp+Shpg215XbA/EHQEAgSJc8UMkABEAJgybxjMGurDjsvjSoZafSe8VzjBAZHtjIOcUHnyB7D+Uxou/0YwDjWilbsgIQarF9QFIAVeuBvDHoARI8X/qEABAwDzzyUC6mwU4UpCmWymTfmCgP/9N9C9kZKL/cUbpEktD/IvLm5r1/eGpu60/LgF4DjAjAEhDAJiM/T5NJ9DF+Rhq+dnMmrYDc7GPaD8aALbWC0Ao0TZtKxo24SQnPjYI1Q379ifjY5sGWCBABIitlTf9KdeyK0O9fxcCoPNfGtbCEKCsopHm/J03iAGGpmVPQgH6BdoSiOtCib5ockM0APDsACB1tcMAbAmwwwCYBiAGfIvtQSXSx+EfuU7NVmbJq58NBvQ0oD/7En9Q+p5nGVT9Hmf7LqPcyHR89VO1XM7mfHai34Y/M4AQAlYMABFRAIrtyfGUi3Rs1GtSfTDtlAo3aJBBj62yofEv+e2D7L9pWf/rjoC7FJVALf4ejg2TGZBmSdA0qAPQoW5kgABQVmQIiJP9LGDK28VQy4RrTbnmAOIg4cf/GzeWDBgF8e8XhYKNQats+dO8Rna6FwAsBVhbAAggAGjAKRGBs1SqLbC1/aLhdDh6k8nyR2gN9hjQn8dF/7GQgtQ+e5r9wryDhMxM9K9nNvor+Kh2k4CAAPhDj1EIeJoBV2UASBIMwNiactNYTqxpbY4mrYBtqSUxZtENNv64Z9CEY7bm9x4+fHwvob0OdoBCNoElF2uDYdFYFwLG9NptIzYbp0lkxgCgkewygGkwAlyCgBBmCsjd3zmBswc4u5IhA4ALXzAC0K8NwRK7lytdhwBQewbALUAb/UEOcISfkAicokTAyYTE1umEqCKIPwx9++H7viTYn074v3j9/SRV0YC8PTrBDz8FFJqFytLJ9cnswN/9DAKdHKCb/1e1ywSqarZ8yimAeTUdQQpgAm8MxTR0z/DDc9iZh0qAgsZ87JU1VEMjA9DGXu4492/49EbJ7OHj/f2ntyYdgMAzCLLg9Bo9emkKHxYP4bofjwBTJBnmht40nDpAuObhEOHO5R9YABToWIi1C2f4zTIfQikGKGhKuvin8MeVBrkFgCZLZmALOq/rkACsuwxglwAwBzAYcPQHqApOzmF6cGT+0VAn1B0ghqdgInLbpwL9cdH/0lB/nPHbrfb7BNLc/WJ8dbLE6J/NZz76mQbsYEDI/OuVYQmz5SGYASEDkCndUNQ5h1As45z3bhWltdnUvFpD2IsbmgQU/4KFdOS328Cu3cVikT28f/+vT+/u/3H/+QGWDpigy95+WGSN9QSD1J6u9IIgwNcCp/h11QAD4Fy+wXk/P0/UtQCgDKA4I8cyxC9sYbTkAm6l/swAVOtnB+gzIoD5fpJgMEhkx4ewNO3wEP6a67AGEPD/vRSAWMARdwYmKTUGIP63nTQAnxv8lVn8qlcH9NFP1H+q1MhGvwOAyNvPbU1KPjXMn6J/NgsQoJsGOPGPI/+Gx9bz5QEGP7y3QQewlmlq3oQiwlkgSMknyKOJATgjjcTei8KTAOqeK+IBZPwPDt/64e37Dx8///Pd/bt7PJ8fsgYFRQ+fPj0sWloL1Cob0lja60DApMA6hNq4Qh7d4jYJ4HJAYALqGQCAQEnyYVAy8D4AO5DQkjGhItWyNQMUPEbE8CLQF6lZXP0OEQDP4XJWrfj+3+kBhAhA4W/j//nR8+fm+beXY4MBwAO2HQDYWkgYDd9INe5Vgv9m71paGkvTMFo5MflOaWL6UJwZTmoxoTbJD0htPLss3Q0hwwS0hEwEQVxk0YsO9kCB0IvaDjRksJqRAnVAaLpnUZuGkqF/QIxlEXEhQawOmhoNEhfFvLfvXBLrB7TmOzFeKpRVSZ7nfd77w477fff9DyD90fEfqfajBlPKA4BgBNu/TLa/zPAP4H+FYoCLIwKAPnCkhVh+eD/DxQMBVw/QBrmWQQSQQALI0/RvHp+li36oScDU/rjDLXS6hpYqfY0WMNPldf+21/mEB2y/nO7gChlAGZWrk95FpSmbejCA4HoMgPO+vMpgrAmU5YKBE+CeBPfykA6QqyHwl/kfvDKMtgIcMIHIVjJZAhgYD2q5An8eDeIwWxj2Po5Mx+dq5jlxQBE5YE0XAS4NeQBBGaAZAEkAOWDhDcYEQwUCHgOwUxCJtKhjaDxb/KHCH3N+lm1KvQ939IXkP9gPRX5/Fd6JchbD9n+YArwqABxoUy6KPRPwzxRXSlgI5GJSCsMAlNzLkBOO/fd52vfpyDTNFLfNiC0G2+1S8bwu1oGf2+5Vf4DY7/jnVFigd21TKLBye969rihTCADFg+MzgDcFdO5FnsP5IwzgUYCjB34nMsEpwLxFME+zi/S6QcfVG3+UK8uBcEoBhgXECeCyYN0ezEPN4LaOTxQvT4fzHImAhUAI/vpaXv52efmV+AFi/1EBAAPUNzaIA2KsAwL4DxQMWdG4sjf/8+u/xxTw8JJ+KP03lYrfkfJjBwAgikOmAP3FAPpHKID1/2JIAaAAAN1PjT/0VkbLX1yv72y9rmIpcOYwamFOQbpv87xyh4VA2i/WqQP4AAAgAElEQVQJ4ApBEvuCRYM8f1ophPG+/qD7KYD5047/Bdz1bWUcNO2Lbrfbr6imFPoZmgFSXkGPaIACpRnJCdDg58e7Ohjo6GHfOjko+G/IJADRMLwvyJWh/8pLQngKgBKePORQPADOPKp8caY0tb+9t1RlEiiW+BSri+tfSgJ6+F/2fAA69XpddIBptiSeE4gKssKzrMihMtNvxwNEHlrKH4y/WzmM3Al/lv4tRP9qFeNReH1JAOg8gF8NgLqfnH6OZ6FBK63Ud14nH2Wzz8o4EzhvRvGXYC2wDgIwA9AYzkSgcY6bZzxENslUosBW9sXNAFB+Kqg/lXvNBvjpxrbB9lb63V73pmIblIcjEcGRAC+urx2BNMKy6WsA7lgwPApweG2YkwgO98x4A8F4DIDsGQ4OAfXKAr3vEzzdPJ0WApD/nr2LHkAtd/as8bUmgaJoAfIGKAawRhEAuvvWrwfyYwAeB9ThYg6I0kAxjAcMMwDKgIgBrgDKgDEHPAzpj8Y/o5T1hYR/DG0/+v1rYPs95Fd99IftfygLIKZfo5/uFvd35qYjkYlccj6ZXMe3+LZCAnC5HRDndOmsPOnoTEIv3GUgWS7bfqr/aXIFIFj/HsK/oy/fAwh8eVPB+J/zGRjg9tI2cPdQkxnAwPB7ioZ0IWilNCiTQAng5fGbhn60Yck/xs8LJkLzBrU2SAT4YWhnoP+9y9I/RZuE8CvBv+ms4LPz5mx29unZ/HyDlAA6AcWiJwTAGcCqn2AE4NVd8Efw0w10wMIG6gDQQywBOD0YpACcJKYy4+KAhwJ/8PxVC8TfUKWfVPvEYmD7GzvLZUF/1bP/gQhgeSgGoDmAQ34CfvhcXgDwx97HJx7TcvBkdgP/cM+OUnGBYQZ8ANQAhTTO7GT0Rx3qtEfIGMIAPOwDkXL9Gxn/09MAB5z68D8NMICpLga9XndwYdPf4R2HzTfmHTI4AhCXENCIQp8AmoHHuxrdgSs0c5ALB7mDIAx5C294RxuBXEr9wc2bEebILCNOApb+8lR2A8/nso2tXSIB4IBiwBkgBfAtxQAWRgXAxsY+3urMAswB9d2thoE6QJcHHHp9A8IBh6YzrhO+99r/ezD+aaUOrXC9T6Bg3FCt9PbCorb9ngLQ+n/EBfAkQFD4I/qryztzuC38CFcDZrPTRAAkcldd+PVIAAfUiJfSEiBfwEFg+YI0zzL+LZcIwOS6HyynVRe3BP3TEPBDTMDeADGAMszrHjBA71pJKx4BOmbwGFCv9AgHgKVTFAc0fQowAsf1MZ4YkgK6c+AuCkhoL8DE2n/XlbLGjBBAyjGkBdHewydvkVYD//HsT2dnIAOyR0eNrb31InMA0gC+MuQMeMEADAG8YviT9V8QBQCX3OBsIAdsmqplSDlQqHPQotEOpir8/N/xssH77flbdmukWcwjAEOpza3aCqNffH8/AOCXAASrAKQZgGy/Bv9UaXX3xaaJxUW0KvxoYuIRMMB0MruFQe5S2oiyAjA5daYlAFbWJwr5QsLVttNyXPEApKqueaD65Pv3Tn0XABN/dM7hgqNVAJYEgRfg9oEBOp2bS9swApCOuQ4XHNC47gTuB0VE6mm9TU4bGsMcoKEecgT0PlC6uwwwADsx0o2ApUBc2EwxSJ4R7nJQ01CpMvj8U7UzEQBnz4AAcrnsxPtWvLG9v1gSDigRCYAQ8F0ALwW4EQgC+hRApwZfvtnOT5o8TOyOMSIgCk2bZMDYE7innn9ambFgia8eKM3FfqayXuytFEvVatkP/FWHFMDiiAuAuf7i8xnO9eMnMP0FHCeA2D+KHB0d0YJgJICvco0qBQFsIQDlEAGktQLALEAiXchndC8doZ8D/5RVb6rL2+4p4R9uPYwBAuw/nrSPP8D53wc6x8cnH8+JBk47g4uKst3PXWAAdgM0lA0sRnYTfvFxisv5xCI3mwr7CsMMwOlIR+cE/TCAoP8yIAUkGhBzdXWwKfafk/88JZh+HambA8PemfI9ALT/z+aBAKZxs3LkvVLRF5iOBRKoshQQZ0C3BPoZAIkBCPo1/oEAarVa/eU3lBYw7sI/tg3HY8qce/fjOClw/7J+735yVYtaxWKjrWKAftvM766CcalWkQA88z+K/nI4AuAJf0r2ldb3QGjauq74iFaFHk2CG5DN5qZzya/WkADWVAQJAHNkvJ8jTwv58lRdm3DAFKexlx50OjfM8KguGqB/Megy/MHyg1UH8LcF9fKhOeD44/knZIDeVUVVLgedXgfdALtpuEESYArQa0dlIAEXGjvgPphBCpBMBHz468V9Erh0NA8I9HljCY8a5FkAhrepiAUAFTsYenyRgwJg5u+Af2YAFADJ3GOkUVyxiBn99HYdCJpeI+aAMuqAheWhEADGAHwB4EmAWu0lnT9vpa3AHKFQJAirQVrUMTgOBtwj6/+vX96mbIVLO+I6+BtqFTew1He1SOalGmKAcjADOGL+PdNP6J8p7+/kDdkeEPcXh9CK+0cgAbLTydw39Oh0K34Ya8E7Xzlkf1kC5HnnZspx8M7V4h8VAG/6du2LXlei/+ACdM5PEOof/HPMPMCnDTIAPYHrSqVy0UMG6HTJDfDRz3OJhAJ0SyIVHBrq4nMf1IOr3QDpQPB8CEnriRbwIwDs7nMBoEkz/7jMFzsBXe/x6YIQgCu7UUEA0NP4t6dPkAA4AgAewGPEPz6VFrx6JrhoL3bXQAjwy0Qv1cpS0APQ+t9jgKAAQAp48/Jl7eVfcY6QdA3eMUEISwR/HQcD7kvg74df3jp2bHIyGg75HbIjjHMjE9trHGaq+gwwJABC+CcKqEp7D1f4l1b3tjIgI6zANlshABAAk+gDgBOQzL0uoQTYqUQMo0Wlcgw/CsLn04m0dAEgjgyLu+ZMHgB0APr/YtAh3Y8RgN55+0O7HYS/1gDHmgJABQADdG8vgQEGHQoa/HYFb3wuKJaePMNIZLQC0GO78Zmp9NvdPvAFDxXC5CO1IBrDcQEj0Pxvul69kfztTZdHf1ADAzOA40gVEg05lEVmyinDKzC1dPZkdnaWQwDzyACPJuCFo1rNeISEgGnGGtv1dRECwgGryxgBZAbY9yIA9ZAAqKMHIKdewxEiTVNGCMY8IuAfWJNx9c+5d+OcwO8e/rTN86eIacG7yAp193vHVnP71amp5xxh8higWr3L/df6v1zVVb6U7C+u7cxFTfPQItsftCqiAaKTQgDzySUkgJWDmN4J6pIEyOOQzXyBvHCKxOHab215efbvQdO+JBR30PnvdE/a7ZMPo+eYr+M23trt826vc969QgboUeKgc3OpcDExzgz2UoLaB9DFB1ixe2D3z88HV7Zq0kAfHC8SLA0Inlbok1YY/qXXluhioE2N/xTvRVQK+4Aw5//10yezT/9ACgAIIJnMPZr0FjHSiDZ4iuMYEZjbXcNErURr/4GJAaoCXggEAIcjAJ4TAKdWr7/ZbhiKB4nFh0MCVjR+aKbfjpuFfu+Rvx9/LpjKYgsSzPdr9Ffc7aWZ/7N3baFtnXcc2zqSzjm+4RzmY8cqzFdoUgusGOcl5yHGRC8ZDIowrsF2qHAgEPygx5nACBN0eQ8pLGjpwkaSgUtutFtHIX4I7FWS3aBhmFCLItlSahtNZoX9L993LrKc7tEGf76JtrFTS7/f9/v9r1R6TrFl4gBbATRWAC7a6L/ogL9zeeXxVFDPqlL4e15ItgtAAoBz9cMnAewMuGQGszQHS9fIhM+QBZgZsFdpiOi/GJyTJlFdOaCrHxgAQC3h/6OD/ZwTDBAmAB5vlavVcrFWicvkYaG0Z2kKLRa1o/zBLntpp6zdS1uWViuXq7VdEzggzWF8vbkE8JygjDG62/6FMEBlY9gCIDSk0FZE2g68jL/O6z+c/wju/x8+YAdwtftci7dRS4qrDRICazeXZanW3XnWAauCAFzq380BEv74lkgmPvljCocIqc1mivpAbQy8/Pa0UeDE3v6fP3j6t5Spq35Xn5/7/s/C5b8Gl78sOG9QAMte+++gX6T7sMq3c3H1USirZVWHYrwU4LiA775r+XBktHf4Y7IMa3FVkdM66dZH/A/xzk6eAiqEOPX/6Qo21Jm1AkX+MZy3Beq/Af4OB+SkC8jhwxxmBov1HdAAXD1Qzf+0Y+qyscCp9iUPwDn9AXYfyDiF/E//qZhmhlaOKN5ioqOOIRmArn+xvFgXPwwYQI4YN7i8EcxNnGoAOr/65Xg4PHH+F0AAV1EBnDvX6vM3m8xMxdp6to2EgPM83bp2HbHvSgEkHf3vUQC38WEimSQZoDffLQA/WleWXj/902enFHAia35epkTSv4EANpQNQH/ckJe/hwBiy64ggKcCSKBfZPvh6+Law1bN3PQ1DBEMHiYAoICOkb7ecCQa+d1d9ACzXTrHAHBi9xA1BEzRICBLtgF1OTlAndyCuVfICwEA8n8r9+Y9h5Evv4INKBfLe5VdwQDwHcDcZxV3oU8Q6327nFJevr93qoVSqVTd3t8BGSA2ECr/BwM4eQNn63ma9xej4xBNCAM69TmBuYlfukgRgPPR8bHxSCQS7v3oA4T/uQ6/TQBqA8XaQgCrNpfl8wQcsJBcZeC7SgBsCnDgnxAckPj4YYp7BVy7xh0Ll9VDL07Tgifv9gf4U82PA0P5wsEaEC3Ol78L/rMM/2YKwEb/xYAI+XcS+lOaFvR77v5GAhDWtaV78Gzv9PR0OBweu/DsIi0IjQd1nSmAJgOFZqZCOFtvQM7JsIuA07QEMG3iBU4CoFrOCfw3u/9zjgyQX8EGAAWUazu7JfoWBfYBZlppAHPaskt4OElg7pYLeaCAfKm2V8HR2yIV8HOH7n9eVSjK/Hh5ucLzTXi0UEqXFJGxbrAAGLsC8B8fi4xFwtPDo4PdHS0+j4DzNmtjz6YaVJADVtyT2m6tLKx6PYBXASS8n1ZXb3M0QG26YKg1qKU4GHAKrJMD/9fPrfimzOvYk/253B+c/9DjW3a7nlsAOArAGwFYXLSr/Gepu29tycB9wTxC8Aj88+uotX2y/+xw78TEBDFAJBKNBfA7zZgb3DEP0MCRezRgFyPwGCzjdwoD6LwNMFM5qHL6v1oG+Z/LvWkm/psJADpFjARU9/9b4g4CzCEegLlXPBSQtnP8NMwbgWzul/PAAPVSvlpnDkiLqQTOnzpCEqRlAQPZfEtqAGAYg7uQWADg7yD+mHzR8lfjV6LRcZBJY+Hvw+HpieHRyXa/GmyY1NAosrCVR0Ed4BrWeGvFXQOQsIOACZf+d+mAZOKTS62yNkD1aACqDDC/ePntg1MVcELgf+/p6+eaqRhqk0Ux2OiXXlqP0VUesAkgJgnAFQRwCYDl2GzAQf/NJ4B+zZVXVI+aRu9rOzcyOjdMZ2LiwvQFlACRuzQX6Jal2eoYq3GoBqiH0+gZ3urDQQBW3uZ+tUTIZfwfrf2dDy8xUCywvs01BBRMLCMF6EoDAYj1Hmw/DMWssQbYLjEH7FhoBrL2nwCCog96pDiEkhYzPtJy5SkvM0Nxkxro4QyAuP/TmrXIo8DuRKNXouNAAeORcPjCxETv8Gj/4OSZFlmic9TEf8OvZjX0Aou0qsGtA9gBJGwOuH3bEwawdQAlBYJcGyDGwKtO1Yixad5/fjo45GTc/k9fLekaFnUGhQFw2UaAP1/+AZHC9zgAbxrALgaOyXQ/fKaQP20M9TdfG+JMnvG3dY8M9o8OAwGch/delABAAJHwHfrhnesmjcLn7Xo8bY9icJbY8KeLImCS0plKXdT/Av6p8Dd3BPwdGsi5FAD5gGr5bbkkqoiRBMrlgz1Ly4pmY+HZZUyAYqU4teSgWMBAAB3ggAMggQoNAM66KwSdISKKhiNMeHSxbmsAsXmYt6AN9aR6Ul2KsxB96QYVUgeejV2ORlEERL4HATDRO9cHp39wpLvNx1O8moosw1AxCruZ9YEXWLw7jx0a5NtQByQEBSQa8oDeaCBSQDLxm4cpXW++VMAHz/rzV9gmcAqy4337v5rSdMNQnSp/5+nUwfmvz0osuxyAIwAaQwD23Y96IbZCRf6q339oU2hQdTUWAXD87d0jI4Nw+ubmhkkDEAGAsB0nApi9cW0N++7Ees2MxXFxXqBJS76oQxbtP96SYMZFAXCV4/+5BtFvW35p/Bv44Ud4z22Vy8ViteQ0DVbL5fpehTICuoSviwBwMgIyAJYUl9znoLa/CyxgmrjVV6ct3YqSzSKhwT+Cb2jxFHCd1wzxWDMxBszALsSeoVRXlygCpGGAA2vLGFn5BgjgCiqAMDqA3t6z/XwGgQPa/QLwQbX5OmBfqy+YbcHJ7cILoHq7uSBjgKtNCUBKAPx3q8mF249CiqY0UsCGQtZR10KvTlMCx/l89uDF1zrC3zZxTAD4elZ0M/XoJvn4QEDi36MAlsW7TQD2NF9s9FtetxN+R1z88qvR0jE5OQL4H2ECAAaYEwyACmD6t2AjZsx4nEZjghGwNCujcXcMNwBRTR0V3qH/p5Ycs5Yv5fH2LsoAQO59OQBbATSwBFJAQYgA0ADURVjf39G0tD1uXHIAzUZAeY0a4N27ApiAeqm+jWZgexs9wQHQwP4eEEEF/74VODs7u7t7e7X6bhyHkoshZNzEJPoIXfjv6cL1qrRKAH6oZs48ht/yN+OXr6AEiIyFp6fJAfQx/uGMjEx2tFIMtzkBGFRx5dvcpNwgc8D8nfl5tAKJxBH4d3GAoIDVx38wdA4IbriPgiyQNUMvvjxlgGMrAD7/5/2sahxe6UVz/UNP5h30ewggJh2AJw3omuWN6B/SzKyISKtHHXjR+NvOTAL8kQBIAfTPuSVAeBoUwF8CgfW4BS99HI4zhHY/A0DAATlDXbxRk3dq0eo8ktJKtlLiBF75DZX/HsK2DffcoYigVwlsFYvFghwlwBOEsdjHMrVD9Txw/WObvBG0am/fvSsXKBBQ364jAxAHoCcAabAtTkn8HQv1ipbJpDO6HDCOZYQ0ClgJ4jgQkP+pLnwbAC+ga2xAguYMEwBKgLFIBBXAxHBfv41/oFP4lU6eaTGCyhFpeyAALLr0beg+WwdwecBKsrkDSEgHIPCPPcMLySdLNEPMSwBioLhy/+t7pwRwXAng3j90f5Ob2VDM9NJqzAX/Tq8AiLlyAEICxMTdj75//VEPov89yBc/qLX9TPekjX9iACQApoDeXgoCRMb+jgSQAfWMWB8KodzHEf4YGevh4L8ltuimRS9AUNvLkwKQAiDn+PzmNQBv7CzA4XRBcavIs4S4QQg5oHCwv2N5e3+DFoELGUAFBii+K6IK2EYBYJMAfeYIIX3e5kf5WpyXE8otpZrYFaBblig5TPEQkpmpqRCVCsH/4iN4dp55FIAggEFBAHwmJ8+0q7KfX3VTgCy5wPgM6EDWAbTJ4S5wwPVV1Pk/pwASPDzkzw9pvVAjA2D7SPCLB6cEcEzPpw8u6YdQaahZMyWyfgHX9e8wgIgALNtJgBgZ/wDF/GN492uK8V70o8jwt3Xg3c9nhB0AMED/2blfCwUgCCD6rDOwaIJZ1vBeHAiF+MLXLGoLchprKA1HCgDAiA4AOIAEgAzv/atJzU+TnKA3EoAf8J+yCnCfvJ3pt3N8hmAAv8/cz70F6VAsV7ftIwHPjwT2+VR3TSzvy9hlQAR/agfsSvXYE4lpmnCKkyEb2npn569+f/nfIAHGo6AAkADm+sgCyOsf4Y9vwAFtrYIEVLWh7wILh+ChX83qxpTgAArm3ri20BT/LgVA0YIkfiRFacBhBggqX356CrVjSgB/DWXVxrSfpk/9j71reW3rysP4oYevYllYgiqxtLHidGkYj1E20SLFjDOLgqEEkQQqDwgbDCYL01VszYTQQMk+UAhVhhoPtgc8NJ0umkJLs+gfIF2boItgjBeW3ViZJBgbOp3f65x7rizJQ5mFFjp+xEkXduX7fef7fk8q+THhr6V91rQACvwi/bG7/+5GEu5+DCq0XhdOe2bk6pfr3/AAQAC3bs3cYgIgBpjGQoBkHigAt39mElPJBOEfGYBGcmV4/Td362IiwLdz9LMpACqNit+o+TGCgW1rBR0A8y5d/3U9UByzfPE4R/epEjA2IAwwEH9bq+3X4Ozv8d1/YlIAfzIkwMlRWfaBhYgGeMpQhvIAfsF/NIn4n+K9wCUrORcOr1y/cZ0lAAUBfzeC+B+9pAzA5BjDn04k2uPH4E4j/rVF6+8PWjjZ+e5jWehEVgDbgc+A32CAJVU4+HBpI40JjW2fB/92MP7TZ12odSgBfNW7Iylcjv8D/GOr81nv5W8IgGy4oQr4plrgh4KhsHmN+nvdPUHBZvBX6I9MRjQDjE2OIvyRAUABAAPMGBJg/H4gsJFH/NNSzxSOAOO52bxWQ2xAhtZrctfCqwMKAe5VMAdYMVN8mgYqxs1fedn8T++p8rgAmSJOiuCwfvLuDYb3UQoEY1yBG/MnYrH4q0OnVoPvjsOG6gceGXDws4t9kQDH8ZJGP3yW0mKqEKRw5xMSACABioR/yxffhNf8+TQQAKcBSQGMKAFgOABmAHqxI1GdGTDxr7UaEPe2ZfXgmCdVI7SyCFZgrakGEPyrqgGggOXN2ZjsFlIEYJd88R+7BNCpScDvGaQqPLRj9XLcP9B4wlLRawiAOYK/vvznllf9lO83r/7gWfSz7Y/QcTWAGwMAAkABMMNhQCwGnPjgh0BggRUAWuNEOp3G9l+el+0ygE7JlYKht5wDwBqgqmgANgGO1/A3SQS21QFV1AF6oCgVGh7u1U/fvX2VKFuhnR1MA/hjNJowfnT80qHvXakiCezV3fCfVgMqNHhQf2v5JAKIFOArFos04VBvIyjS9KOppI8IIGQlcuHw1Wd/AAJABmACUFnAUdcDiAUgAqDXO3qhtwH+Z6oG7Z3i+sPczTmAf25hZYE4YGuteRBAEQBTwcOHa0ABPk0BPiSA/Lefd7HWoVnA7822LttKbeQCzU9Yd/TdVAYgq8d74HSPjWSI2ggH9HLpNsofsa+fSHpERyclBAAEMAP3v1cBfAffJZnHjb2g+0MZnMc7lJFNALQxfCghS3TZBQRL73YpxF51qlVSAI7IAMdp0PoSGai8bGwHaJUVcGqH0mPEjUYsBEAJnGKKjxeU2litlLHyb/Ydgj8e+BGABnDyYJ0CgAj9XSkX2K0f1E9e6dHiSANDyvXDp0gylSqmaPhRMiYOIL8OpPwYHQBZgPfHiQCuNFEAHgnAXoA4oDUDDPQHbWoXmEP8FwqFlcJfGsIBRhpAsC9MgPFAf8gXkw5SGxXAN593o4CdqQA++ynupoh9xc25QOtjGoCsiX5s87kWDAVla5BeLu8JAhD6+9j3w6MYIQkQdS0AKwBigCvkAJgBuBZw/Bk87Jv5Mi/tDllD6fS1aykcl6/2ZQ5zU7AKyG+XjokA9gh8fAvjtA9s+W2s+vOIghatAo1nnzlgV5oE9jhDANCun5ycHiMRvBo+AomSP/43EoCDPFSr1mrww9SQkig2AGSwX6sdov5Hrtr75UgqgSgbGETV/0SNAVD4Tw2TUcAXYQFek7+RAyAFQARglAGMiQRAd6UVAL8jBfT5+5uaAE0BA8Gdnqdri49yvLd5YQEzg81MwJJuHFqmmODyi49xyqNPEUCoFP+6mwfsVAL4pyaAWKi4EA63g7+h/7Xx56h/MWTzTM8zfSeG7++5EI1G1HOIX0Yno0YEYHJUQgBAADMcBOQo4DhQwKfwfe5kRAGUy4mpqfTsbHpY9eLLbL6U0ax/igbgYB8uXSIAHveD8HcU4B01DMRp1xPUJiTIc4ZUblAaj3Zl3ngdueDkPydVhH/NQegTBXgOyIH9Ktca1+HnPbZsVQsIHiCFUb9UFKAfHR4uDsseMS0AVlGUfWc4AIMARptKgEmWAPL6Dw729fhbMwDOE+sPBqPrH+fu5Ar34Q3eF+8+dOFvBgEMBUBZwfnl9eI2MQAuTrSmvuwSQIfWAX0b79cEkLzZhgAwCJBlB5ANm3G/jSk7NCBDqM60najZcb2IfgA9+f6IPIL4LilArQCoFnhkxGsBxicmPoTvv56HJx+T5VYGd3PNzs4mh4yVGzicV3XbbSdOyQEQ5CquApCxP+Y4UKEA56Xzsl27YLMEIcYE4dLfrTMF8NRxGSGCqQLggdevAfoOEkCNJYAL/prIgFqde5Z3d3+J8zIzCgOW/Hj1Y/Y/RVuBUACAyuFOACsUX4RX5Oon/0ICuK4IQBcCmmkAnQeIuG8R/G0QB/S2kgBUJdQ7sIPbXnO5Ap/7BcwMbnkVgO4bVF0EIALm59O2SwDJbiFApxLANwYBTLUnALW3V9cFw+W/vNoL6O9xZ9C5k2Ldan9/3wU4TADiROn6FwUwpu9/qgK4BASAEmAG8a+Kgccfw+P+J0yVY5tsOZRKJUECgAgYcndoZox22+2jU1LVlVqtJhaA0C9hQPcrNRGwyYSAczSAihhWaZ8AdwsaBACsQLtF9l6z7hcO8Nz/zAC1QxlaUH8jbUKyYSRRLGINYMJfTDD+U8PDMWmIjqdRfT2aFvyLBXjvFhDARW8l4JiZCdQ8QPgHBhi8oHRAMwKgoaLboeLs1iI4gUWmgEWdGXThr5sHRQIs3bv9hAjAtkt2yRr+e7cQoEMLAb92LYA1mz2HAK4q6c+XP8X9/D097gg67/4gjf5BJIBBUQD0+E1G8YMVwJhQAAkAzGFfGiEJYBQCTHywgu1AKYsH4pbLQyIBrqWHqRG4YaoOKgDMAhxWmQCqzAAVR03/VbB3XCfgNBUB/9uhTB/tFWERwB8IanQEVdQAZAPo4+wRBXGS2FZbhvkdu4uDvmAi4U/KVpAh1QuUp41pPxABTGsFcFnqgLwmYNLQAMoGRBQBAAVcgN/gQHMCwBpB8Ha2XVxfXsgtLJIRQBkAKsCoBNCHfcDy2u3b9zQB4Nm5cH4AACAASURBVIjmr7oE0PkEEF8Nn0MA2YBx+W/N+uK2n7W/DBDq9y6MQOnfx4+YSwASiqIAgMb/pFL/o0QBV0ZmRrwK4PdfoAfZ4FR5GZeDgATg1UDYCsgbuVRrHvwlWKZWILpjq2TDlQHQ+0D0V01xX/kNNKCi/MAEh4hoWitAW4jEBZAF8OoA+tshEcDhaSZoNAqLG8ApgTIPiAiA/YGNDiAceHZdKYAJqgO6rBSAagZqKQGi4gHgl4O/HtRwTQmAOcDvx+qwzcU7JAOABVYW/7ysJcCSBAEJ/VvLyw8A/yYB2Lb1fbcQoDMJ4MspSy35jcXXz8G/cfkvbCbjVgwX0Pixm6RRQ4oJ8PcA7gdRAQwyAVDkL8ISQAhA1QCCCXgyKixwkSSAKgYmAniO3/dFHh9/DALgftBkOo2rwYYyiQw4g4wxrxMIIESVwIwxuPlVKcCZqN//6XA6Qc0Xh1PFFQP4xijnIKAjkcCqiX94369TdWF9aMfnSgDFAxk1EBC3EmdCIKlDuBUQx4F8+MkNIoDrJACEACQNcMlUAGNGGFApgEEhAKLnvr4+UHJtCACbBazi+nzu0UKBKQBrBB8snTnLSw/u3UYCeCoEAAzg65YCdioB/HUq5BLARqBtDNC9/F+sxiwfuEN/vwJ/v3dblPb+cvm7CiA66V7/KgSoIwBjHAcYQwngJQDKAwYW4twpW6bB4MAAU7gclNqBS8bE7hK3Auwe7DHGJAIgZQDKAGgecBi6zm/BvLe3UKcaEP+1KqHfqdWYCaqN6K8K/OEfpMnwraWgr6aG0Vhwuf/x/9gXojvVl18NZLOBL6Zv3FBBQCaAyyMIfx0FGHPDAB4REJEooJIAfXR6/AOtVED/AC8Djs1uFe7kCpwTuI+1AR7wb4EOWPsI8X/7o6c2ZwFtGwmgWwjQoQSQ2lFj/2NoKwNtj7r8cbJnb5syEh4kive/cUgBRFXwz0MARAGTygSMSR4A8X9ZLMDEp1n44ebKFk/ELGdwPS9BIsl7gTO0DlR8AJjnIzAAB69rYgEqnApU3T0SB2iyH+Qcjd96jgDhXzYLVCjtr+DPWBf3D2zksDbQ0gDeKodMAKcWjfwRCsjwB+4jRvVfxIXEPhsJoBTMbyEBPJ/+4w0zC/AeEsDFBgWgywE8yUBmADEAIgH6/MHWBBDjE7JTG/O5XEESg0QBRgxArn8kgFV7m5IA8ObL/9glgM4kgH9k9N4PfKjC58E/+2IVnH/M39/fupJUpQB7+zwKIDLGtT8kA6Iu/A33f/EKHPg0cgUI4LIRA3h/moYChVNxnplfztCKYPyEBIBNwgkfjdDlicA+CwsBOQSAVy8QAEAfsP/rr/gnnYYdga1Sge5/rjRQQMM4IUwsiACoivz/L3vn99rWecZxkvo49jm1dbAO+BxJhiFLMsUQg4XIbnIuEszsQi8EIXjuYE2plsDA9KLsrgkJYYEScjs2yOYWDMPNIIW0g/1gu8g/MJBkIywMDSnYMfIvCc+GSXu+z/O+5xz5R3rrC79O49hxgqOe5/N+n99i5ioBAP6APmudznpnfa1Wl++tDlZsKgmwxwRQAkDtBIhxFRD+ubHRITImXKzVCgaC/fTFtVABoBSYADCX49dQYyCbjTYE6JJgO66yAIEPwArg3bcAoEeWgSMaUO1dfHgP5UEPCAH37t8JZ4d9Bu//hgLAz41l5QKUjdJ355VAZ9L+f/KNpRd/9Bnuyx9zAT4iz99ddnqOlJFGgn96IBQrAB3/l1NIZFn+c7sa0n2evAtGWCXg+tPTS3d/MleUFADnAMbyE9M/PAGAbpXU0oyK2gcU44VAMhJE1nbQqRiVBmptX6lc+wbMv9ZpNxv4I6MjV5qtdrujKFCrv/2O73LyIzph9WgPwaq2f8Qb10T668N/sNNpt5rNKbrNY1uxkWYbDECCgr58nScMvN484ChnuWunaIoLAXn42RDvPquWDXNqdnD20mO2/5kQAPSazeWSOX2SSQRUGQb05uUUG4JCYVvsX1QACPAjAFC1Ab39hoFJghIMuAsEPFTmf0PsnxmwpEIAAIC7dA6AM3k++cYMN/9UPj6xBygYB/LpolHi4WH9p9SR9xldg2ciGQA8YgQADv/jCU2LuWftQjrpBQhI4PlEFrBIQjZZ1IWA5ADkp8fQDXDpWUkXykgT0BDpYm3/WAaGUWB+xS/7/8PYndeh/XVajRTmc3MZEepozdQUYaBTEwh0ZQVOUfqrUUCsRgeJivtfQ5RBhwA43icEWMOysc5+sxHzuZmJpwKaJddstEiOSHZiTU0Y2Gm6hqUWivN0M1/tBHmK8acKANhCujRIHsAThACYAASA6fzEZGZ4co71E15jj35KZxMZqAJ6RelgyMIcIKte8rQ9oBHAXkBEARzZ06a2jPCHTo+DpICz+DkZP9yAXz+Y59EhpP5vsOmLBlhyVCsAYgDfnpcCnk0A/Mt0AgVQvneKAhDtf9UsLXOn31HvMKgADkdjCgCQAeAf/M4mQZqGAiUzJxTY2WQRBcFEg0AC5BgNhRwpAPpETjUDTPyQz49NcxBgvqS7ZfxYLMadwEoApHxZp8mNNO5/ucVmhxQA3uqdZgzDhHy9eROjO3nRYGrkVksgoGICb00R1PUm4W4orEpDUaj/Oe2IBsANBBfp3r8SM2Q9AM/6kmNZRIJmZxeCYXVN+QA721umVABYasYIEWAU448R64zFnLIsFCWxNjs7+EIAoEqB8xPDIQD4qicAFLKgKV3/9IonMkm69wuJZNKj/wtZeoULA+PjAxEEaABEKrl7jjt7DjaP89SIZ/dJBnA88P6dR3T9swBQLsCHv+qtKgUAAHx1vjD0bALAdYLVf9g1c4r+v/n8iumy2Rzd4alXCOm/pK8bAJFjw6YTdqHgAQAFACAbt+2cB2/AUwAg0Zq2vWE8tAAAEMAzwfLTXAs4GzNVoszAhYjEuLZ/ngUgW7PMxgHv5llfR6Vtfa2Fobsyb9uoRNfx9Rkr5E0MNVkJ1IK44IllAfUIA1aPNQ/UpbZwVYUBuQWxDrcDswLU1CBkL6SdydRNTSW/Va8hPrmupwwduuLGIKVZ5j2n/sLUyNOpUW58VKPHrJHbg7ODj397bSaIARABrkMwzXEAhX7yWAEU2N49mHzcy+Sy6aydZgCQ9iIAjI/H4+PxgXGFgItRABhqU1M36nU0gAOCVnzpDhAwf39+/iFd/3RCF+DrBQJAmSsBDffWV+fDwc9iDOCT70IAWP5HRwGgPrz9fAqDg2H//d0D5WSwbHSBaF9YBXghBACKzuJ8z9OjRwCAEsgWi9kB5QJ4HBBIsHeQZQCgrx3mP5eZRBAgf3niAZTIYklW/5bLaJXnreAYnYnJADJHnzX+vggAAsDORv2gUbLoRq1g7na5ggCBZYVrevqc5app+VOttjDgrVW/ETdgNfqjrrOA3HWMnAOURKfdHLJcUy3/4PIFPm5AAPqM2zio0dcTAHZ4zMjmnstxQLZ+njKExaBTI7x+TAGAKzZmL/05PxPGACIASGoJIADIZOABkAIgAKQTCgAkAej1LozbTIBxFQq4GB3YrvRcAHtEegK5JwTor1q9S798fPc+nYfvifkHEuA97DGrchqwbI785RwAZ/F88fcIAFK/OBEAN78eMS1y+9j+xdQd/QQ4Pf1OZCtEKADw6QgA4GsqAJAC8JL0YMYZAHaaBaoErT1cXvSIJoYzLAFYAQxPIg04pqKAL0t6r4aTSjkxAQDbP1+WsDLL3JNxoASAnY2NFlb5lEV2m/IOHIiW3NFzSoYaayIw+NbdoZEC4lqUAir5x/0FdR5BXu+0rqaCCmUEJq2KIoBruiEDfN909+v1jY1NHQU4kJ7giFBBHcAQdz2l1KfMl5cIAP8cm4kogGkCwOR1dgHk5HIaAEkBQG44qQCQK3xQgALIjnNL9rjKBhAAutaICM+XRQeE/6nZQbIFoWo6i48eAAChAlCFACOWigGWy2bqHABnEwB/DQFgjt48EQDzWOd5ZMVUv6MJ0K361a8dAMBhAHDBOSec4gj/IxEgABAFgIiAFwKADmmENBRALpHgVGBm8noQBbw0eDtl6a08Kcd3YgEAZLEeT9Z1uQ3g1eudnZ31zb0Sy+6KW/ljRVqJcSIreAMIWCYYUDudAZF+gboeMSqhf0kCKgGAaQHtZqpaVQ3xWFJA5q9snzeDuKEUqPi+26rX13fUoLFXr1tudI2gb5CrI/avAFA2rKHbKMx8cTkKgPzEJLImSQGAaICkUgA5BYBiAAA6pADo9ScEsAhgBFzoj3R0GwIAI1QCJy4bdIzSIgDwmQAgogIKAgAoADQDnAcBzjgA3CuzJ4YA5lew0a97xRSbfw/Mn+6q/i4CkOXjZqCveEfd/GL/DAAvyzGAJIRAupihB9D2kgEBuAKY/NNsRgCQCwAwRk/4bxhJV119qzopH9u5SST7qgyozObt7mE8xxu2/4OtkmnJVavdb04SYAJ/d8Etb+y0THe0BRlQP+4D1EMABL1Eq6qqsK4+AAl2a6T8WfeL8ciiT/j/wc3vuiU6GHHM0/8dd498Fbr8X+Ht1fbWSl9kZTApANI5C7HUQizmCAC4aWPwdzMz7898rwBwDQCYJAXAKQBRAKBpVgFgLl2wkwQAepeeIwDYoQKgM24Loi/09EZ7uiMAMNQs0Z4TCGB+GQDgw0ggUBRAuSox23MAnMkYwB++jQDg6rFWAP74U+ui09+tDQUAhkyvC259RysAtR7jnXcD9z9UALatAGArACBehTckq/HceqwN6PbywjRAfix/+VoeWwouPSv1BXu5HczMTgULd1EHRBZVOlTjOndITvMyQdeUlVxbW1u+/CpYvxnZz8e37rLl+nvt2u6JTkA9av+qppjVP1/+/La71m5YXASvv03VviSGL5a/tUeH94SZsv7DbGyvY8zgf/gbb7r90a3hKT+2IPc/AwBZ9efwhrgOOJIGEABwDGBOEyCRzTIAMpm0zQAgBZZgANgFJF7itv2BIIDLgi6Ei9vloeANZstRBvQcXzcqAHj0oRYAOgrwNFQAZevfX5wD4AyeCAD63FsnA+CldfEo9sm+DUPvsIkCQH5TxQhYAfCDJWVnUqKezdKF5GWhTYvpeKGQK3L1HzSAXF1p0gZIW+cYACRrJ8by0/npa/m7eOw/dvsCCUAISPWqpdzaATBYALxhAGxvleT6d2F0rUM06GNT594WGaIZeABqQS+i1dDtK6a7117bPaXkN+j3qYVRf5UBWMPtP1pdUVvCBAGqe6lC4kJsv7l/AHGCzWH7eynJTvrW1oH4AKQAXh+a/aHNkZ+DjOcCDz1Rf2FlHiGAf1x+P3ABUAhwfRKHAaAIgEIgAsAwCirIs8oNEwq8tDeH17iQJeCmYf94G4/bCgB6iaM8FbLCMLIH2eg7vtPZevonAsCToy7AjS9VDIA0ANoBzwFwBhXA7/9mOkErwOIJk8DpfG4CAL3hPg98dehDV/StD3eQXQBkikMXQBNgwEawD5U+yE9xuU/RS3PVTzIsXYMESHuZonyyqLaD5acvT38/xg2Bt1N8v9KzaBmOgaG5vtzfnDoj79491ADYbpD948IvuXv7B5s7UNk46+ubhy2CAJSA6rtVNes4kL2WtdXePangX/v+qqmorgcM8W/u7ranVrR815iqSvIPxGk099+I6csMQfputrFkkHecgABwAPAbjZWIBKB/IzsAmH4m9m8O3eRW4J/9n72reW0jvcPMSCPPaCR7sppuZdkJVLYUsIgD8Q457RwcQrIFHQohpPKppdpceyhLD15wltLe9lq6oFYpu2RJtrALoac9dXvoHzCS7WBhaEjMul7ZjuUa+5D29/W+M7K96dUFzyibBDaWP+Z53uf39fwwBtCNQOQHgI4A8TXRgO/2pWoDByomKnUgAGoVJnLlHszAqwesAZACgADMYQLANR/H9hlblANOMoDbevBgSRHAgiaAxYdZK9KtgOcEcDYJYMp9AwHw9WWRHWTlp+7b6uyPFYCvbkv9QRGAigBoFFAGf7QRKE0CiAVASRpWqSNQKoNwTfA8IDDA/OzTUUwDvpsVbLlkme+PTdKGTtT/rgUHbZ/xz9k0l+LtwaHqs2EGgGtzcwtXewEHSAjQjS/42OmV5utXp1YCegr+wySwhs2G1zuu1EJFA8iBDZ/C9t7Bzu7QRQk/UCkH/SImJ7P9LfIaRwmw39W442kA2oFOKQCUOSjVcBR4/r0fqxjg9m/RFBx3g07wJICoKtwRvIFdl+OlSh2/1RsV+B3uoC7mbHWJAWg+gAggM0wAJxeaW8wBOuvTbWMZ8OM78UUMsPhZFmmVFMA5AZxVAhhzbU0Aj0/vA/oiSQAI/07HTVyKAFQEQAUAVAAZ0zAMmjGhmQApBxbwQfNkGI3NAbUrUJl9gfnFd6lBhcC5uVk45H6PB98TlQRwkQEAD5QPIGTAHRX3X8jGzReDpovw3z7aPXFt7exsbX279Xr/eujG8I/QvQaTVl3LsY8xQOwXzrYia0nw4/0K3s5O5MwUcCD+Lw4OyDmYVwIe8oZQgv8LLFTsF4th6BQPdmXZyPPvwpXhj0P4B62DOOyIGdBHt/Hw/6cMAtyY5jmKankD78qGngICtG/UExcCvl7zanjlVR/gDE8DGSYqAGIAXvGtFUAC/9hqOVT7WW4voQK4E0sAVgBAABhT8TTQPz45J4AzSACfvkUKwDqdAGjlx8iTrKnXxviWe/waUgB047LhjI9WUqZJFEDDAAx/HAXkl/CA2g0gi8FOUEADFMA7mAWYnb/6OT74X8YEwBXByBL0kyYpHnITAMDraC/MwvG/Qz7dg8Fen321Ew3E2zevj6ksALlXRqJYcaC4+Z9XJ3wC1ygFuDYM/3Xq/33Wh2+lZZ1CAMWbg0G/P/UWOhi326k2XWhiOtXv7w32j3aOtiEMKB58u8v4f/6v/srQx3DDSekCiDDIaf4Svw9fX457AK/O3QD0v12tXqmWSxs06SMMUN8ABggCOPHp1Ffw97ADiDkg9gOByzSPSQCdA0gSAA0sxRvHLSCAB0tLi4njXykAYYDuOQGcXQKIFcCpfiCjI4+zpgz8wbHuqg3W8QJLkP24FltUgC9tAmQnacj5zwRQ4POfgI9/EoOweDlYRcNfrQgplyemIYLFXsDZ+ctPR5NZQHrvSKJ/ap7phG5zj9T+cwJ9P9tpjg36oW2vrKw4qzOrqzMzMzV+7uGhN9LOctd2dLoeq4IUApAKyDRf/1tXA3s91Q+81jt+rfP477O9bAL/yzGnWH7GToMcQh3Emof8+HIIubQNZ/1k/ybwVx+YgGOD588HK0MUAnAj19OIGpqy4X0aBb6N0f8t1QWIx/8VDu5JBFTKSQ0QwAubfwJW/MgASAB6FCCnFYApWQBZ7aMIIOJynhrFgpdskUeKMD4GBbC0uDAUA3AIgPi3onMCOMsEYL2RAEZGPnNNHgVDBRDJ9uqOgr/rEvpVDoB6AHzfyTioANTxr89/mkMXCvAS+Fe+gAr/ZYV/IoAfcQgw+wF6g9+fTAKDFABK/5C2aXaaB7SeZ2rMd+xuFvtvi10jV8NAQzaPklNGq1WBm/zIPQQjeuL5PL0qRUUrrQigx41+1AfAtX7p99fWP2QAAgRgWdGQM6mF+4+9oKId+uld5Qpa4sxpZEjKuFlggsH+wdHOi90jd8jiFIecQsx2kgAgP+BRHAXWW4GAABqU+m9MxH7AqAEo5KeoH+FfBxEQqKgf3xpYYJgARAOk44YPh4MASuVr+HciVAC6WthOEsCC1gC/pq+iS3fzm0/OWwHPIAH8mXIAFhPA6X4goz/rmnrm16femeEYAOIHlgA0K0QyAOFPIYChFID0BBUkB6AzAcGJzUAVfn5byiOEcgAvkQBuXUVr4NHrctKKez4NAZMCQAoIt0O3u2z7Jp63KdMsIPwowYj5MG2Jw6YY9PYtfLVwV06h3TYzIAi4fdVqHr1S9T4c7uFhP0K/3i9Ag79o+IGen/1iJPmEGPoE+tiDS3+9pH8Cj9/YQxLAlAm8uZM2xy4O9sNl20pk39yI5x0tigAej9wjP+D3cDG4GAL+UBL/b5fKlzgNoDVAHbmVM38BMYC0/tQKNAZQqyU8QYAAjCQBcCNQF9msG3dOYfcHEwCzROZ3EAEsPVqIz3/igJ8yn5KFSfObP5wTwJklAPuNBHB9JTNMAK60tkkh3aJ1mIC4fIYCAcfHBABc9DghBaiGoAKf/Pr8V6vqYv1fSYh/Pq7HG9wKNHt7dv7l15wFdBKiPcRfrktrgamk5/vwpm0Dx9sLQWkcDQYqQSGVkQDdpoFg/q8f0ufdzrXzbQVOz8u3Tfx/Jwebr+JuH3Tu6ZGv+NraWnz+b4rVF4UAOHLgul3byPP6Q1AW7RTiiRqmsVeBe/zDDmb9O5i+9GlRKgmCAiAwh9kBI2N1HJVOpBAHGQ4IIKJpYgvdwEZHcSVQYgyg0bgCLwwBLpW1HVi5kqCAgGIAZIC6KvzV2BSQtwMIARiGBAE0BGDZqRR9/lHEGoAXl3XgthNzg79CBfDoeAjwvkXwx1/Lzb+eE8BZJIC/THZjAvjwVAK4dzMmAD9WAHElIJNjkBcKJhUAGf2mmcqDsM6JAC4MVQDkOhEAlFkBtBIEUMIytkwEX6ZC4IfNdPJsJOkfspNeaPmIf3ySAf2tVglwlfIlkx0l9obwP4XjVPfbYUMe/NtcXtYV1msX9w83e8o/kGf813s86c/rPnvryviv19s6GmwjZNMAaIAXfOkZ4UHqmfQ5HYixE/7OEwk0IAQy2U/lmQWCQr6dzxMHoPTWuTdk2XCSzM9RAfwcCODuB7fm5zX+565Vq9UL1er4hfFLJbjLeHPRT7KBFAVIIkCV/rH3pxZQPwBEQkoCpIgCiAEc0HL0cwk8w+KffCQt1EMKwP3NR0sPHjyKO4H4et/uqhjAbn5xTgBn8PrFV6EdVwH+/j8JwPElBdwhCYAkYOUrFU88Pw0s/zH64SSBc98wPB71Gw/gbwWNe0+tqPC0L2AlGQEw+kv0bI5XG9euvXMDCwFUCMThpGR0LGt00DwHxAiALoWxBjzXrSDn6xw2dy5FeCTx1g2X04au5YekBVAOAA9gBJM2cpgnNFb9qcHB4SYb/kMIsM47PtcZ/GrFJxz+h/t7Y252JW3kMbuWl3PUbPsZGZcKWa4g3gnDbEuEL6YgG9RSql2AeADiEHgZ2l9B5d00AbjZsbuj90b+NAfQx7zIHLUATQP8Af0XlCW43gsSJwICSgViRcDDJoA6jwHmSw2pH3qpnDIHpjyAQ91fRkWsRXPLySLAUA7A7g4TALPAgiIAtjB68uk5AZxBBfDVH9nkw/9+Arh70RYL0IyDHhCRdAF18BUZZOiND0+uUEg5skkG8Y8EkDKZAKrVIKfqfrwZJO4AiDcDDql/ADA3q2Ez0DWggKtzc/MvP4dP8S4mLuUcj0f6rKib8YhDAq9Sqo5XcqqXBYUzenLoefzkhQsFcDwoYocQMTxLm7maV6/XZmZWM2Te9+yZMhdcV2c/LfoDZfB6/2LorlB1oe7VajPcTusoCY/lyZBHkZNWALEpCB7voJqMNiC/9fBhq4Irkwu5tB2rHKpUhtJ21Xx3lIqAcvbTQgCcAQT8IwWwBCARsEHIVfXAisBfVQI4EUgEQKODnjGjCMCQRCD8zFNMJvABDFdlATkGsLVzgOM+QgLAeeDFJAecE8D/gQIo+noY6HsI4H7bib3/mQBIABDu8uUyekuVC0QAubQ+/jEoKMBZmCdkj1crshaA0R8MXYkKYDkZ/pcY/+PVabQGxYnAy0/JFKSYqNzxnpCoA0oEnuK/VSv18sOflArOMj+gy1ak5nCKOIAXUcqCa92WNArTgE4RDuMIp18o0nGcVZQB2C6TslfQKWBTgn7x+Oe/br7en3Jdx8CGmhpu2jSogMaRL44AxR++Y1EVJWNSRJ3V7wrERGZh2ILsZ9oBcECJhZGX64g/ILcqEM+5FhZrcBRYCOAy4n96ApsAUACMX5LNYPF6QL0kOKaAgHOBNWCA0rRIAM/I5XQxwKRFQfDjzJeVt7BnJSQAlQHFOhAIYFEIYDFBAQt3fvBf9q6ttY30DKPTRNZIYRap0cxo69JZjcJa3VWRV0uvDBqBo4NVoyo0VFkZNtRtTU23wrQpJGxhQblooM1VehXqXCy0Swm9MAuGhDZmf4LkAwbXEQV3e7F7sVlCb0rf5/2+OdhJaC+94G9syXacTKSZ9/me9/S8mQAAfHQGAKcaAGjze7Eo8HkGAMWd/auq/gB7dazw9Cm6Qyo8+ScS9e2fEAC5bth9qmKAAYjAmLB+7VgNkGf9tmv74nARQAwHmEVL8Hm/FGjkd9qN9cp92ygcGZZd2NoyI/GdjCSoO9sj0f+3raRso1x3WEWr2eQierTQ1Wp56GZEYgnRGxDbpbXD5e7RkOhnTM3s7cY++/LZs/98+ncv+v+vT//97OnnemI3LMNnYZk9l6VSovNfzYQ02+iVS3VHnJXPe6teKvcKZkVRhTzA2NUBBguJVO4zD9DS9vrYK70TPgwnJ3CZvtu45AoBYig4dvELhQsG0wBgAEgAcQBRFCSYgJ8G4Pe9zZcDOmE99A8VjAqnbN0Xwz5ANKwUTZE+oTUlSwFEJkCNe+JBU4mrniLIzcsvA4AzTbBTCwDI37/cBfjxevQFACBc6AoPnsAWocHFTyrB2j9QAk7/VcxOzgIvR6MPP7EureXPr7QCiX9L9KlI4VpDAAC0wbHj1b93LlAKJNxq2P+rj+w928htbT7aNKPb8Slf1WKs6zvF6bffunjpcH9hfnF+cXGBVhdroUtf8bcL3aZTyptpBXO3VeIBqIDB3haNijxGKLy7qybmXvvii6dYXz59+tnnc/Fdtn5/rB5TqRH6jwlKCHAKs9WFNg/s8AAAIABJREFUxXmsRSx53mq12q3i7F2nlO0ZlSmGAFXu87G5USZtbG0BBNI89dTtV2YXgFwBCLe9L4aCgv6XymVs4gUOA0oIMHyl5WnBBUwhDi7/DHosmtHJmRUCgE6PVQMLpp1O+lWBeFFKSNE8AJiOoETKG1k4invdYdHE61IQ4OYxH+D1IAB8eAYApxEA/iYBAIHq5Z+8EADeeR4ARBRIVTNMKyEsYVckAIjdP8nZf7iySfIBCp0OIYBV4JG/Br4LrhwH/uxj1D/wO/BQhQuAluCLfzwXaAjkzRGO9PLGQ6XYzm9ubN5XtqWOnTBHPVG8cPHwgFaTjE7aYNVdtCfDHCUcdJv1cs4q7iZ0FZV8OwEBVHpdKXIIZmjt7e1F9/bCoZliu5gkQ+FwuS+Igp0/Xjx6o+Q0Yfz/lJbv2T6xgF9yB09TAEG16pQtRUcwQh3J8aZzmfS9+1tbW/fGsXEi5uogi6KLxNehjvy43vSUACAHjpapbJbnghjumjaJBggMMMpoFKxlxaLftDTNztNzwSoQA8gVbCufzXeMVCo549YDKAA/pQ244DiCldoOVASrI19BPJr4mgcAPgZcvXxVUc8A4CsCANh59Gv/FwDIJkDcBBHB3ZFFwrRZLel6/3ISiGHa7qhvBgAYtHiUxo0BgLlA3Z9L+zvenYq7uud5AM7FBygFelfkAdD/PwIBWL733iNFsze3rGiwSSUWSyTa35wcHE4mjUljf7/7hK2e9v1FYgK8M9+Yv7EI26wyEjAmODUjRbgxkgDA1o37HEFNrd0+Ojqy0VJDjkExEtTQ5DMSp4/ab7wFtvGPBWH3C+J881euXFmZv4F1/frt22jlq1b3+XjyxMmFmQWIhCTkQJV1goB74/SW6wa4AKB/iDDIA0e6E+RXNMgTIBi4heNWiUjAK4YRZAHkDORma2Vh/jxtKVs2Nc3CN3Q58r18hxAcqgE5vKrkjHAC6JqHkuE2GgqPCKOPrPS21GIT/x9fGCCq/uh9qQgSCAIQAIR9ANDPAOCUAkBUFu++VBX8pxkxHlaEAVU3gYaCsOQJAEiFIsL7FytNNp+nmwxT/jomACB/HAA6IK7mc3E/VP/hNzt00+Lv9lAJhCwgrdvf4fEgU4IBjBHgJ5L/8L2NcNEyIuFMQJk0NtLD35oI66eHfbKYhcWV4bDfb7VWW6urfXEM+oPhcG1lodkgWxSrUTPDuj4Kih2SjdNLm5kpzhSJB3ALzUxqajvuWT8yqWN9yn77zclh47DZBKMgrFmcv7LU76+66xt4oJP2+yvXm0wC9pmPPHFMVR9LKVDucs5klHv35pIbmyE15tn/WI1zK+D56wgoIJBB/4hTIsOH+c/iE/pKUl+FST9IgNWZLcHcycizYuAaAYCRFXiMt9qyK/RTBgA5KZTDgJFUqMgAYltHtpnmsv6Y6wMEhgipH3mSQMEYwBkAnH4A+KuuCADAfffOCwHg1zHlBADIY6QqXL9jIUpc4bmffu2/eBCleFD6KVjwBOjWywUBwLDcaLXpzwgDANC2T+CQrdU6uWyeK4FmkfYmyotKgGvjKbcQECGA5R/cufMoWrFDSiYeGE6i6pU3DyeOM3EmDALVlbVB6xctWoMWoQCtgfgcrPXXhoO1+a5wCBgDnFxoOeGRAAYADpGBIiddiGOtTE8MVdUz5kUCnEZj0jwAmBDaDOhs0va/Lc1frlZ/fkHQDiIB4AG1sM5FAXP8kcmsZyKVV5XNja1RzNVfQeES87TvN4myHDAHaBJlYQCYJZJ0qz6bE9MVAxBgGFaWAIC+EhSAAYBzNyakw/Ejq1KBNKNVTHkUAGHACF1GWzgRtjWdlABwwgVAEJBVQX/LLkCQAQRcgLPBAKeyDOCHHy8rQs0LxPPFAPCzbcVDAGVKlQjAe1IsLRiAxS01WiXl7v88bS7lqwAgFKiZuPOOxwAMUbYaDPoj+of6fyBAFgI35XIPswGYAJDL+wfc/6/txrm2Zw5Gsbz++PGdR3taOjyVcbXraI10m8wexu/Qc71LxjjAag3puYWNX2LAoD8cDNfoGIIGMDHHxtwoxHRCABxi4YXN0IfsbqAnz99gqW7VruFMDSIAB4fNhbvC+sn+W6sn1gDHypWlu4CAfQEC1Sf1lD6W5k9+gEIQUMlkNjc2zLEPACoLAp/7oFGVDMAHgFqtBPlkTggeh4BXrPxsDSOXjE4WQuudfNa0TVvjhKCN3+CeKLc3UJYEEgBgnhMRKxFFtKKivzEmE5NBAPBEAW9efhkDOAOA07h+8zEzAHELvwQArp0AAJcBQOw5nuIGO1u01oABiMafpJgz4U4EEE1AmArKEX8fAjjgz4Fq08v5mXKrIoaKWxqxKxcALjmN+kPRoMjuKBckjJd/9bs/3XkU0pJRKWUd49eja5cmlybol5lM6o27AfOHyTMHGAzxOezTsTZcWlkiCFgkT0Cu7mya3IAdIe7Dc0788IawEQEA4px6plNn+wcEON27fLZBv/W8+bMTMKDTLS0NV7oEOAdVfDarTpLOl5nDx1xsfT28XlkHAGxmPA9gPNLfRYf2w8MqOIAEgFKdAOAW3ivyAvLeaFBGAI4HmLlSDWZs5nI9vO35Di6abbdFi2C7LQWCipIBgAOgFgBXcCYlioWt5I5bUynqgXb8NKB6/4OgKKCnCbR+BgBfAQCQVQCxlzGAn6sBAIgnvBaAbVEQqoTczjp6dAmAxwBSPHYKXSea5iqA2bb0AhAYsKxp0wzs/mLTypY5/ockF93W2R40gVD46jiXrqMd4C/LLI8/h2GfCQEA0VQk7javwyYT0YsTwf+dSb364MHAW2T8rT5bvYCAPjyAJTbIleHw7oIXD+xW7YT774lp5+wC+PUyEgB4/89sNfhkCDgQ3AyGsH4+Vk+CQJ84QP/KEq/hIp2uuQ/e0ayWRgkpBc5BgLC2PgcAIDvyAeDPuEgbjBnNhoNQAADAYQAgAlDPFzyJRSm2TCBg5vLMsYxcr9fpdfImLkPbLQtCIWabNUKEOsAMMgHIBCbTzAdSxYqWisa5pWKbOQA2gEApcOJ5AOApoS4D2D4DgNMLANH4/2AAnxwHgLGU0t2WocDxKJmWRf6VtEcAZBBAygCk0HeqaRWv2I/tPwuZelHxPx0wfiw4C2WRukKWW2QBYf9Os/57nlXiVsmOJQN4mEyG4v4Ui3hMLxwKBkAw0G2RPQ5d46cvhfWLQMDa0lJ/aYke/8ve1by2kZ5x/DGyPCNNbCQijbQYokpqwHFVNFHwGCpiibUlJbbruI3cCRKbQihuw1ITElhYWlqYXGpqH8L4FJpczGq3mD3kEvAe1PpPsKRCIDQ5xL3lsIdettDn431HIzdZtjcv+JXkBAcy+np+z+/5+j3uhtusg10uzNeYlIOVRdR+WWHYS29yx+zIsPg3Ev9fLaE4ByUca3ANhy4FoQZYf8PLAHIe4Mebd+8C3tQdt+k2HZcuhwzg5XwiDv5foaEEvIcYACIMANh+qcR/Cx/Sbu2VqChiKPDQLD2oPnhgYgDw0IyJrUASAbgmMEkLgSEGwAXB6VXZ4I9CQaQSQBRgejrC1I2yAIAAYdoZhsol4yQMoBACCKV/HwBoA7rg/e0AH0gG0D0DgFMOAO9PAuqH8eHRkwBABKDL8hDKIABI7h+ayLD589g5D/9SyuA4lUkQApSTnPwbMH/MGRpSIJj/tMs5qgIuAgKYJgLA+jmt35Ny5+l2a7tdCAR8GQClM26WyP9Xwf4dtMd9NH30zE7DgwAw/81Wu3UPfTExgKZbB6v0GgXWchrtxuCp9xFp+ez/PQDA6n+mQvaPIn3zDl0Pbkg10PyvyQLAtfvXLsIB+5dXhOOuEeV4CVSg0tWE7VMxcBgB4PnzQh8AcHsTvPxnr2vza/OinTFHp5ynHQrYFDgDdxII49Yg2RsEb7Nh24AAsWwGewRFe7BQC1ryQgChEEgAEBFSAaPE9WmqUiQCNf804OM/+BjALYkAFALwQGD3DAC+Bwzgo3cygC8HAaDfBkB+oMsAIEKAkFwIHgpHEskC7wUDDOAxYKEBTO4HG/xjmAKYSgyaf9Z/SOLeTuNqMGwELOUeHGzpJFN2h3IARdoF/nT719vtCO0u7hOAFDBypuQ1xxEmSVbJ5o/233SaO7uAJ/p+HU1/A2y/DhygXndXuEsIKEBG9coAgRGOcDwICHgAoA3nS4Q3ADjz4nINvt1teAzg4rWfLu/utVv3G03vYCTgIAJgLqCGMQcxAD4jDACPVQKAYkcr0iDA2NjuwZ8qJdnKjPsAKLvflwPvkwDCAI8CZG2qARgpmhY+5iyAEAvD4axI2CcSCgAwIZYGhlghRAAAiwP13gcA/d0gAQaA7hkDOMUAIEcBlKP/DwBIR99jACzvFxF5f3AiIdxAl5kg3p8yjJQHAMey6p9dTYjqn0EzLML+J30bAsj8bRsTACZuBskdoC4wPsmPOv2tXgAArZ1bWk8k/3iflZavsv+HgNyRCOBsCt8PB6zfsZqP9HVdX3fqaIlAygED8GYRAmCcPV9WFdkPGBgZGWQAHgAoWgIDAKIAtf7l0P6ZAkDYfxEJwFW4mn5j02KyAXfBAdj8ay/X0iqnFAEDosA4nhT/xgDAM08dtfixWNew/NkzEyHAZO+fz1+AUMm+YvPDlghA7+b5LA0KAgUwqBMgJoovAMXZNO0JXUpRe7ZRCJFQMH5++BLDEwIBQjzm0AME6IpCQJ8B9ORigJ+9iwEoJAt8BgCnHADwW9d5LwB4fQCBoGgF7nISoCsZgDgy7g+FIga18XIbIHzpMgwF3PF33B/5xwDAOOH+k9n+gjv4MsdEAsB8vgXGuq6P6b/88vNzKscf4BUBACAC0IK0s0Ik7I6mK9L+rzuu45Fyh91/E72/05xrbCEA7LH9uxQBYBoAC3REAeAeOZIAMCokzuknnqgiOgSOhsulRaYAtRXw6Iw2nGFEDsDNP3cvfvJoHZ7/Xn2ueeIsCLh5YQYFA6CJxWi0wwCAcme41Vgt3v7iED4mXOI4e0AkAOz/MpGA/AWPArA4EHOA87IggBQgietDY/ks5V3hc8iaD/Pk/vnTyqbCQiucG4JRvZHXhvYBwGMAJwDAvxjgFusBCAAgndUzADilAHDHA4Bi5zffBgCjEgA0TxeGkgC+EKDADIAwYCLLeX4c+0kZ6Xy2kEmmKes3MPFL4f+UsP9Jz/6TfQJA68ErlR+B/d8E9wn2evhhPB7viJbEIwoBdn6hBpWu2MaNIKAdEwF4Xf0neGTXkV7Z8ft/uO3fAINcJ4+Mlo/mzxSgXienDD+Sqix4R33OHx9D44oIDrTMomQAay4ceSXuNUDzb1DT4SdXZ+EltOt+23fgYTnXMQgADKiG+DWgviKmOdUM5gBU3MWAKmK4YSh+7q83iQfpn5nVktADQAbAsoCXxE4gzARkZ0QQMGnwI89pVdsgvQAjGcuZMUwAAi7TYtbshNBM5m6AiNQODAcEAAjd1C6HAGItQO8kAAhNsFvDGk8DnQHAqQcA/Ji+DQBGxQnKPqCuqAYDuwtJnV/OATAFKFCpD7fTwhesYMSSKSMGXz5q+5tKJQYaf9n8yVVlZ5J45/V2Ntq/rACYuV+NgbHqNz+Pq6SPj20xCAMAADtfodELxT2ySm1SRADV627TAwDJ/8nu4PdWG/V196w5MPjmhgcBlgwCgAHMl7ti1VkwSo4f5YNR7wz+FpVjR0r2NVh/BQCgtuDWHcdDAMoz0g/q//35DbzefbiGNcgALJeKAPMv5idUagOKsqowcO2nz55HVCQAqCNIyww68R8c6nTauWqFggDJANJX4CHSAHbSXw+kICBdLot8IdUE7Hw6Z9pLLMS0RInZCbkxhIKAiNjfEokERA6gx/aMacCenID4XwYgIeCDMwA45Z2AAgBI+7WofjcA0HxLtVH/VgkL+y9gCCDbfwAA4IZSVJT5HwAAiQFUAaD836RhDCT+hPWTHihWt4ABlH9Hbu/jD+OKQhogaP8oTw0AcDCEGkFdrE0IDqDNVBcXEQBqYOeuhwCNZnO/3QYrR/OH2yM0o5Y112xt4KyOSxAAdwtAYI2rc5VxhVciBIM4FhygGWNU8BkaCopNmUHFRnlegAAmAG6fbUAI0GpDxHGXKo7bs4Bgy/fqm3A5fAoO+X8616sUBbwQnQc+TfCnz5+orCFGHACQoNhRv1jHRIB+kMNJIPNNjoMAsP30JUABDAKSVA7IJs8jspJemJHgakAWqBguX0+t5u182cjgGqGlzBLVZgvTHgcAChAR+sEAAEERAvQUmQfseQSg904AAAowdAYAp50B/N3HAN4LALw1XgKAIvbnSAn9YNjT+oqEQ7L3L0ONfkKNcikRW80S/+xrfaQG3L8MVwXx5+SfjQ0A3N5SuvxntH/9sBhHUU00/w5rEkII8LigBoU6wJEEgCtVCsmBALjuBtq/S46/tfNo+WZ7wyVYqO8vo8B+Y67Z1nfv1Yn9Y/yPVMCyVmrcnjfEABAEBjASCAb/odG0vwIxupwVDgZj1dIi1gGrK+4CXo7SAA2Am0Zrb3n2L/sO9x3vIYRtLWxsje3ue3GAYznAB9waTwZNqTQJ4BMvjUeeqEB10P0jAwAm0CkG47dxKHhs9lmlxKogb4jco/+XHIASgTMk94VqQSQXxlohCZwOzqZS6fxqLA8AQKJhAADp9CrrBEmpcFHbmcAu6/HxAQjwA0CfAXzqUwQABnAGAN8nACiqv38fAEj7h+86kH65OuOIdXajPrHPsFwARACQZCV+eKQg/BcAQAUoRoEpJgCTMvsPX1X4xtpJmcsi+o8lwErph18R5z28ox5pQk2PRQlRaFdRvUXcUuW3e+E15eRfAiVHn1wn2t9+BBZ/U9/dgN9twK2NOYVta66xq4NJLrD1ixDAovJ8rVYNewxgaPQIbL/4Fg6E4qgfKgBgPI8hAEDAq4UFvBo5d/jP9ve2ZvES7SYFAptXMYHfrjd3dX0W/iACAPZPMcB1mgp4NaUOuH88KgmwMv1nOeHOUTR+mz6rLRMAoIK6YOXcZeD2wAAwDLgkMoHIAkjwb5L7gaYMFgqCd9UGAIjZdswg2UBiAPAhFSamfWkAFm/EGi7KHflJAKC/HJHwMwAxDfzpOwDgJ2cAcIoBgLtZvyMAKFLsnZ1t1JP6BgAQff+RSAYTgAmpSp+KxVaTAgAoAT01SAAMJgDJpO0/eWoAMqkFmBZiH8Y7mpTSZAkvsc5vYIM9Pa3LAADAy9fAI2NvD/j0/Z0bQJoxDd8GL42/3dgCTLnamLM2t9b1seW2YACMAJa1UAMG8LI2rXhDL93426+/+fd/4Hzz9ds458HxTRkvIwCUFqsrC0gB6q4D13Pa1LIA19vCKQMAgBbAz9iNe1Z9Rwf//UdqP2pYxABc61+YA3yxNikAQIiEeWuYwP3j61VZUVzTeI+TPnZgllgZ7A22AufB/rEhwOMAWAw4z6kAoRkMCHCcMB+aSdQASabLWQoBMktLBlYIC97mQEQAFG/mLULDo6NeIUCQAG81aC+oeiGAXxGkDwD/Ze/6fps6z7Boc2LnnJJlwcInJEXDOERVoZHcpnNSNSK2eiBWEit4qqeoWOo0X2SVqqJc7GIVF0jOTbngwjLaFVez5rayerHtalVlaRL/QLBTU2hTnBFDfhATYlHqsPd53+8cO1tRucykHMcguOAkPrzP97y/nkfbB4A9WgP4/c8zgM7/BgCt6DxVbr17FFEcUgBw0AYA//SJI5ICAAD8BACD4SNK8GvX7D9O/8Nibddy/M9wyYoHgMYH2Bb0vVFzQZ3+mmmOdh/v7pOCoKE4yQ3d/h/nfmOcAAARiXiM4zCecnES0em6ZDEByFg5SsmDhcTI8EiBpwsu5+LcBhjmIkAmIws3hzRFALSSuU7Rf71+HRhQXzd3AQAIwO3oStTiMoKV/+tVdb/OSxL/qcQVLjnGE8MXptDIe7eQSIyk6AUGEGfCEVv6pW6LiDs2nDjxR/W+rUc79a3jSVMhgAYJR4Kt+bNnRRmc1cEo+k/OnPSrXgAwQDUDDqs64FFe7Rucn+/t75/xEwD0qjLNZC+2L/q7JpVzIBCgy/YR6jogcjBNBBDRNMUA9N0pgK0K4nQB9gFgTzMA28n+uRjAwq4SFW8SO+d/kwF0EQBgnc8v86Z3fYGAfxrneY9M/sqXGv9R7f+ZlvOfM1kWAkQD4PvQJ0F8a+8nNRHWXtDNt3dqdH376LiuOee+MXpD57KkWxjAmVBkheLfiucL6aAKx2A2B5ZOb2s2S2H41gWKwpFENsiNtYt5yv5RAUAOMLwUaWEA0Bei+L/+448/1pkF1Dd0GwDc4XHpAUajK1Y0mpH7yQ0v560E1wTOX0jD0zMXT6USgB5GHNwbc4FoO0TGlsZsBtBixQ3NY3106yl+3lp5Zz3JuY+umS//lvXBhQIMMAC8oSQ/WiDALgWeOMxbQcgB7vpeBwD4evFMvMwA7g75WIUJDED5BhECCAMABhxob3NkFksCAu5nAoAjCgYAKIo/6D4A7MnLYQBAAPOZDMCOf3r+RTXcDf/bEtpgHo+j9g8A4OMffEBUvaa5DzDZE/D6ebm35yeO/x5p/mOCvRUCvNyywhLg+MA1HHa/SxqGyRU4s/tfT7Zr0Oguf/NIZ6lMvPT1dbO44DAAQoAxSPLl0lMqGl3BbB7HP9cFrDzO4WwCU0Ejidw56a1n5xgBOA2IUviPjR/UuAmoaTf66o16/YcHq6sPHtfr9caWWWLZ0LaOUoBdOiMT0Uo0+uWlKbFVB6l4t2Bxro8GRB63uDqHG8bV7VwX88MEAcOUomSiYzcVA2j6gYjmsaG/87RWFhOSWu1hUuMGiGbCIsx19XXlEE5JwGDAe8x7ktOAGZ4LVBNBpxgBuBCIKiAzgBmMAXoHKSubJICexJQG0TQsB3dxGiAAMKlMHA60tyCAYgEOACy2pgAfOyyAAaCoLdJrHwD+jxnA57sAQKyv+VXi89/TrtT+gQDq/Md1wusN09c0b5swGlBAh22VOmf+Rx3/p9TUX686/0EABsP/HnyNGEDozCccTe9zAmCaN5Ivf/AEpyHbctV2RhdUTVJf3zLt/ASTwGdCSyvRTLqTh2dRM7+W5xodZf9EASzi/cGpHKfhqBBmgxyywUJcMYDMCrYBxl/SKP6ZADxsXP+hymaB5VsPQAGKHZobvskL3ggKDjcnKtGxnMIaYMDlwqyFFqRAAOcZWXQj6GvOvl2WUwD6niyUAGJHTdv5eEH5rxDebdVq4kvCCLCehOUAy4PiX/zSpgAEAgGRBgUGzPhbNwNkIJgFAlAFCM/P+/vRmCWE9XOfFsJAXm8vhjaUbQgBABsI8KM90N6KAJIDtDKASzIK3BL9dH3GDEATBvD+vi/AHmYA2vMwAEWEOfrp+XMVCP53hxyXz65DTvx3+TB1Gg6Epynt5/iHrJfXd0Tx/13rP71c/bfPf79AgFQAz549M/5aAbHyockKwMQBjnP8CwBUN8uPdB6aW9CM7kf2JIBxchyrwBUCgCn1U3VmJfxn+SuTmcMYcDrVbMbnTsuYfZYnAQkBLAwDhw64GQDcbr3eeMx2oAjE8mqj8RCLQgAA4/BttBzHJiYqE3+87FLhfzH/J0smEPBOcAbg4gyAb5lnZHK50udBAOJWJkYEIHbXbBofqwKg3l0uV+WuBADl2tMNXcMctpurAJ2XBmEShjogAcAxogDHOAtowQAkAadUHZA7AT7//HxYAQA9lF6fzx/mLSGf7R3KFOAgdAIYAbqU3ZFtttBkAIvCAC7tZgD49TeQBCvS6b8ICEj+fR8A9noK8HMMwAYAzVbMhpYoA4Bt8jvUjP+hoV5Rog7IqYSCXtgvZf8j/zv9j+PfiX8uZAeQAAxgBXicdQBdnyYXJP71j55sbyP+KRg3q5ubq30dkDMhDtC3IxvoJQwC8RRAdGUCzJt+jGCOyf+sDQFWASXAXCI1Io241HBm7gpP6rnSF9AHjGdWZBDI00Y5gLtjcaOx9i2cwWEFTsH4oLFlLJY0GGgZvkgo9H0kFqtMVCrRrCDARSsKmLEZQCI3xRlASvEBumfuLUac03mUHi0rBoHySVE6QNVf1q6J6tdrzfgnANjeSXaU4IOo/4XTmnlxCGIA4MVArgMgD3iTh4LelDoA6oACAYQB9Fnjs4eEEF3haRFg7pHlQGUe+uqrQ+JsTn8Wu8C2pv9Baw3Arf96FwOwKQAAgFcBF7XSvjXY3uwCfNUyCGR++MxBoFYAKPHhr7GUIPxvX3AsPkUa2Hb97e+Z5sDHfMo06wFz2i8v5v8n1AgQKtWt9T8pAQIA0AD8PvQ3F5sB6NwCMJKfdTIAgAFU723S9XDRwylAUd95WYfJVknTeRQ4QkdytJJ6iw/k01fmbAbAWQAWAdNziZSaxUkNJ4ZnL3CvwHUux1NBRMojsbDmgSWau814uLZMoPOt7QtevV8fXdQwDNimHUQP8LtYbIkoQHSlwOw+eLpgYQQJGIColx7ArL2HgGN/TloTfDsL+0dLYy8KAOh9GwoAFop91XtVOwGg7KNW297Sv2aa43kPN/qSPqYBJgDhwDGMBKMQIKXA5kjQCcc5RGgAay9iG4DXA/zT3unpHlEJFOcgBoDJfoEDAQA4BbQ5QoAKAIQBvC0MQILfSQNeIQCg838RGJD8Yt8deC8ygK9aGcDzAQA9enT/Jf9vZwBwPP7U+e9Y/rIjzRGx/HXKfk3ln9al/5b4x9uLkuFAiI7/yJl/ygyAxh6feveTJ6gAVlc373H4b1br2GaGv6e+s2UWBQDujkMJYGIJZblMlpsIFNdRBQFxVQIsxM8n1DTOsArJTldn0JW1AAAoyy3NGB4eBGzT63eqZccdkH5ffrxuKADoGAADGItNLE0sVayVP0xJ0pGmpENWjygDwBRQMC/Rn+K9LSsWAAAgAElEQVS7Dsfn0jLTD4uCFQKAiVDJEADY2FDCK5qxdUtlHeAdFP+17aejX+OBdehf4JO5NhgSBqDWggMBv80BnF7AiZnDYh+ImqtjG8KK/8qdiVkc64PZFAAMoJ85wFCXMgx1OEBH0woFDIAA4CObATgU4ONXmAEUkQSU9gFgjwKArAOX3M9kAM05AAGAplI2EoD2F6AJaFt8DnW1AEB/81KLvxz6R1vof09z9n/X+U8XDwGdZd3rEPcAPkXpS9c18/NOAoDq/bW1xtp9BoDNx+4Ot1QBdx6ZBjt8GpMQ57sdoxMZdYAr54LSBJiN8hBwImNxD5DjcYSzAAr/uXz29Dmu1KUoJbcyFQj2HxEA8HRsrC3fKjvWgMQEVu9s6QIAHcYxyPPBcqQSq1RWMrk0ly3pxJ+zZA8hwXtH6VmZ/mPeMZvL8rc1VbAyUXoRAFQGdalomusbOosAG25zp8xepKuPG421TRCA7e0tow1PwuAc4Cq0ks4ql0C+TgakDDDjqIScUiTApgBHlXGQz7YOVa6BohM6pDRCh8RQkP6GJQJ3IYD7JxgAhX4rBCAFQPjT2538x59/tQ8AexYAwAA8z3AGAgC0OwDApX/O/j0dYgX8YhMA+ruc+GfTMOX657Nnf5qHvyhXS/g7xb+WS4YAQxGuw19GT+0d7MTqN4xffEAAcO/O8p0799cajTsAgOVuFjQhDlN/rBs8nlB8KTT+XeQ2IjIaBQKkp1ywFDlX4Nng+Gz+HHqAs+fPQxqAISCRZ6JAx/QVEHJrxZqgnPzmIc0DAuApPlyulsvKIVhowHJdV/uAxuEI3Y4ygCVBnFxW/q3/sHf+MU3mdxwP0Afa59HO3XXyqMTskDJvckeCkqDER5ScQUC6gDuZWZn+wXZzZGfDMDPZ7b+6ZFsGfzQ1WbIlu+Sa4OWaW2L23/4w849lf0OpHkoYNFJaKJWWSpFzn/fn+32ePj293b/8QaMmKvJo5fP6vD+/sbhDRvzIDEBx8Coif3DoskgCut0dJBP4ZiHxxlery87Z3KqqYeBBixtpVgArL168IAIkGQAvVVwPd8b/MsiXgrtkJbDTJAAFAQ1vsQZoEplAngsoLQtulJeDeC8QrrKL28GtF8WPQgIIBeDlRAAAUI4Ap70P4G9WCMAMkInAtz1ajGuAsdjM8D/+vAuAHQkAlxUCDN/4GgBUVVsSgHEB+Y/mOACgggHgFSe+W60EgDz5LcS/nPw9cPCrzl8O/9uaf+hrtrYJAQDOXHRd4Nt93e/T3+sXBhbjTWvqJ4NbW88SeDEBUmYSAOOzaj5dJwCguI53S5fsI4P0BT8M9bfRi2R5kJsAMAbQN8k9+kP+kwgEJvpF/a59kn5/iex/CTH9f10K98BTBJA2ASBes+STM3GxLETxklR5ghDAt7joW1pamuiItLtF8bE/CgBEUYx4PzrEzyPsBLgMCFEQDbP/hwIYWGzUedBG0/MZFUfPVC2eQQogiw6E7e3t/6QeAwDP3ohjAbLTcZWTAN8TdYBm1gAneDcAFwNtbcGHxIYQbggS68K/fVBEAfXi9B+cfat5QVwSoNU6KizXBFfK/bA8AWUpgBIALOvnH3EcVJYBdgGwQwHwdzsAXn8c9CO1yjYOjM17HpH+9/Ap8Mo9pr1LBVDSA9YS4DL7t6/9k5O/7P6FAqjFycqGFk5OnxP7ucUicB3F8ekp9XMSAFnYfzFf2JYaIPfQo0wjBMgnV3UuUsxMtZztfoIQwMdZgHAwEuroIwIM1pB/Pzk0ijGAyCjP6KAZNzrRQUQgjdA/ESQ84J5v2Ef272vSRJk0XreZnbPbP0mAZCKnMgAczj3nmDfzUnCElybPREJ9ov8gMkRGP8HR+s/xvCH/qdH7oE0b1EaQnhfm48Hz9Me9GHbWplSjyADA0MMqSh0r28VCLk//3pUEALCVU10zM4oj/gE+7Z+4F0gsBpAa4C2+AdQkioFNQgNg0YLUAKULwrwYTE5siP9D6ADZDCAjOPrPNE8Gcy4QMqDaZc8BXAMAfmL5fwkBBsAMpwF2AbBjAeBxmSHA68+Dux+UAOBxCOuH95cBQEXFHsv8GQBoJrVSADb7LyPAAfvuH7P2L+yfT4KiAeB4FwNg4Mk9fJF/OuyEaSjGAzcEwEI2b2jG6vPtlZVENpt/6OT9GWpuOaeLORWtEUX8L3p7yR6XfIvnw+HxUDsI4D6DXn9ZA5T7OoKo/7UNwvyjYRhk2LcU9i1CAXg1J98GUVbTybnHZQR4PJctyE4AV7xZCg7CDT0On2L8DIX4eAdDiPm5OwAPxDOjITkmEJpEkUCkAHy4Hlyh8mIjfbVoMABUTVtPZhMrxWLO0NRMYWU79RgAyOsAgEv71MwCSgA0d7awBkAeoIk3hdpHgxpLGkA0BIhEoFdKAC8nAVjzCwXgFeKANMDeKnkz2EKAy54DuFamAEwEvO3kDAAxIKYAALv2tvPqgDYAKK8HQM0DrarSUgAujv3J93uk/VdV7bHyffUcA9gygK+J/0v+fz99QZr9/+z+yfGT++eldZgBpgiAN3N3/7OG74Fyt0/syMbWVjKRyBYNpY5MYrWwkqKfOGQScH25oMcAAAeJciz1gku+B5dMr2ikv48Q0OE/eXIIFhjiGX16YTFQG7n//onAEMz//Hky/zAiAN8FB5qekCHNJ5Oz5QJg+VFyLRPDxnyHQ9l/lgEgBIB83hnSHNjiT1Y/iWzfnVF+3CmEA3h13A8gOhACgAUH1oJjvlnPWQBQc8mFlc1CBkNCaqa4spIEAL4chvR2xu/ivfljFw8js2piAnTKfoAm0RfMBDAXhNh2BEkFYNMAXjMWYATs81rpgb1yF7IlAipfVQC/u1Ru/7/5DgAww3WAmV0A7FAAqK7/rwDcdgBUIx2O3h9BAPh/AMBrRfysAC5a/r+09+tV/Q9/VN77w82otaxgWQBIAFxAH6D7rs4Ti9q1ra0NigDSOcVjGB5FzTxPLSQ25QINbTW5aQAA5JMrzuHqplAA9+SangkAoO36yZNsjxNkjz2wyKGIe3CwrS8Svcx6PCyD8oH5gcUmTa4aMTaTy7OzZQpg9vFyOqdhTNhR7TxGCuALFB2WiDdL/LxwNASsuNvGTvk5BRjBnWB6HrcEutsnsKQ0SgpApgAGBhavqFMxTDbohaK59UDNZ1NreSPuUKYMz/Q6KZ6NrY2tl3ocANAYAHdwMQX9wCQDmrnx4oRIBQoFIFsCsRwACBDFQB4MOHhYlAJ5RXh9qWojLgUAAPViWLjVuhhoiQCHLQegf1LqA7AR4KcKKwDRCfiv3+8CYAcC4LNpZwkAH71WAXxgVwCW/Vdb9r/XKvhZCsBy/9L2rbZfW+ffIVv8f0WK/9oWYf+daAHuut3NvXHdOAf6syMxMa+ALiACwNqR6vdyq4ZhaPrzhYWFVdkAnEmnMxo2dTkczpZejNf2wrnKPV2B4HgfmeT4KT/K7+3RQGBEECBE8UAoehnuP8hzAojiSZLPz1+kzxZTtCkdEcDcbHkE8PhRsqDHnWIg6PhZUwGYjwsGohEQp2b81BhWD7VNis2AY6BP+0SPP8ACQCiA8HniTe8+NRabmp6KGZsFTD2qOgGgkE3kDKdnuu7It+jfW1hZeEYK4JkRI/t3xU/zotQ/nBME6GICmEuCW5ioggG2fiBuC+Y4zBrLOiy2hMPf1z81z4UQAbyWOji2FzfRJAIYAg5LAChOAYBXFMCPNDJ/kQOIDf97FwA7HgCffxMAPPTNsn5p/1UlAHjrRQ3Aay4AL638KG/9PXSo0Wb/pgBoMM2fAABvdg7XbwYGuAr44zpF7CxACiBLor/udHFtM1dnGMrw80QiJzYCxOrW0kgCsE8+TC51Hj4ZalxYZI+fCND3w1PjqAhGRnsCIz3+HkJAR03ffWzzpo/hPkFUAcPz5JHP4Qw5jiByBMAAsImA2UfLaxkkCemtie8fAAB8vfM+0/5xF2i8n4hzXfj8joC4EDJZQ8EGPTjg5z3lo2FMECMFsHhhSovFNHVKXV2zAJDZzOY1l8dYLW4W8+v6OgNgY+MNzUkAeFjJZYB7716wCMB5wM4TpX6AWpQCuR/gnUPvHJKJwAONOBTcKKXZQXs0UG9qAAbA03pIgNZj4kCQCYCKygrHjDkLCAD8VgLgkp0AvxadwKwA9F0A7EgAfGx8IwBuaLYqgGj+EwCgrwO+BGoG/KwAzAJAvc3++TzVAZ4NICff3GJu/JbmbwkAUcPGh7EAkADoxi2wq3XyYMZLACCbzB/5ci2VSOXJJ5JeTuTjYghYXUsXBAAqHce6fb298733FjmtB4PEte7xvg+P9tzBbs5Jcb2bNEBw4geTQ0HpjaEAYP8+1PT2o6sQY7l1iADmRBvwIysL8GiWeCPrAMe6CTe+xd7e0lZQfl6/u39kEv6/JiKOhB293hcaG6HfC+BKIZ55Hg2KiAAaSABomqrouXReAkBdzxYMh8fIbKYTidT284zIAm68x/UHh0fUAbvKAAAJIIoBtS0NaAquLaUBeO6KCNBy/HZzc2ejxWdBgKdCBcg0wD6ZxKFfEGeDxV1EgQAGAAUA9M7P6HclAC7ZiwAAQEy0AewCYIfa/3c//qvTTAJ8DQDcNzTZCGQTAJUl+9/zpi0E2Mfd5FbzH9yL2fJzoOHmTVyxvn3zdkPZ4p8r0v8LBdDJCqBZlAEvYElON0aBrhoAgKHU/ZIBkF7Pp1OJhVQqZ3iqFaNYVOJ8xlsvZjcNChYIABWOZvKsZFYwxyi+CwKM3To6jtRGiH/G30cCAb9fAiAoBIDwyN3fB1g0LUYWmZybXZ77igKgGKCoKyLkiLf4BubpeT7L/PG8Wz0TRJwINxhF2P57Rm6N9fDL3yNOlYR5amiAgHNRi2HloaIWEjmdc4DqcH7NcHnqjEKWIp3Udmr9RWoZADjN9QcTAO9i8qGkAEr9QPSeWtVAa0kYhQANt2+jb6hRApoBgL5AKwhgCcDHQ/gX3pS3AkoAcM2ICgARQALgV5esLqD/sXd+r22eVxxH1o9K7+skJhZIiZNAEtsDByaQGnIxptUWCVLsEtSgEsI6lkAJhawgjAyiuRilFma5SMHF0EFHVtalazIxWHqxXnWwP8F+ZQsZX2i+cF7Jvx3HbrLtfM95nvd9nWTs1gM/ryxHjoMcWefzfM85zzlHKQDimcQAglb8+wMA7EsFcKLmKoBH/0UB+FwF4Oz/eA/4vQDgjeN8l64BkLP/nm7fx/Js/pVUpZLce/JfAoBeAcCFQAnkAZEIfAcKIM2tyxkAT5fWWsu7zSYfBdogAhjLOye4TjESJ4d5wwiGowGff+7UJU7l7bF/YcCnn3721r1h5zHdOB+IQ/skADgRMEW2/M9eYgn55KaZ3m2RByAKoK4ZQI/qS6vLqN4JRzvCfSOk5OFwkElXlQAo0yqUy/d+8tZnf/zZvbK7QB72AQCdj0h2gDepWQsAmLFO2A4A4tsbZjSdXm41GQDN7WcuAEh4qHIgAkAOABgCAJQG4KqAZIzdAM4JICag2wNkxio4Otx/Rtm/xAPOeHICnBN0kgTnus+pkU9qMjoBAASA/VsOAF46B0AAYP8fH787AMC+XF8etfRJIGkz+WoW4KbptgRz9n8xfwwDFgCcUS6AzgCIAHDsn95zGgC0MnusP6bsXwjA+5cIgGxODgK9wwqAj76l0x/+8MP60trOxo4CwIuVaDQa3zwbhrcejW+tLW7RnhwJdfj9A5f5iA025CpdxeEqWeRtmB8ZZqkkf9AIeI9HhskQIVEAI1cGD1k1DCEIGhurLfIAniw0lPHzfYMePSGtDgBEQr5Alv+d4wAUxf4nyhMTE5OTkxOT9Mfyr/iGH0C5AEWEHcZZcIwcN2sIAZjGRrO5EZfSpxmcNYoaW4sCAHvnmb0kAIjsBYDjAjABVBAApdj0AtPrmREXK6a6BCbGeJA4fkf9rg/gegFyJFhCg5gj3HVOjwnVBIggCwEFAH3PAPjEKQdWH18ZUgqAb5n5/qAWaD8qgD+cNV0F8PC1CuCm6SYBAmL9SP/7eFIuegC6h377zr8kANRhHwCg3wHAGACQV1V/3uSfmD/ewZXKUKWSu3yVrOLqIMcACAAcA7ipANAGABab7RcbaKJvnGB9EDU215rttBWNBjr8A3PXxR6nYP7D8PhL0ORl72JLJAIUb4sT8ItR4oBSAFeuc2XezMz0zPZiawGroRRAXSuAemtnBSWBUQLAqSnH/qvsALD9a/PnawIQeFkCjBIDLtHTZQM11AEaVny72Vw2ZBxo2rDov7ZCvLNtAkB78bm9sP50/ekFkwFw5FUAvKkQIK9o7+lYMpOtZBM4X0kA6JVkAAGgwuOBju2tD1BbvpIADAAQoa+rW5wA7Qb4/QEogBr3+6rFH36sALAnCPB7I2hxKZAVNNN/PQDAfgTA5x4AxL95GQD88EMXAJEAH/71+Tp9MimbASDmz3H/844AcOyfzT/fk4fbqVbSLfqT7J+K/8vuT1eK7H+okhuE/Y8MIgbwc60A0AyQXIDtti0AaD+T6KDcGRtrTfIBovSD+gb8566qtH5xnHb/aokAUHJMv+DFAIKBKg5Q1ArgUq6DR5DRWl5FEpAVgCcK2KBVXyKxPo1Zfh3+QGrcowCUA0AWr6wfd2VNAICnyBoA80o/YMHRVwsHyQMgh8O27RXVEBgdj8PGJgSAAOBFuw4AnJxFQ9LA0VuSBYAH4B4HdAlwGrXBqUq2kkrSa60IcF0AkEQi8JjCs3bUVPGWFAiqIcJnENzpVhJACNDZGZC2QBLiZwA80Lu/9AUgAMRF/uM6AMA+BcDJ/w2Aaa8CYOcf8t/XqUYBdyvjFwXgHgHQ9s8Tgq/ne5KOAoh5Cv9iHu9f5gDR2zdF1l/JjQEAIyODSAPeOmKF+UQuAeDpk7VWmwAAAtgEAO6jrdpPr5ClbMeRBvSRBOiVoN5otTjM1k+6v8S2ry9ljLdFA7BuZwEw9QH5Dn2kLQQA2y0RAAgC1FkD0H0D7YHqjcXdlZlplgCht3kO6ZQyf2aN7P68BALlSY0AlgDDRSAATzeViUREb8Q3m/bOCdURjFsep3cXYf6kd2wCwDp6AhxlAEQu8ryEx1kJAbj9wd9UpcEE19NJZFQqiRhqLDOiARgAKUiAHh4LrCc59/TvORp4xgkLdDlzgg9h/GunAIAVgALAzV8/8CgAdga+iLMCwHeYJ/58AID9uD7/znBiAPGvXusC/DIYcmMADACS/53O/q8BwFbvKgAQYC8AelMpFQLIe33/pOP9J5UASCSyBIChIQIACYCRQRwEunbSxJGTdPovBICFtZbNAKCr/dwMpk3dGNxaoS/byybtjT7fgG9gkCyySiZZLJWqZP6EALH7gtIAhXJJW+NtCHKo8nHVNChmKfs3IAAaexRAXSuA+bp0BahFQyFfuGdcI6CofY2JCS3/AQECAj3phNYdeD5ao+xydAMA6ABk7Nr27sy0mnOCIseV1aYDgHYb/RD/HcJpx1DkBp8pfjyExgk6BiAaQDsBSLymchWRAIkMRwIJAPhFJHr7j/GvAf2aZPUc90oAnt6kAUAa4JATB+jsjDgegBmMPyIFAAA47YBYAXxhBPUMOfPIAQD25frtd3FXAdx4rQK4dT/iUQCwft78Hfvv6pPtn98onh4AAIBYPy7sMPlkJYUH3s3fEQAZcQD4zUsbWm6ocpkVwJXBr5FEu2CwAjAfEQDqa61VDQD7+QysRo8rMHYhAQwCAOIUc6dYjVenqkQALNn4JwvlyUKhMFHQKOBYYFH2ZJ0MHAtEa0He/0kALC00FhocA6g7QQC2/wYaA62YtXAU4iiQGJYAYFX5GloATDgSoEy3ghIeJdg/fYyCGflgKMwRx/gGmfq2OyFsOm0sL9ouAOz1en39X/zb8HEtwOF37+YwwiSHNaQ1QEY0AL+6idxYrpIhBYBSAQZAZqwCDRDLZxgJ3EGICeCeCSQAcFjwuAYAt3x13IBIkAQAewCWFb+jAOBpB0DXeYkBWBY6GB8AYH8C4FsPAH56+HUK4F0XAKQAfBz888MN1GOAdNU/FICuAuYYgDJ/VgB8CjWWovt8XrL+MfH/1fHfjBMBYAXAPoAA4GpVeoJzDCD+DfoBrrVaAACv50bQTJPfLAgwkC+3l2fnIgGkKuaSRQ7JFasCgEJJiX9CAO5w0+kAxoA+nTs+1aUcgOn4xurak/kFBQCJANQVAICAVnM7XQvXIpFQR2AupwhQLHG8YbIszr8woOxepDxYkJSGIQBGp8YfB6JRhADIW961280tbg0oNwUAGwBoLtqt9fr8+tYshnX5Zx9iNMDH2Rw6J0ggkADwI9f+ORXYmxmDBECVdSKBGcI9/b2caMnE8knVtJXLh0kJaK8fAHj7uCZA3/lXCAAASM9/yzIeAAB33LEAogDuawVAALj45YH978f1m2/jUQcAFw6/TgFcOxv2KACxfsf/RxfQPnWElN4pziFABkC/sv+8AKA3k8rA/vNu9O9l8xf7T6SGKoSAIamvHfkIRfWP3ucOGOYNAcCCrQGwFQ8iWG5yqVBwZosAsLhtBiI4C+T3zWVpT6+OkwIgBBTUmixMyifcsB+X2CBxFZUCKB6bDikApHebS2LsSgGQ+dNCFhBfayw1VzetWi0aQSrQf3n4PTJ/bOzkAhSw4U964gCTeGoVfxAklarF0dHR8WpXtCOKribh2U2Y+iYXIaXlmlleRQqg2Xzxgv7D8wDAjdmOubk5v8Xjwb7OigOQ4r5AKdEAzmnA08le8vjHhkgBZEgBxGKcBtCJvz0ntWV2oPQJAsdlggMIICPCuhEHUG4A+SvIAc6ygX/iAcAdpzXwfVO7ANYBAP4PAGBcfJ0AeOPwyT0A0Pav5wB3d+mqfyd/5JwCOuYp/OnvSVWymev53usZeodymYqbAMxoD0ABIJXFyDva1pAIvItJ2P94X1oXn0USfKnVaLILQOsZAwAldLRXBs1NnJhbXcbpBpLIft/A38ioq8UqJEDhT8ruPZ8KDgLoQ1xyxPB6zBA8gOkZy9yyFxfm4QFw1F+t+bpSAPTlVnP1pIWseCTkDwzcRZEPVol1hmv6bPxy4W9KCgHFUpEAdSboDyEGEJw90rZJASybkvVUNU47EAB280WbvB48fePknA8AwEHAa2/8/ccMAFRQpbIyIMAbBaA1dnksAegmkqoxgEr9idHLpUe2nPoPe1cb2tZ5hZF05VxdSY5JBJLldKyKrDFpIJBq8qsCW6TEH53RHI/WKYyOeqMujI1U14SGkXSbOhDsT36N0qHCQqcWRAfaigmlq9bf+yVLsrHQDyGKPvwlyzH2WLxzzvu+914p3n77h6/8JRJyY1vneZ/znHOeo0n/475RPirko5VhHAJQCXA4ZDL8hQeWAd7lAKATAPxsAADPy3++AIBzCQBfaAAgK9dfu3QGAxi+IZuNACBOf7EHeEL3/fNpAqBoAxrVfT/G3HGgAEA0UYDSBICI26j/xbmERdOA0elpdRKFQKoDKjJRAKwDPq02NzuCAfQAAGJAAZiZZumg2YAgIaMOGf63QVNQBQSA8z+XzDIA0DjAyiMe/0mWCSABoBxg9nejpaEhGSWAonJwXG+KYN+qbmpXVWMFrUYDkgBCALNlI6jeY9rebJLdZ+D8x9SDkg9MSCD8cwhPo8WMeQgZgAx40wYIuFxC6+WYbHW5Yi7r8glJAO3/tBv1fbh399QF4Q8Zzs3XhgEAvmQMIEoioIECCBLwUiRMfQBLAABsKIghgDAIHuVerd/RUAB3uCMD4DMCXh+zCg+NaBQAAKBs5ZbfJesHv3j48A8aAxCFQA0A7FbP3y4A4Fxebz3RAMBqv/zjsxjApZcrJh0A9PB3XiUCoAEAvk6MHsCDFIC0AJSa4inqS+M6oFEB5PEPRxi9lKem0WRjfvJ9VAFfsNvK2OxLKmCz2hQAcOCx2hWFK+bWypUO+YUdMAQwBUMbljVItKkKkF1cIQhYWVmBdyMFSKISgC36dHS/7SubzJiRQ/xfP253qlvs+BcMgMGAYAC1WrPe6CmIADa4IdzvHus6AkQhBPg9gYB2/C9yDGAJAADAr3LeksVEAOCy72D4t7djZTIik2PowHpt+aiBBKC9DeCG9uDdZyVkABamAV7KTwkGMDWFTgrf40IgUQAxFeR+EfctUxvAUsDAAFj0e7XZYM0t+FvfuHfUy12DJib4zlAOAcgAKszuD5IA10/YXpDb928bGMD3cTUgA4CS54s/XgDAuQSAv+sAULz284EyAHv2uNQHAFgHFvR/AAC8RgVAC38dAQJjbgCASDRMttXxMC8BDoY/bQSBJABSAJywXfia2YLbKE95Ez0xW7WWAQCU3V2FF83KseNWByjA8S6Oy8pmSzBkkgp40iazySyEP4b+Ip3+K4s6BtzDcJzlB/daaMhhktBpHL356pgAbBnjf3Mg/lu1/cbejoLOGNJGMAj3mwUIIIkPSw48/DkEiNSDhz/iTX7C6gAAkCD+rbvHEP3b9aMi3N5lpd0LQAEQAJABtPcb+6hCdHsVzACCdtwLMPxDFYuAqP8DEPRTgJfifDToRWoBIgBwY0UwEBgduGgsGDnAqCb9CwYAz2ldyAhxAEYBAADg+C+zLp/MAxoGvN1PAX4mi/i3l5efXADAuWwE+u4/dV/wYuyNMxsBPrUbAcDpdBoTgJGrEz7d+Hd8cBDYeP4n/IlIKhUZi6upVBzOpPSqGo/QMgst/Cl9hZfvFPkBL1Aj0PxcbphEAOaEfe0UAGCzVW0QArQBAIrLhye7vBgoe46qzQ5QgCMPkmjZ7AiGLLI3t4gpQJJnARD6+GHxEUsJqDYA5/UsMIXZ5NuJDZPDNIQEILYOkddoDhKAPgSo4pBgq1E/3lkvQ1ZsM1mCloovj1V+ajsSCccjTXsU9yQBEBhAwUP/lQYAACAASURBVCRnGAGA+D8hAlA/FBMaMfJgFABQbzRoO9DpFZIATK53EBp/PTUzMz2DBQD8IkrdQDoFEErAD/Dwh2dL/pSawmpMPO7XUID2hXnZzjYmA3qxA9jLN4hgCiAoQIiNBaAGQCkAJgGZh8AAPrjTXwW4/7oQACAFWH5y4Qh2PhnAVzoDsK6/cyYD+MwAABIv/vE14LQXtB8ABhIAEfzYbhaNhNPpeCKuqmo0Eg+vrq5GU2lV9P+x+GfXDPmBowAAADC/+iNaDUbTALKCOUC3VW3WBQCse046R7g2BCDAqvQ2CQD2Dj12K2TlFmcwFJJChRwEHXGAFRaB+CmrIwAryEFIFkbgW7RAAlAGRuE53BMVACb6Pw8AEP9buCKgfrKrlEvlCmYdIcniv4spBVGAewOxr4c/PtbGy2aHgycAsSM45T9s/6ZxULHp4R9zeTAFgG+2AwQAru6zCoS/ZLLdoPUjX09NUhHw1tTMwtwkZwDcIlgXAgAC/EuRVNS/hD1AY4EE/BbCY36DYSirDRgGAwkA2LNxQQFGeFOwo1yplFgVsGx/AbeDv3tH5AB8MdDrmgRQvPAEPfcA8L9XAxkBwDbE2b9Ti38CAGH8r5//2iggt/6Bt0Q04VbV+FgEGYAfGMB7q1E1nYr0Z//0QAKAEAAUYH7+lQVaDfSYXAGt9hu4GLDWrLH5OBQBPcedvV07rQ0p2q9s1po4JXB8uIxt9LLJ6QiFghuvFnIrK1ksBWZ5OVA//rkan0zeXRvfsMCLewingIvALPbq+3oFoD/+NzksbKE96FZrr32y68GamM1kghxJChbypPPfQ3lRCI3aDRd5CXDNa5MyTgQcoPw2pUdiP8T69YrEJQBSAT0nxHcaHSIALAOQJJPyGZMAECtngALMzC2kJ1kOoFMA3R8Igj0+HV5auqUiAAAOqOFARKAEg4kEVwS4DKjVBn3MJvRVLQtwWlgXAE37IgA8IAC4r8sAZAikM4ALS8BzmgP8VWcAsueXZzKAz/sYwFUt/Nn5zwCAO3/2G4HR5m9h/Z0Y84fHEikVUwA4e9xuf3o1HY8iF9Crf5wBIACokzNp6gOYf2UuiwDwuYd8gcvK6dPu02qztc8A4NATAwbQ6eH47Pr6ekk53Wx16vud9vGhB2fmJZPD4UQICBXy2Ww2ycqBWUIA4AT4zq98YcJsQYVjqFwuFcslT6/dhojb6ssAus+JANVaCxsC6+2THUCAcgXuCP9KcCM4ms8tUq/xIkMACnst+JNZOP0lKZOBYAJklV1DykEdKwCQA5zEcAMLDjgpO5eRAxxj1bPeYQrA5um1DYtks5mVn5IlKNZKFyZnpqbnFogBGBAgHje0BAMAhNWoH1OA+NiYH34Lbq+bFwv45e6jAN9qAOBlOwLZ0lAAfqcAADzjy8pHyAB+e+e2LgPiV4+1TmA7GgJdBNv5BIA/8U5A9Hb85mwAUHQAsDmuGuk/ZwDc+5cBgNfIAMZENzCaAMUDgWjUjxoAVaVVAIAwvBgjehMwIwAGBkAAMP8eumu/gTVnOxwmvX8DBWju77MJuZNdBIDGCZufXy8tP+u2mnhYAgLE7Bto2GlxOICXB23SRCGfE+1AFPsMAvABh7EF0M3pyFgkYP9WW2W9t92u0xbQqiAAW12CgK5RA4A/JoBo1rdPdkqViq0iEwRAImAb0e+XZGf/ImtHSubya6OOspRxwMMsuWw2KajstNv/guP/Q+wDlBgkrx9u3bS6rDukdyABwD6k7qECCYA8VLmCk0DDf8HAn1wABgCfF2a4CmjkABHC2Ljb706ptyAFgJ/5UiBOAODXGIABAMgeiKic8Arx0aoAYgBcBrRY+d5fLPJ/hNvBPyEAMJQCPlasHAGKaAh0EWznEwDsmi+4/JwtMHYGDl/6ZgAAWPuPWANKACCcv32+PgZACQDO/sNbAhPQKGT/ibCqpqPuSDy9ugpfpdEojE2xRcUVnsatHkgAIPzhmsOBQOwGRn8+JQYUoIuLgREA2sc7Mc9hp9E5YBY6xeVet1aDYOnUt48Pd+04M4sQ4ISIdEqyNBIo5PM5VAOywAOAEWRzEIwJn6kiZbC6lTEjz4D4jx1ub/P4r7ZqLN616O/y+K/SA1lCtYb7SnuxUgWrDzYsP4ScZmkj5C2s5e+iAokaZDKXw9sVPp5w2SH3zzgzDrNNhod5w37QFlfjoCRR/Nt73c0dq6tI08AQ/x1WgLxZCQIBsHg+pd/Rl5MY+AwA0guCAYhKAAR4GH/I8KbSTzviT8GPPDEGH9VowM3/iuAKYnEwZwABQQH4ikAG+SECANYGQH5/b77/4MGDT5gGINIAtAMoM0NAAAD7P966CLZzCQD/1xVUAIDlv+xdz28b1xEGJdEhd2VJjdSSkpgAtWwXdhIIEKumFy8gCy4kgoZg0Ehd+1DkoKKnIodCOsRolaBQgArovQXSqkWKBgl6ixOgQA9J8ydIJENQ4IHgYcklueEPb0jBbuebeW93abfoVQc9UhJIUVr+2Pnmm3kz84V2AWbD/n8VEBDy+aMyYAwAbPwQ/llMH+AMTN8hFNjZX1lJ7769u3twQIFA7oCuO+Es4CZ8GsyfAeDH2c/5eSTjUM2g0Py00ylpAKj2LaNFtjHcFiGN5HSpVHGqDiEAcemWUZyAhU2MjSMQuDg5ViwWL1y8cmn+6p07X3xx58/zl1bHiyasn3jt4fhYHMm/aN5seWL/dQz+sMniK3UbbbhYhD+KApS4PbAiMOAQAvTbBg/s9w8YiceK8a9eYdGN93nc5isThlEskvVPTk5GRGBnbixu9SX+BwcYpIoCACmn5LYpAvBq1RogzZYUIAhAfGIMKRuKAA6yWYxNAQDQ25UFAKggQHGA9AHWDt79HQ0Alxf3AQjSfS1XsLCELxvKFGDBv3VFkgCrqhZg9mIEcilcBkgA8Nd3997Z8xkABwC03jcLghBQbP/7OQCcUQBIxf73SCDpDXgrlAOIX5xRCCDxP+cAgpryZ/y/r/zFELC+vy8AgNNxnQCAFu7Z5/k/GwEBwDjQzc2bm2u5LQUBWZQoTd1i2RwzqSlAjQFg0La2KQZwWkpJI/m0c2ITAPBvm72UKYqm3BvAexhk5THsKBAUgB5EJg8x7WZynPf+8qgmMK3eoNGsihZg/cS2yeBtx+mcPuZ1enra0ZSgJAIB6A6uE+loNrvHJkblqwNen7x+/fo4EfZYschvMzESVFNCYgeH43mCE/Fod1j1CUBjCFbGBKBS7lsUAbiobaK4hlsROjfwecTHzBsMz5+vZcEADtY2UTe1uSnVgBuhrYD0QUaZPxjAOgBgJ7HIMKyqLjQJWF4JfD5KAVg9AGC+cEWSAEFPEACgqMb9bH/07t5bew99AFA8AACQZwg4ylvnAHBWAWBajQVGCPDR/weAyRll/7OrWgk4iPnn/XRgKAJYRAhw//L9OxgJsJ++vJhIb+wvJxIr+yACyzvYBgh7f+lpwXkMbcDc2lp260e5D3UaEAKh2z1QAM4CgDD3kskuuXyZpE8xQJ/cNTlM2SVoDLvH+ZgytRi69jHQDvan5ttHDiMsdBMXCaBoIX983B269H9PtP07RADKBDGw/FP+dvq4U5KhgAwBdoWpQMV2m42G1zIgTiS1wTJB5QIOoCWWcaHFzc2oXJiLEd1wQ/Zf7SeZAMStQcVtpVKW51T59SgCYHJUEzG+xIfzw0+yAIA1MAAZCSTXUBqAACCTgbnvM/VSAMAV2ekVhoB1YQEEAFd94XDEAPP+TVEOvR0gQEQqgaPw7tsfIwTQAPBQcwAAgI4BUn853wQ4mwDwwVIhDo6MTafnJoIIAPxiLqQNyACg03+iAxjU/c0vhEuA9Baglv5GEfC+DKeUTScOO9PpUPpfI4CUtfNY8ExmTToCX+CpIJAIN5kCcBCA6hhQAI8pgGkcEwC8+bhUcmAwDc4Sul7XOorNsYHD387BNbPSNYtczsmSSojoXN60up7rVquO2DYhQK1M1m7X3Ioyfl4IAsq2LZXBrlMSqbA69usJAogF0HsKWcECO33WVheBdV10Ab0x7FPmraW+6zZCq9o1+MkWW47Ts6atLuoaKABwmACUb+UnMO+k+DoTgD+tbQEAKPgn+1fiQBs6D6BDgAxPZJeBLOuX4ftX6DPh6WwYFLauOACFAKpCmNsCBQAEAjQDuK0RIIL2J3p9qARMfowQ4O6DuwEHwFoiACjwRkHUXDpvBTij64N/5NVpGY0l35z6bzmA8ESQ+PgMEgCzMzMqISQAoGL++VExkDAA8PxPOi+XteHrDqBw/Y+4/7Q6i29iLgitTC6LfgDej/gqbxIFSN4gACCibzsYlVPrb1ttz3H6BvcFGtOgByDN0kFD12F3GhttqLWNahgQkfOope9C513+2Gz3hvQHbq3O2T4QADTgl+o113UeYxifWsgGVhynLAAw9MVCHC7l87rTMVYq4DFFjANRbfhctGxy2dKRaVit/qDaGFlQG+IUYN/tpqZTrQFnAGpOpVw6KZf6Bg8DvG5qAkAAsMtJwI0AAXRToORWyf9zdyUhQHpjPYEQbP0+tgR20gkuAbqfULswiavK56MlcOHSvL45rzQDV/XHPjtGDIAhgCKm5N+IAfzu7jM5gAeHPMWNo4Q/njcDnlUG8PtHpvZLc8ate1Mj5i8AcO8wdiEeAoCZmSADgBVQ/vmFkS4gtQkgE4DVECDV+xMeAbisMlZBAMBrnyUvN7knOJv7hCnArSKyAIQATwUBKkCAqttKWttdd2DlzeNjM5/8d6dTZwDgLAA71WH/dTLJqHb2eLW+QcLxEy+ImsftrjdgG3TKftuv2yxxVrFWc211r2wEdE4c160AJEqOV/H1QuwaH/JJvzUdM/MI/AvR0SWjS2LoYWr3vMDxC1zRc03yX8Ssftdamm5zBrBWs5FxKJeeWlHIkUbiL93DZ/PhwdYW2X82l82I+d8coQCqsCrcILi+skxcAJ6fXL4SC5E2LfQLSpOg1gqb93uGtFiQDwEEAEAAaVf+JXqBHowygIfXDhEHRTkMSD46bwU4swBg+MTUHO0HnlIM4N5LxTAAsP0jAzCrtMB1BlCHAIEI4KJCAK3/Ecz/DiYALIf3/0Len68CAGu53FbmV3hGXxoxUADTTCEI6FTsuuPWGrVBO9nebj1tibb29lOKAWD/NRdTQ6W2pkoY0FtKkUmKpp0vis5nMC1rqecNlQu2/bbfk86wgdJCzB4gDuDY9YrqBazbrssAQKbveHYgGERgIR19OKCFf10sQkNHH69QKEL/i3x/z+PHKYwS6+ecBqNELNVut19s9/nYcP+4lG4ZRFkK8YjBfUD3iAC8neVtgAy/ZUEQkNY7AWpEWNAfKB/Fq5e1OstrLBfkzwX2dQJelpnh8woABAJuKwS4wCGAQoD33tnbe+/Bg9EI4Np4gRMheEDy0Xkl8BkFgD98ZlyYUCGAefjGC88xAGTfnwEA9v+zq4oAXAmS/lef2wII2X8g/htMABgtAEwr80c0e5P9PzcEc1NQjrMAUzdMQoAjM2pyENCp1+sO+eHasL1NlyUTHXzRZI9+R3GzC8NBKqApHrZahbxmq51MJpX2dlKW0W71+sOBZuBOJdT13/Gq3F5YdQlPsBxCAcQebkNu2fQcbM8JKYYRX3CZeZA1P/F6rTYZuz6ULIsOqNCm2RjQl+twtw/HArWWwS8jZtET63rc8kBPif1/p8ezAmMTxffvcRtADvJnu+AAGbZ/DQHpcDlAWvdYqrLABMsFBnJh93WvZggBeCNAY4ICAKEAggAXogVt3VHuBn4P9h+CgIffjrB2qDCAz87rgM42ADACoB/4OQaAiSD5AAAiEgKS/fM3ZgCBy/dLAIIqwPta/I/lP8MSILoAePlZ/39TQ8CGdAUCAbYynAX49VER7aVHMaMPBCjZFZsRYECG3W5LHt94kX7DSQCyUBvuW0EAg0Cj+cTr97C6fPmm7z1pNvwwfMT8sXoNpyYEAMFGleyeTHbQwE+6RYeuOV9/7blaK4AuJyWBAO3Zm0+eeOqQWH1vyAMNG+oRMH/bdiUEQE7TEiJjtbrfeJzDgP+H/Zc7Tw2VwjB+yjUAu1tv0wUEIJcR/x/KAygK8D1NAdYVA0h8N5F4lRgArR9o2fDF18T8v0NXhQAvLyxc9UcHKclgKQgEAigAAALkD3+OVoBroxTg4c8mNABEC8lPzwHgjALAbz81fQCIRkfaAac0BXjTfBYAVhkBVkMMgOv+r4YJgE4B3gnEfwMCEKL/y89Yv2jdyw8FAIgBmAJMvfBxMo7ak2jc4jRAqU5cHP54MPCGXXGd0STFBxUwAPpyymXBCDFGNjKuq61yjqCqLFFbv817+uGWn25DHkj2L7n6QYPtf8AcgEAACNAXACirrxPsECga0GwEB33ugI1BcwDzrzgi/IEIAPLGR0dHRmvAecxGtWb79p+SFMKc8RHejKl/ggBs7aIHILcjwKlTgXorMFwSRBDwfWEAPI/NpwBaNlhHAd/SGwGaE2gGINJvzAImwgCwRwDwm2sw/1AtwE9iCgAKxAD+9R/2zu+16fWO4xibND9cFc3W1FZhpyaHA+dMsCvuxkArlqaUE1wOKnZ2O2NlKxuHScAcSLcpbLlYD7sajA3cdBx3PE5EL8ZgG3hxdrE/QNsuJHwvShiJsU3TxCwp2j2fX8/zfKvsOhd5vm1NajXafj+v5/358Xw+vTKAbgXAFxoAfm/QPg00MNDPUcB7QZ+ksgIeqv+zEBB1K4A9WUCeAI6zf3UHUPsA4Emd+Ruzdn/4kFMfEjMJkQATf+jnVCBsgoE1CgPknaIDBAAh3QhCH0/lAzR3XtSV/eNFdfxOpVy1k22cHuBdGN1wZYgV6vlpA8AhAABLIDugLiAAIeBZDSt01GqKAiAJQM2DHWbA82dvXPKiuKrr3N4AQgCIsWCjSqSCmQRAlGJ+d9QfRucgNIoDge7OKPvPzkIFcCqVmJ4WclpxwLfJ/N+2zgZhf6B3B0kCsPm/hy7AHh/g+NGYhAbEBaCCYJAAAap0wEatN29cv37js3fcUcClj+FIM3yFwnXkcQ8AXbp++ZgAEMDRIPZpoAEdBLgfQQDAVwV8VP9rcgAIALb32F4BoFMAlv/vagC+N/MPVm8vPBU0gb1BZzPv46zSCIXVfaFzdazMh+SbsiBlTK1I2A8ACJ6GxqEl1AC1Mp/aUQapIFDSUsDahWE3572/UNxDgHoDGnGW2u12DcuO2PwRAbV2q9ns1EpbpUZZKwDNAXiDV1wXZ0DMHhbrjbLjEABqogDWS5sUyXhK0X/1X4P9H67dY30+FAD+IDYDvpBJTqkrmQEBkEpManJKHIALAo0ToBuF0sxQHM922TDgvRh5AboeWAAwFJORweMsAg4FVjUAgrdvwFGAd9D+TS7w9kpAXADv7x/1ANC9AOhjAPjDEeswwMDAgOQBHyIA0P4DfUfY9Nn8x6NRy+l/UxIQagDU/g+X1QJYC4CT7uy/Fv+8ZrAvoBkQAE5AHzrCfcFGvQ4d+gvKtJ0ybM2b/jBW8sehaxCav7p0Py+0TwdgUcUAgfIPIKQHZkglNgW2YAi3aQB0WtVS59zBw6MbzXaNeUFRgFrzWPzp081WaavVrJv9vyDWj2cF8RWrVYxJQtQQHRN80UoF2olVDABotZ96FQC8qzAOTH1lsQz5P+xFcmZtHxYt+BfuDXAEUK1scha6pqQSigAJdp/cqQDrdLCeGzz41VOgAdxOgNsHOD4ELgB/Tho+iwg45DcAgKMACABbASwt3VQAIA/gyUr8US8J0KXre4+8ukAtHLmvATCgAdDf/08AgKwjbP6sAKL/TwGYGgBUAGYCqNUCzJX8M/t/gubcJJS8ncU7PDk1lfoTpr5OBxUBwjgMvI5zOpQpVYpVOEXH83Qir3ZevKjWyMxFArBBUnC/6HpeNOa61wXI51svS42Dh0fi8fhGZ/1ZW0TDersRfxLfHFloljrbuxA44KNBliug3BNRBWDrtHjKYIU+IR7AungATcjzPfGGDuMA9LJSCNSTsN5Yg87B6rcioxcAy5/Mkv1DGCCbTE3M0LIJoL63X5NiAA0A0x5gkCSA+AHG3EUC6LGhQzIukOw/On5o1Q0AOAqwJwagALDKSYBQrxK4iwHg1wDwR/RpINz6hQDfjfQZAHzJlv84Ccg0/4lJEYBVBigVACdwPLU7ACjbv3v3zxkAJBKpTHI2C3c4qN3sb+Af9q2DVNEXDwcVAWBij9pNC8qLLrWoaVA8AuNDyjXyAaoCgDx39rJXwbVzkwSghLvRAO3nygHoNDdGnm4qAjxXT2H/72zHIZPfanVa26/qfCzI/oscaCQA7YIUncDU9QPXAuvH7kasAarbIQTA2kYNAFAhF6Dg1JshDxUuQ+MmCIYsTl1UAED7TyZnoYEaMGBicnL6DRrgpAUACwEnxP4pFxAb/sqwjvsNHT86rGWBAEAgcMQGwD1wAT6Ym5tzMeDICtRAIQGCvUrg7gXAH28ZBRC8I7XAFAAYuITPfxgP2ACQbDB7ANGjYv7nY7okyEQApAZg8NTrDcBd8X8R/wm6cP/HX2lCGBLgwftAgI+CgXDYr7bksLeZhz21UqYege0RqrUJHdzdeZEvsRNQsCWAyPwC++lGtQsMSADYCKhCN85qu7mxsAHVAkiA1sam8gnAg+i0dilJDwqgIFFA6BDADAAIFMX2i68DwPYASu2RVawDXsMeAFvwBRWFuHoz6GEALDzEH9A/lCRKovzHw8CwSDRZXsDek8FCAGoSinmAEyfsagBM3Zo4oKkO0ENfUAJEFQD8BgB/ZgDYCmBp7tYa1QHBeeG/9QDQtQD49HBAK4DgmUuc+kcCfAMIAONBR/xaAvgPaBdgnG8GqfsRBRAbspKAXAS0ZwLAWasJqIn+k/lrBBAG1EcMAwIDssnPITfR/zDSh3X88bC/kYf9v6yENcTqt9eouA86h2ItUNWEAdlEJUpvb/r8Kz8RBWAYUMZ0f7XWamw3W62XnU7rvxvbLTR/rAbEIn2LANIwmBkgAIDegYArkf8aAFUtALaaITyXtBrCCsAyAqBSUfbfB6eXPD4PtQHpv6scADwGhP3ADAAmJ91xABoT4EbA13ly+KDEAe16IM79awCIAtAIQAocMADwBj9TAPjVHCkAiQMsfdm3yiGAXiVwV+cBPz23JkFAfwjGzRsAgACApxdG12wAWCtqFACM/ZQ20xIBgLHgrhrAN+z/evuf5u1/z1K39QQVA4IfkLnLgUAf9cv1eRu7RTATx4GhgE32AYLoA3AeoAQSQHIB7KhLtq6g0/duBUAMEATUnSql+9afv2zRapcgsKfsv4wmT+bPDCjYCsAyf7Z9p4IAcMpwgQegACA1CVvba+jerMU7oAfKDgKg3oyEYf/3+A4EP8Ry7U8yygHAGkCEwAROB7YJYESAu0WYFQegYgCXBoi5CHDcVAjSwGDJBEQRAFLoG/o5FQLOvVYGwDFA78Jfe5XAXQuA355Z0QDw3uLRIBICJAVw4ZgBQGC/2/phgByX/Z0fHh5yxQBZ/7tnAEoN8Jir/Jeif4lcgt4nbftnAiQVAaYWsz9FNt2LeOgYry80upuHXRQL9jsRru4fIR/AlQlk69QMKJikvYkIsCnnRQJIQLBMAMDSnGdYFwDR/Fq1wlpCBEChUDCDxBwMBBaIAAV8LwgBlPUDBMQDoLetGjoxEAOEuoAtyhLg/g/zxz0HAje/bwUAMAOQSWWEADYArHIA+2ywCwCDfCjghM4GxvSxAPhBiiiIxY6+5Y4C7GcAIG9/IoWAoABYAix9vCKFwL2pAF0NgN/9JeQRAqzCsEkDgEvgBFAFvk8TYJ+1/9MwYK34zw+7UwCQAeAJgKd4QNXZsWnsRTU9ZkUBjfNvLD+ThY5h2czssrq3kxll+8r6F9Pp9AMMBA7ciexDDeD1heKv8rBNwjiAGg/V9IZgegBt27VSlaxemylfvPXnxQtgOcAxAPUgX7TKAot4IkD76lgahNu/FWIU6xcFAFPF0fodB63f0e+kAsC+LQFQWt9qoQBQANiGVyhj1jLfDP3bF1Cs8+zvO/IddAA+n5q/ePGisv9MMpPNLi5OgRuQgocpdJ1cbsCYLgiw+y5go3CJBEpJkLF4DAMMX5ZjAkddLkA06kEA+AEAK7e+TYWArP/xbW7pjgbAk15T8K4uBfx70INNauCIXPAjGwD9l1ABYCmgBoBHysGirACiuu6fAWBaAYEDMEjz58H8z+awNx21qBvLYZPKTGaZxX9OrD+n3mayi+puhg/J2ZnUfHpe3eRo/79IP/gmEODSh8H9cKgfEoKRVh02ShgK2OBEYPD0zs4LRySAQ/ocjdts1i4WiAaQT7AbQF2BCAKVqqugd71WdUTuk/kzZWRsKDIA2oYrCYATRIoVyP5xDtAhJwAWnjRCApS3VwgAEQgBKHApVyGv9v8+aCsS2OfZ9zP86dy9OD+vviOL2fn5dPqK+q6kUxOpxfTV9NWrWR0/mcxpNyC3nOG1DFDFXmynlBSQgqB3dTLAHQaAZk4WAN7SLsC4B2MAAIDV0LHrPyYAuBTA7ZCUASkF8Lh3FKB7AfBFUCuAgJQCSgpAEQAAcD/i0QDwjVMmmMwf+oAPif0jAIz9SwCABwAPjqkdKrt8DW7BrLoL4QZWm9fi4rJx/nNa+SvjX8TfVX8GDB/u97S6xZkASgWf9u6HQKA3Ho9HmrtF6BBWwkJ6au+xu7NT1wU/ecvY8/nC65eVBgCjx08RGIAFRZ4IDtVGfCxg/VmpTPs8b/t5O9mgR4ej/SMBKvhAkQCM3yEfwLEFgPqnbtXiJKpX4nAQYAuKB3YboTAcq/GGwx7/D3D//3X6ylUw9ivpK2T+P0pnlrNpXFnKnpAMyE3mMMAC33ha9EgBYPrsWWzOotOBnlz47AAAIABJREFUuiDosk7+D0ESxwLAf4wP4KMgIBRlBk8rASCVwKIAPli6GUInAQEQ6RUCdnEa4F8GALoUUEcASAE8XNinARCWWhC6Fd4iF2BYuwDWMUBxAYgAJzN4A167hnehwsD/2Lu+1zayK4yNlOhHNjEbgUVsQ2srgfRFYGFiKDaVjIU9NuuqCo3Jxl5SapYhZomYRtOglIVlo4dOofuU0kIgXcguiV2TvvRlXzaQh/4BjqyIEfNQQrERaeI6LotB6vlx7507cvLuB48V+UfCspbmfPc753znOxzcFdPO6dy/TImsweGP7LbCgW/Pi1tccoBPh8I9uE4LmwHxofYOuoS+/EECQHLt4OBgmyeCkAJw7LuN92JAV0FAcARCAH/Qd6f12p8abFJ4+1V/V4cADnzaGOAhAeA9op4rVUAU/hIAiP5j1/9tPMoZzIeAZ292ms3t9lAct4SinWFv/DdUAf1DaRUXD84BCHD4wxfwWi3TqzM/qxqoYjRgZmaWY74iXnZ4duwM2YDy8uB+VQgc4GaAHAogN3d6awUDUHrA6FZYlAAisetfCAD4WOsE3LlfEwBQ24wfA8BRBoDva+8BAJ8BPEv2hOQwQLSPYl+e/8QAxPq/QkFrAQoJgF/+q/Lxk5mqEgBkHAIAhAAV+eoBDEAQALOSy5kY/tmsDTiwgQhwj+UAnw7FezEHQA4QSUy0X795s936T114fEyjcZ9gAC9bKuYbjSAWuPoXboOPfcULFAmQsIBJewsoRWvHxfyePjTaH4h/XigknjD2XRn/CgLgP7azjfwf47/1ZnuozgAQG2y/br3+of12GlIcXt2WCMW+pO7Mnzbw/Lcs0zLtCh3/ZgX4ADzjd7YEUsypqjmeqKLQh3QLAaBcLWMKkElPpWfSU+zO2N+vSYKoEMBVgEJBcgCxLFA1AqIRMjjZCm9FYmQKfueiFv3YEDirACAcP/YEPsIpwI/+lpDDAFtRKQWk/N9nAJ/FXoTENGA00Xde8P+x4TG6JdT5Xxi4EPABCLQAU2mnjCbgcOM5AAXOaBWj2/YBQB3/+GyY4lp2ZnJ5yyRzULzrMRO4a26M4//lLy/FQ8LVZxIi5MzQq/++mpQGXMlnpwUFwA9PtfVUg889jAXIABqBckCz6/IVPJTdc/y/i/pjsDc9/jeuIAOeHv70UAQA47+10w5Lk6JaeHAwEXoRraOhMYZaaCv+O4r/jx4trS4tLWFRxKjmIOYrjgMAYJXMsmNKBiAxgIuBzAAcKrjYmVQKP2NDoJoRi0OlKNDXBA4IBlDAhwIAZACEAH0Y+xGy/IokH5MlqM8AGAUe1BUDiJ35+hgAji4CfP0gqhhA7GGAAYwLALiWkHYA8C/PChY4TIsA0TwaI75ADOCC3wPQNADEAPrTThXyzmo6DQBQqZQRADAlMBkA6OQ3Zo0yhb9gABWqEMzml03UuTIAWNY9QIBHbFZ2PYbm+pPk6keNzLoy+ko+BgDQOoF+0DdU0GuFQK0aqP5CMX+/RuhLeHDWr/kODPBk+DMEyMWinvqZvGQJQDQAWttv3L14VM7PoVUzSoLIyDSS6K094FHt8afWKjIAQIB8tjwLoY/VFEySCABKXWhazSkGAMFfJO6PW1mrwAAy+DTqNwSVJlglAYWURABaEzD87/PDTPv6mJVEaBhwLQAATAEuX+zZUgwgOX0sBDzKAKArgS6dDrQBF4UQYCSiTO2jH7AgdHhM1ACHRQswCACQAhR0DfBUf8YuZ9LVMhw9CACGYgCV4D1LIKAxAEMBgENJ7j283e+aT7lB+TAZZVvfRBS7glHf6jM5cuP0wX5LUICWXwWQn5jvaxRANAE54KVcqKHXAODUVwzAa76XAXj+H58BdOUA20QEWq1t0Vp82djZ6QzWFQAAGtPEwyS6gyZOxO/fEPFfWl2ygAFYy3mzaCAAAPPHKmlJAoAh1ROzuTJxAD8FAOLlIABABgD0X3g0H6YAqhUI7yAiALy552hdsNICnBX7JNHsOPbtF2QJGrjYD0gAwMqxEPAoX3++XgsJKXCkJpRAfgmA4+xSvVfkAKHoqfOq/Mcc4IKK/4JvBl4gAJDxjwdN2naqVccRAFCWAKAYQNmQwS8YAF2WkTNMBgAbVQAW9wLvXvmK5YrrsTBu0UD6grbfmtVv8glQAFfMAyAF0LR9+vnvS36DlP8Q/efZXnlRcHuy0dd1/nO9L1gP7GYAHpUAZGvR2/Uab+NRpa/DX4i4P3KARPIhSzR/8ag0t7q0itV/80p+PltG8k8XMAAHXqBVkxSBUhWIvVXFAOx5bMJU0ylgADMCABQDOEQBkANcZQZQoBSAkwCu+3ywRSaSWATc2iQh4MWPL+oJAPsBcRfgWAh4xAEAjcEloRNKIKECUEWA63EfAHpE/I/JFEAlAAAAigAUWASgOYFO4RIw25hCALArswAAFckADNn8K/PNSwBgcREwm8viMwBAke50ygGQA3zFA0ufPIipoE/o7tvJicUDoAD/ktZgDV/jLynAoU4ANftcfVyAtUBqZjDAAMTh3gwU+zDCsSHgI4Cn8f9gDoA+ATwF0Nrfdd3p2ouIcNLmYsAkFjcSoVp4fZHrf49u3wYAKAEBsCAFyAMolkT4w4WdwJLJUwEGYaroBMzKFqCN9X+jCp8MLAJmkAGwU5sOAL4aSKQAxAACfYBTXAKkDea+EFArA1z+bc23BF357lgHdISvv3wXC8mMLhJXSqBFPwVAJVCvKgL0Eve/L6IfN0hqACA1Afi9XwKcok0AuJyOqk/lQwwAAh8IAHKAMnwgBJiWYAALxjx2twAB5uVpx81A6+lH1BW79vB5DA5JLAVMYsdM2e/HfkUUoLsKoEDAVQ/VH+gITZAy9wsKhUmYg6NHkgHIJMDz236MANudXbVB3K8Bul6AAZBRCBMA92B3tx2OhrQlAonJBO0xqCUnPidIhvifuz03V1otAQRYy8vW3fmsXbIEBJQs2yxZc6YhL78OOFvJEwLk6YGge8WmpYFpUQSksYD+QA5ADCCVEgigGAATgPM9ogYQkZ7AX2oMALsAd/4al4ZgtWMh4NG+fv+PpA8AQgmktQGFJ5BaDxg9McalYCYA5xgA6EoVfDNQVQJURqCjVafsCACwK7nRGWQAkA2Ytsz/Kf5xjx38UdoVOzsPGFEEAHBICWCyGghPvVs/Y+fCTybCsThFDKYBcvtOeGXt9MEiVwFIDxws+bsBBMB8oNH435l2Q80Kd2UB1OsjCx/BAORhro52/XTv7LUbba+hiH8X9+eL4v8lEwAAgD3saeC6rXB8Myw2lsEvNvGMR7Mw/m9B/GMlNF/J487UbLaogaJdARgwDeEMAq9mWY4GOE4REgBMAoCF5XKQCWRoQ4jIAEZZC9B/qA8A72iKOgED5zQKAG9+rw8AcbIE/ZYAwMcA1gEhndkMb67889fHAHCklUAKAKQnkCgCLuJDCAHEbkvgAGNSAKAAoKADwMCAQAS/B0ATQKMZW/SfEADKuLa+XMVBAFWyBghgBKALF4M69JmdgfEqzi8UhSDoLtztpW/G2brk5tqlyeRKMplcWVlJbor9O7EzN4ACeKwFahEFCAoAXIUCDA17gz3tRvOdF7mJ0fY/YgDbO57I7pviUA+y+0ZncHB68lWnoRiAVgbQCIAcL3AP9nc7I3UGgPDzQbFGIDZ5ae3muBjO/GajhOFv5ufFFDC+HtmS4P+WVZ6hpqAhZoORUgkKMKOuDNkCZlAFNCW8GUf9PkC/bhCGDICKgCoF8IsAYyfEYhWsAZIl6J1A+BMARPmWqoXjse+Pu4BHGQD+XvMZQOyxBAAqAC6SEujkyc/RjkIAQLRPAwBcBSREQKlCv2IAmBLoGQDpTdKoRgMASFcZADLGLM0B6gRA5AAOhryTlWHPdzt+hRYYxQUSB1sbgACPfs7s+OTiZ0/W19fW1tafrONyXtq/tbIOv8PuS9kIcAONAF29yz/Yi//k1HR7t3G4AsjfkfKfKcC2RzZiGP6epyr8ihM0OtNbvad6Vl55DS3970oAPI5/RIDXQAD217gUE96qxW7eeEa/y7MbizSbjeW/pxT+FgPAfJFXAhcdin96wElvW0sIAFl8/SgHKOe06cBqDgeDaD8AzQTSdLbIAUZ/zMPBV6+mtD4AAkCKqoAU/+e46gsAIA0k0EWKLEHvcArgFwL7auKWAiA+1gEd8T7giYgPABNdDIAB4FoipDYER/tU/Z/i/9wFef4TAPBYgOoB9CsXAAYAAzLPKjD7YjqdwWofa4DLCgLk8e8gAyAIKPofTnEBfUEWFlD0tgEIcKtU+uNPBQQoN9MhMRAEFOAai4EUBdDCX4t9l0R/e5sTI/X64NvOO6v/UhKAS8F2dlzeD0j9QhnP6otm5+2H9eeJsyNnXnWanpb7u8E0gJcXYQ3QO9jf7wwxDm9F4kOL3euZxuH4R/oPl5UnDyAGxWIRawBcBzCA21ulCikmskEKICcDMz4A8NHPHuH9sgsAbD/gDsQ/YwBQUiD40yfHx1E68hgXA14OMoDLFx/UBQOAt2Hk/+xdy2vb2RXGjuRIcmoPzg+s2BK0tkJxKBhkUgdC3GqETfwgqqOodZ0mJAEPSFk0wsjqoBkmi8ZdaGEvsplNcUuTomQw00VnoF0Mw3TRP8CWJWGhRXBBjpI4iR7IAbn3nHNf+jnZa6GjWHnMBCxF57vfedzv+2u7AmhlAPhymP9jQRPQvWCaA9IiwMZOhwAA2+mm9GcMgNKfAYBHOYIJCPD6hRCdHwAgfhkYAN4GhF/Ap1W7/b8yQwTAx2sAnv3i0+7zxeHwSwSmwlN4Mzi6CRvx6xd7qBfAzYyeLvFG4AR0AXqkPDDdCND7fzm1wZ8vvG28OSobmcxw5SinFwL7YgcQtTsK4EXAvnbxd0WoBZALSBhg6e82tibKlbe1YnG3ICsE8wiQ5f8BWQ4926syAHjq4NsYlqWvlDIjpf/DVDQGy/+4CUU6QHNEioKqBPBBCXAj4dMQQBMIUHaBfr9UBuv30vXg1curKBiAZqEMBUQfEAHAwwFgSEHAafpOcUnZ8RT1gPj5LxaCP7HsiMGSdaltDdziY4B/ddvl1Nb1Ow4AWAAIAOhxpyUA2H8k6n/KfwQADzJ+jxgBwBTQK1V/hA5NHGQAxpRZJUgBgAewvgMkGAD7Svqozg3SD3hi/Be0wRLhMIwDNzdjmywxorNrv7qgWZp94aTxlNWY6LvLKQDKg5VM9b8e+d2jXCGfa4xvZRy95Ub+jQSBXI6sR0QUGVgU9w6ek0cY+AOCvD9Rgfz+UWXSsHS7G7k8CgDvS3JwrA1YwtoEEAAJQK+UXdu+pduzi/RnrxMkQEAHDBgAe4L3hqYA+BSOx9l7EqZaCd9AHAaKfWCFANwjjOW/P8kvB8eTcbyj7V0Ul4KwBhD5LxgAlwUZOm0TNYDVnv5MrAFoJODab3dsCgC+be8BtfYY4FuHBACb465eAyAGwMF6yaEA4NSQ7P8NSQYAEIAMYJBrAQyuJmdYDco+dlwFzO+/TMJUmmHtGPcC4xAgBgFJDgPBuDjt5lD5NrEcDgTn4PSPstN/GfIiFYuF2E9rD68qR4Pb7PUgBBgOoADVknQJapoBNGmFwsWfPKveC2XnVtq5PV47yqMgCHh8qeQ/YAlf5+Zg6A4IGACBNqHFg9rbXqthbJcLOZMI+DEM2BUiY+xRrVbfPXHQloU963yk+zNefAzpz3hOLBUNTPEeAHtHAgFQAgwGRAEgIuwLCoFgPgmkPiBAAFYAhMd+vAkIgivgLBpPBgkBRiH98QogtgHpnrAAgAHRBRw6BQCA579hNf5IawA8/Ue0NQABAN+094Bauwv4jdOuxgD3tC6gtgigzQFPKABAI5BBQQCAAQzyEmBwcSy5gof4DEkA+vmXHlwOSF0GVk0ADDIEwKIfFHCDYSDACRx6s2p4kzGAVCoGj1AqFFl/ePEKEYE7MNe042qg647qAqBCeE5od0j2n9Mu80Ktf/jKuWVPd0+8rdRLr/eeoQkw2oBCuj+jtEeLsAPuEwhC4S9e1Ou1stvV2Ws4X9X4wmBBUoDjDGBfyBXtwQjg3X8Me5bclyzOO5T7F65cfPiLtRCe/ZtRALvwg9nZ2ShMAqAECgADSIgeAN0PZF/ImmbgsTLD71Y3UwDBx0CeAfM/CflPMcbHAPNEAVAzEBnAGTkFAAg4JUoAqy298SeuB6T1AEZoDUAAwH/bciAt3QP48XdLAgB2QHRaWwRYgCBJEAUAnWfNAOCBBmD/PAIAZT97eFHrD4tOPZQ4JS8C4Mbq9Mf8HiAYAalJIJz+8SCeeHEoAdgnPBAMoPLNJkIAZD9CQCgVSUXW1tZ+eZIkzDrx4qJhdD9iL6IqBwHFD1UASs6rkCtWXFvZjmw245os1+p4TB88I1/AZ0D6n1P+P39e1zw+DyuTLsO10bX9qlLM70vx34IaEzQFIwCCAhQZAajeTmctliwILjnGkcpcWF+LRCIhmf+M7kSXb2Ab8AHLf8YFAAB8gebzfzmKAJAUDEBvA0L+/3RMOQSthkmYBRgABICAn0u5L2oAIBmAagJ0IAEACmCk3fe5MaDeBbjGAYBUg9tqAC2OAP8QDMC2Y1/6Sp8DLizIRQA1Beg6i6cBz38GAJD/qPzpGVQVwCAYgpEcqJg4+5sswfwCAHQxYBgEakF9QOwBwFMinGCcIPwgShDAyoDNGPIABgOhSGRtPbKOHOBed4dhNwABuia+7ul5V9hT20C53eb8N/8e9HsOKn1bts6ObCZjH75Urh3WhQjYwQF5Agu73+f1w1qlUi5PunsNS6clPTFZOYIxgZ79x6YEtAMgAGDvDSMADfRny1rslqyTVH9+z14PBwCW/ptQ6EdvAgA8QP2/OXbU+3A7kjcBiACwH2JiqgCgqQkgLAJH/WMrKyurq9D/4//F7+8nJ7d5BQBEATzAALRVIDSKsuFlxe5x4Qx6XS4Djly/Br5gfFMo7WpPAVt9DjhhUwDwxLwJtECWnBIALMZZ6gfhmTBw5owkAAwAVAVgkgNRtqCjJgZwWTgB8BqgCQKSogsoWoFQFSRAHhjWhFElMLxMtUAKKEDqIabPIxI6ZQBgc9/qWXjHuwAlFAj+wPmv9nb38/lS7a0rbct2nMuyOLfhniyXK5Va7fDwhTjxayzvx93DG4wqZDPwf6Wtw+XGPhmVKQVwMwzIDmBpjyCAFQDV6mQ3fLuAAY7bSACuQPaz/E9h/tPyX2Jqir3sAJ3wc8T0g8umCHMAmNERYLoJAeQUQFsDoEEgFgDzqgaQ00ECAFEEnLfw/AcVyUdyDWCEZz88nU6jZCgAgGOyPQVscQD423BaAIDNeanHxABwKH232yIBwH5eZwAIAJD9EIO8CbAoXME9tAjgpZ0zoQje1AOAGoCnP10IxA+uYgB8EwhjjkcAHgHwC5yaCoSjNA0ABIh8fxW+3Vsuo8uCF4S7tp+wl1I9KHEKUMjtfhgCcly5ax/EuOqVl65MhuV2B+Q4RpexMex++dI93NfbZeF/dg4wIpOxucuNI0Yv8G9j1n8o95EA8Pwv7RWrjAA8Be81G3qvOtD36+TjEEWM5L6m0AUIfYDmxA5gkAAgakIATgCaEEAfBI6O/k+Jg/u93vdcB5zH/F/kAIBzgDNaF3DgvF2UAFZcA7h/n68BKA6wYRUAYGu7grR8fCnmgLCFMowXT9UMAGqAHjAHUgDw0YCcAAycGdAZgGgCUv4vCgDw+oUhQDMA6CWAZACmRqC2C6AlP6R/HHqD4I4HI4HYJtQBqUjoMXc07wBSDcLhjq9P9izk9krEAUoi/XNHJik/jgqaZFepXiu/7JvYymQQCJqj4wSLrD2TSad3escrjSKMC8Vf5dm/K58Kx0eAKv+PJmCzFk5Vi4NGABcimP0slm+GpQVgnJzAgrwwwjADwE1fEwWYmVYQQBRAMwfwqy0goQ5OY0DsBBADIAQQJQCRgI8IAAABjO3r3BaoaRPoExQNpdvMzrYpQMsvAvyz21C3O25pm0CSAfRMpjstchNogNN/xQCo2u/n7nK8DbDYXAfQTmDzFOAynwNKAFiR8ysAgqQPHmLrzQfjLzgHA3w2EICVIAYAUSAAwABYpJACLLit7PtFDjDR+wUrAorCD1w3C5ZX9hUn0GX7iq/B+6sOZN/dBcc8B4IuiQInNtzj5UqjVMir7Je8HywACu+lAYL+l0pvoABwwzVguy1jt9i6aAfg8ac8/6MoiI4eIHFyAowDAiRhJQqpkZgCShzAfonKf3ozaQ9YUAC/sgfp93q8P+v3/AT8QUAe/OdUACwOzksG4JEMYIgzv9OiBQBzAO4LNiIZAHu69gdxUwA8nH9oDwFafRHg3w652m0472ibQKILeFIqAgBXPTGkEEAxgH7FAOZxAZCvnWkuYGOreALBMHoVAp2rWAGwMv2xJAD0SIRNEQjOsdMunJjjy8AcA/BsDONAYDOGo4DQY0yhe85OC8iEsSLAeenX2AYoEQIUcrpqj6kgaBbuLJZKryn2EAYm3X29rh2Hw+Hqw65Ao16H8f++2gcWYn8q8Y9jwC6NJaENAPn/7smSxY6nJSsA/k4EAM7/T2Oz0djsMjgAAAKEkfzwewCJmzdu3MA5II5EYCJCw8DoctDUBJiZ9sWVKwCN+5N0Kcg/6u2Xp74WYhFg/gMM4JRgAHwKeP9zKvwlBfjsL2l5ntj+/F27B9jqiwA/yDGA1Vj63MwAEACeOIUkiN3WKU5/SH9iADzo9PeMrq6iACiPuPyZfQZZ9k+vxsmpgv6UxQoBgGD/0/FZE7PFBdhYaHlZnv20HvAb4MfQBIAuAFGA0FXqAzo6DRvdql16Cm0AuhfMEKBZt+s9Uv7qou9+kdKfPTgQHNQP0RnwtYgSbAMXzHqf+CswAtt9PwGg2IUVoIbDbiHxDLvjEm0zrf+fvet7bfO8wtj9JEtWKof2K7I95yZxSn1lkAhpGPOwTYRjmSmO4zhL6o9kbO2UmoBQJc1oo71IvosK5sB2s0FG1pGNttloLrrBdrEx8icktmQUfGF88SlacJzYJulo9p4f749PdtitDXpl11FLaWXpPO9znnPOcwQByE+nBABkIf6vi1eZyZdwQzKlPc6s885sCahRVh/qBSAGUJa9QOL+LxKEgv0qT1gXwZlxsFAswEgw4LIroBk3Nok/Dk5KFYAZAPUByDqA+G4LSws5rgJekxog64BnDQAIDLWqgHtdBPzxXekIEAoFf/Jlx04VEBwB2tkWWGSqh3UC0AsMgCUABQBwvxfoKBQoMAQQABTKEgAICUaM+38cre7Q9zrniMc7IrPFm/8vefH5TvsgAFfkJYECCL48TQBwA4PovT4gqAFoBxrq/kq8kC1c5gm8e1nbczWxANO6h5x9VjxPxj798J7ACIAMfxwGqPkzf58AWN+hBtZU/K9A/L8MVCxyAgstDl2i7r88JgCpbDblJPlk8hmSPQUYpNOZWQEBE7gyFX59E/KCl8WSYTkSeEoBgAx/bP4FBuAWS+XRQXyH8BvMGsrwlvVLDfCCGhL6jhQB4UtVAYEBQBXwkz/pBIAw4CbPAkIVsDUKtPcZwGcPCNChu6v7ttEJdF6JAD/t1AAQOmqEv8EA4jEqAcaQABRg3h8+XwV+ULiLvB8AAMzpy65L28FKPBGklL9SKqfQoQTbr0pA+rP5HFyDFAgEAA5FiHM9myMImJ6+ksduIAFZQRudAgUCRO51nKdFQQICGh6Lfa9gAdq+R04Fc7w3xEPEP8FA4wnPAtVWmkj+q8V/rgDw8TD+uypVXs9udX9F7b8L8/n8fBZi3JkhhBOvcDqXlklPupiEf8iFkSmyB1BTU1P+ToDxU7SDSRmswGYmF4eyS4V4fDCBb5WbGE24vLAtphlAXFUBFAXo7T0a1gwgcpsB4OKAqQO+uWRLFSDyvVYRYO/XAbtC8k21IyfPdxjjgBIALgUsBQBLx3QGgCLgZKzfBIB+SQASo5IIgB1YuewWRAqQEAwA7EFhNHDMdUcKZYMBMG0FAJBPgA1k0gwAnAanpQxwHdbkzogjgsWZTaXE3fmr6c9/wElAkLxCh8QDEQAZAGwJqOnh/J2xz37eONq3zIsBa3Dr44MZAH1jrNfqK00V/7pfD6izCTD6ANaxJQGgCOP/DVAVrar4pVrdtykB+HVqfj4F3F+8LIh/Ijn5LL1yEAOKJScnAGBY10Un1Iwwg4FWAYkB+BCgiKOYpUwBF7bASYAg6AIAuC4CQLMG0NMj0z6qAobDOAwceV+7AahOgLMDB5SmHOpuOYLufQD47d8XbYkAga4PlApoMIBzt0JVCQCBN00JQAAAFpJisdEYqf+QAmDUc2JJqYACAGAAvJ4GNEABBaWy7/4nBkBTQeWpDCS3SbjzBQCAJI7iP3ymJ9KZVA4AACEAEGAuKxBAJgHnjixatjx9P+pgg0CYCZDWfYZ3r1kXkEl9jfYCbsBZfohmYF6df8BfH2LzcF0X+jjg/Ym/yQi8lYZcLb5B8d8G8S+SACvShZu/O858jqO/BAAIAQgD+Sw0A4HcB5aA4mRzJV/06/iXhQCpAaC9YlGuBcS1TAAAGfiZGCsAXXNBnnXpDYtfQBUAUgDaGgadgJIBiHNQXRYhe+nnUAQ4q2YBqRH4fekwAYyyZQi49wHg079Fgrz5L2BHPpaNAMY8YEf0ZEVtEAscUAkApwBSBaR90oYGUPYdeJpIuCMCAFwCABe0QgKAcQUBYHabzUlf8Bx2wgnqKxhANoVnDu7I+ZRg/dM5DH46zsxsFjjA9PRpDKWrQyFLAJtlW3bwftfVDvAHo4aghhb6duYAhoMnrQgnBNjANh855Ce+yBIEuER9Z62/3qQIEgeg+F+n+N8Q8b/YXsWOIsEBuAUoegMVgBRQGuIAGP+Z6TzwAvHCxYFfwdxcKpUF0EuyAAAgAElEQVRT3UE+DFCtAMwAHEkBMlIFYAAooRirZFrI2cQbAjPBVAhgAGAGIBHgdV4kA7blwWvsBiAfVAUMqKpS+MHdFgDsfRXwr51BBevKF1SJgOhLdTvSxrlqaKnNJADEAGLIAKiPtF/cJZj++yVAekYAUMBJdMz/wap24pQR/ePkAI7KNk6/zGVT14EG51JgiyU+/vPzeZEmZ2EQOCMB4ARxgFQ+LyjAAiUBv8D+RduygnZ7pOtq9Jstb1VyAGNKVzv4G2t8pEawjPEPAzuIAfoQJiyDVTg4hL+6899T0S8e67QHGOIfPADaYAaoGhYQwAIA9wCKV6cRADAgCTDoOI6uiwiERGWEMWDKDwG6FWCk5GQcRlNpxA4NQS6BApdjiowABdAA+mkn4IU49Qj5GcDh15QGEA7c+qXIAD7yxT8WAVRVKWT/ueUIuvdVwH92GwBwZ7d5wCj01kkAsA5rBcAQAUdJProwGTcJQNEoB0IZEEbTi2XcEZ5UDyUADHP7b1l8oIvpYrqEK8RZCc+IABD8F3BBPIAa8B3JGCAAACmASALI3PwOzARQHhDs7GMEWIdL2DOmdP1SoGHwzxUCMAxDDGAmsMGUYGOZ/u2Hu9h97Cr/rXgwWLjO8b8h+D+YrFL8swBwWvUAwwJAh15cUmmBfMxCiGYAGP8sCQ7rHKDk6HYKpAAiF4OWINZmyvRWuXwSg9gRSADAZqGTBAAsAwY1AFRuivj/5NrARd/j7E3IKHnVzKHWXsB9AAB3fyc1gEBTGSAqRYB7tEWcqjtHe7gCgAAQUwxgkvr/+2NxMp7jdn/0nKKPFzT+jY0kS1MljQAzmaS6/gkAynICSLb/ptEGmw/nxaiPzcyYKYDjpLJAAbgdKBr9orOdloYJBLjf9xIRADw41tY887bWXYErPht/in/Pg2o/koHlh8vM/FfQI6wBjUBercntz1wCXJcUwMP4RwLQENixtXEo0gYFAKsiSEDkOPkAfpd7gFEDIBUgacZ/mpqCFQJgU6SJABPonwIUQM0EpxUA4Mb1MkwAclMgNwTRoIZ4/2TdD2i/APO4tAs0U4DDlqWLANoRdEDF/8DFY0vSNNDuvNwqAuyDHOCzPyyxIVXIfnA8yiLAeQkBOA4E5SrpG3KsRzGA3rclAIzGJQDEZFlQzf+oXkBAgLGR8vg4zPSlJQSk/fE/7Ov+l+UvGfz6y3dOIAXIQiUA2gFOUxpzOdJO/9cCBu733Tu/teU9AgRYlwiglH//Zt+aZgfLL/67/gS6gjHcIeIbHj9rrInvF9uejwDUdi8Iiv9eYxXniNeQQ5xctKgAGA5XI0dIeT1zhRsAco58WckmCAAQSKrwT3NrtCEDTBgqIBqDDU8Up8rD4+Wy+CqormDlDjLIIKAdQmkoQLyXtDGkv59SAIaAY2EDAOQo0IAZ/28dUJZh4dYkwL4AgN8ckipgKBDoOif9NaUMAADwASwRlpndwR6VAEgG8G9kAOgMpvaBjTaH/1hCOtSTGzgN/JaHtf0/PhXXl6pxU+O/ef2rez/pi37UAAQA5AkAFs6go/a5k5GgjaM20Lgy9G0UEQDT8PqOLKBpka9qFtoEdyBq/+E5/sYT6ud/vr29vfm8tuIz//RpgTL99+pm/G+9fFypVnHZaihsLd4iJ8Z3F0T8Qwvw3KyjEGA3CpCUHIDaInxJAEIATwuWAQLQbVEuCnNHXDBidBOKArA/CM9sKwQAh/C4pADAACj+e3oOhiyVAkRoFAjDX5KAgYs/bNeNAq2tQPujDvi1UgED9oMPdRlATwNEj1cUACwe6KE5IICAt3UKEJ/s9zGAeJwdQBKDFP40/eOOkVM1uwEqF9BhTQGIASAAyM4/k/2r2p/O/+HhnEAGkAcAIG+QaMd7Rxa5KAUDrPe//GZrwxNxCEJg3YjbXeJfGXnVatuPHz99BpYAYAqAB/747NnTp882X3i1JvpfayIAgAGcADxafUTxf6QC93+1Gq6Ew5U+NmK8gfw/NZfNOoxpM0oEMCDApwFMKBmQIGAnBdAW4bAtHL6kRbj2B5MbQmJqMnhSkAA1LEgpAOV9rxsAEIAiwEdG/MO5+LOQcg22u//V0gD3wfn0H90aAPzrwfQ0QKdmAO29kgL0Kg1gVAKA5v87KMAYUQAOfl38l4E/zvk/EoDiFJiC+hjADCcBTdGvCQA2AwEFWLiy8H2S1S7dWrRCNt1HttX5hUKAtYYy69SmfdwiZPYJwKaf55tP73cuViqVMGmK7W0idruOb7548bxuzv3sWgyE8JcCwOrqww3Q/8PBKjVWCQjo+5gKgH+cBhMQIAApZ8ZkADPNOUA62YQAEgIUAgwra0AOf3BoFQDADGDMYAAGAcD3jWn/BUoBDAZAhd/XQroTEEeBrr2l4x81wN9XwmpcqGUHtF/KAJYGgDvaEUB8v8s5wB21QjAUCB3uUVUAYgCQAcTj5A2sCcBOCkAJAN//p05pAsDhzwYgOyWAdLMC6Of/PgaQRwBYOI041vGhXbH5Axu22jsvb20t19eAi3MxUBv2Gql8TV/m+PfW1zePH7nVztsHbbvvjaeb288f/We9Vvs/yr9PAFxdq4n4/7bvf+xd30+b5xkVGR8Yu3GmzRFORaQJCFquIhmhhEQBSlQL4qhAiOe2FGu7yFIIioM8YyE2VbvxRS3VlsYFm5KpqUKmtFXVSt0mbReVtv4JiU0sIy6qXNjxtpSSSNsF7H1+vL8+Q5ZdWvKHSxILtXXs53znOc/zntMK0wlR/OK7M/QeAe7qfbAAAg8QZACxuh4gZiCA3QPY5Y8AAMeBshIBKCMAc4KIAWQ0A5ASQOiCGRLyNjzsFoAmAcYQIODDIcAfjp6UF1KAmdsbKG2AZXDh+EdNAtAIPcAX3g4NAB8rDcAUAW4GNQNwTkgJ4I6eAlwwGUBISYC2CIAUAMo/MypVgHGL/Ev7r2kStZkATITdHYAbAgaBAQyCbV6KVIBcLj9CHOBGwGnFKYe4d7UeCr6+97xcrT0BJaBS59ldrucENCN4Kv3/dnbOQzfwHwoJKL3E+M+o/1pp+/nzZ04LmBXgCLB1Y4hdgFfRAzAaxfhfwQAG6zCAIGDClAFNEqAwQPcAGK4IYSvsDZYZd3UARg/gIgAsAoYMAEAG0F13EuCXR0+qJgD/GfAoiPA27YAaAwDudhXVIoD3NObRaBHgDJ8GUNahnsLAMdUE9JktAOWDHMQApAg4mlECAM//jbu/YQGmGUDYmANaDGCQbv74LU4qoGwCcvn8OY4KaXOQvQAvbWvxHtl7vlWpgSD3tFI+YISv14F5JXDryT+esC0opANQVgB4C/w/9V8R9b/9M19LWwefrHi0MfQu5QCNCNLCE8BZAICYNQbQDGAihuUfNkeBEy4N4BKW/zSJAFk6EgQW4SgDjrk0AEMC4HKXKqCtATAG6Or2dOAQ4IMrNgOY+fkr8ifADqjpBtIYKuBfClLaCRQ+vEZ5tCocgOPBNtSCZ+GHagtAAsDfiAFM2SJgyGIAaggw6qp/HAIoC2DLALC+AagfASIEwBYAzAFVEyAAIEEbge3Xj/i4fwkICCgM7W6LqsRYzsq+JVvWiZ9yG2C7Qn7g/4bypwsSxw+s/6rB/yu8AAD1v9dTaGshYxXBRwpDN7n+c2gDDiZAuABkigCmBhBTg8DwvgzAOBWE45WsbADgMZphEWBszBwCqPrni5LCe00NoE+1AN9XAOB4fHgSQBX/l/TrW60GAPy9KQE0BAC8/2evets83htc/n6pAdAYQDsHOt/Tq8AWA+id6pVnA7UMSC6ABgSMjpkawLjFAEwMIBMcPv1rgIAxBtASADOAWVgUBATICQRYMxCAPrPoFez4nm1DOvdTUZeVfcvf9QRcldpTjgKgRLCn4AFafnH7zwIg1X+tUhbtf2CDnZVAkfB13aD6P8flH1nkFeC4Vf0xND6RIsBE2FIBbQiYliogmYK8hi0AxQSOSm/AzNg+EoD0BmUJ0GAAvb19fYoBvFL0yM+JJ/ALGAJoAoAM4MqdDV4UCDTdQBpHBfwTjwFweeNriwEICOB0IKkCFp1At5sB6BbALQK6NADYQwMFwJAALxrTP7P6p+sYQL0CSPxfSgBn43hQjhEgv7Y2zAjw055gB1tvCgTo8J3f2xQIANFctRfSd3kqCJz8Ff/H2z+EDb9cA1DDBNBatSzov7corVXBAvgH1zn8O48CQIT2f/GVEAcYNBuBsD0HcOkAyjDMZABZylnDwIUllAAypj1g/z4dgHQIfXuqjgEA4rd55JaPU/jwg19bGiBeBAC0B+hraoCNcn31ewUAgeAn7vOAbAqkAaB4Qq8C2QzAVgG0Cii7APcYUI4BJAQoBLg0rTTACVa+wjGTAegBIOwA0v1fMACAgIXIcipKCCA5wLXTQbbehnXHNt+R3RIiwONvai8l41EOMHoDYIaQeK66tfViIxDk/zWo/8e1ylbp+W5X0IPVjyuArVdP0/5P+xtY/6lIZGEWbUCQAQwa5a8Wnw9mAAYCEARkp9UccElGhS/hKhDOACQCUFJoSPcAXP9TvcYmoGAADAHd5BuDl++81gD1EODkgIcAIOB4mhpgw/QAHw2pFe9AcN1vrALyMrC//aa2DvU4A8fkIqAeA0oGwABgMgCz/M1A0HGLANSVPzGAunMA1hoAsP84jABjsv4XFyKRyHJUIsBlztn8OOiRJx4CgbaNh88EqwcA+KZW/d/HeNAbBMPDCAVKVii4dvxwHQGEnWE4eiDAYnt7J1iA2iAC0Np6dZ2i2NvP3MthCFAkMksMYFCLAPEXUAC3DqA5AJ8HytIkkE4FCwqAi4BmD3DKFAFxBBDSCCA1ADgMBD0AQsCJoj7nJzMBrMtYBG5qgA0EAL/t8SgE8B1/U4sAqAFgNsA7bRsaAA7zFhAAQK/ZAkxJBAgxA6ifAogmwOgBxi0N0HC1QAxQI4CJ8EEMAB6wAiDKhluAWQAAngSsJagLEK/gU69Dy7fYvxaD3+1VCQEeV8sH8X/pDLKpAwQRCDA4vFzXA1QsMKAEUOgyyqXtvX9exXundFcPfurn+l/N0wAAOwDqAbgFsGaBrH9qChCeUNMAeSTY2ASQvkBZmgPiKvCSXAbmlCCXCKBEwF5TBGQAIAow4EinD5cGqK631FEBwQCajsCNcv3ujwVl+FF0risAMJyB/a/7FAVwWvj+f0f7AVxQq8CcCWgcBVJjAFQAjDxAeQrYPALEt3/sAFZcBACpMN/+B5kAQOnjNyh/8VhYFPWvmoBEYpW7gPavh+jIAy6peDq8XbsSASrlrRdAgM4QRwAgp0D+7YEyQIUDAOFfXoLlHy/qp7D70/rokQdCC+nM8kgeASCVgg6AWwCGgBi1Aqr+F1KReJgWI6nwSRyFsODkSjgsHpoD0LEKHRACDID2AEZdY8BT7jGgxQDEW6kZQN9hxQACxUO/4kVgWwLwyFOjjtPV1AAb5Xr/r3Tc1/AEMRkA9gDr2jzY6eg+Zm0C2gxAgEAo1KnCQDQIYBAArgGJz+K41QWYGWDpzzARDy+7AVALwQQCvAEwSPWf/DERAGgBUstgDACjwMQwI4C//b3jQcq1B79gT8D38Bl5dO47DDC8gcubZoYw9QI6TqDuzk+/rxr1X3rm3UDxxIM6xKONrnfbqf7bsf7vYwcgGcBZBWnmPFC8ajAEiofjyWScDZOQGsHkM0LJAIthwxyQlivxPBCOAUaXlAjY3y8zQgwNsJMy3gkB6CyAxQAAAVqKigV6b6MluGsIMENDAPwr9h2/25QAGmUM8JUJAMYysJURrtdA0RLA9gNgDQA/QhfAXgqjQJQ9YD+4f2VoETBjZAGpFiCrTgBNz0UhFBNBYDE5oe/+sdgiGP6IC0SzxSTeHsEnB79mk7PYAtAmQBTXAYEBDA9PSgT4yXoQ9pmg/KGL9Tz8rlbFc30gBNj+3WV97y9JDNhkKNhUX6Vy+YBZAN7/Yfi3BfQ/WAQ3VfivAgnwHr/O9e8/l88DAhAFWI4sqEEAsIAYIMAcZAPEYhCGGhMv7+zCb6LLkQiZJQECxMk4Ccw+xI9oBvCawQBoCkASANoBiHdlTEAyOgKzK2AGbEJOKUeAKb0IBACA9d/3ql4GDVAuqGsIMDNzmxkABIM3NcDGEQG+8LRqAFj36+tN3gTw4zKw2vEY0GPAXiIAncYiUGaFvObQhFq6UYIfdb88DJgZ5yGAwQBU8z+XSiXT6SQBgLz9zyZj8UXa8scrn5+PxuMLKcIDumgHeF49w/W/qhDA/7nPFyAAwGL0de1u8TywUh/oTX4ALs/ATWYBpo1gnfuXrv/y9taO1+uouGyBBMH1a7L+L9/L59fuYQ+wHE2JL4CD3K3cLXiV6mXl8Fs+JajO4GCE9AKqenAMJ4ektPjrE52AvQqEwKrS1jIMAaITQ2eQpfRK2r6yY50hcxOwUwMAIkB3UTYAAgA+kW4g5kGAo4flnoDjNDXABgKAuz0dhwxrcL/fMgVDEeCdoY4OZR58mBUAWwOQ9mCZNIf/rEgAoCtDKiBqABn3JrBmAMlUau7iRQq9Skr1P7IYi8uSwPoXpRONzUbn76uncqLioYJEifCTicS9xOrq5OTIGdYB2m/0BBWLFZS88HBnTyJAtbovAXAHCJcUCtTHiRnu/0ArKtXS9u6/gg8cjl0AEcDnlfKfuP+vJvJ5Uf+IWQIDlqOJxNoaYEAuJ35dw5cj/piHFycAAI870MIwMwAAgFk4P7AyfemSAIAJPQbIMgeg84BLGgEy/RnyA8zS+8Nf6fR05kJnSAUCSgCYkgygr28ASUwAORTGAtIQYEZBwBWlAQoGEGxqgA1T/z8CFVBueBUDhgp4xlABC6oHKLa9qhlAr/IDkJvAovMH42+j9AkHVAuwjwRgjAABALLZJIXecds/l1qcEwRg/hZDAFVGHOphnjAAtmnx6Vz0Pj+XW0usJYZXJ0cmz/l5Gth+TbQBCgCcYjHYs7tV+xaEgG+tJkARgFIdBGwassBWeR8AqHAESbW0txP0PhDFICpnwwM6QLDnpmz/3xhZHU5gtdM5IGAA4n84Dwzg1i2oe1X+eKVw2ykmqMIylH9qMTIXXkEGsLAoAGCaAYCzQmSCsCEDAgLAaYB+cgRN9y+lzTconQkZc0A3AwAMYA0QIKCAhqB6EZhQgM8C4w89aO4BNhACgAqoVjxpF9CiALQLKAFA/Fy33QKoTUBaASASoFMB0tn+rPjMLakWwJoCuBjAJQCAaQEAn8FdTnoAiOdSyIXnRWcQkQBwdjYSZQjIiZ6AAUAxBXEbBQCYHBm53K6uz//L3tW9RplfYVadZD7cCN2RjGa90Sh7N5BRDBtMYoaG+IGJ0Rhrmlm7NNt9p6FDmJ0ZyxSqsL6FDphciMyWWHYLm3ZWke1NW3rRXuxetPR2nAlhJBeikBDcVJSlXmjP1+/jfZN/YGDeNxlN8COZzHl+z3nOc86JRpSlCSHgYfXlBk77efL4v2ue6F9tNLasDzb1AN9CcW/84yLSNYh/PP4x/glyIP5rRP8ZisbHBgYGljjAKzILVAPAvAIAPv0p58mRJpCaVQwgRwyA5ycjAxjNZnlZgGc2MIsApAIKAYAcgAC5FI+LBoA/I5zY2qnEQGAAWgMABqBEgLe0ChyNHOe1gPr8ZwZwF+fGMAN42NoK1kQA8NN/4lAgIQCoAnbYy4H0gkAFAKH6MSoMH7GnAmsGgC8jYAD5pNKZ44lEsiAAwFZgTQGUGdjLAOayhQLF/4M50f6zuYk5FADSixPZVGourQFgltcCMwCkF+wUAMuAVAYAABg8ZxDg18eZBCAAwF17eODVGq4AxVmhDas/uLHd9ciwAF8CoOBjY/PxBhz/a403Lx5GIPirSACWlyH+Y3u+1vQfz/8lAgCkALjVLAdfNgHA/PxiehFTHC8CCANI4Tx0TPxzSgScxRTg7Ggxu5UBeBuCiAGgBlii9CxhmQCS8Cm3s2d7BiAU4GBILABBsQH9STTAKf1+bFkmx0IG0NoK1kxlgD8HlEeGFwR2dPhEgI72X+jBYQAA71D4f2EAADWAK14AIAtgnO5EHGlmnpuBXF0EsHuB9BiQC07uQdZxsA6QeyAMYDhVmcixGjYBqcEE5sRwY9EvJwc+fEgAULbUM0yjUQYcHOzrsxDg8r1qmAGgjsdzfbn/xSaRAPTsNtj9L/G/si0K2EXAhtcJjP5CHhb8+lksIBf8R3T8/1jR//ZzfQAAA5QCcB3QZgBIARbMReG/KAwAuBCpANg5CAygmOLVwE7RyQoD0F7AC7oMQF7gISUCuiOs+blkBXrKZk0NADIOwNYABACOiQ04GoiGqhdZA1SDwHgu6Ec75Y8A55lpDQRtpusPn2uTd9BSARUDQAD42Z7QLq0D7lT2cNwNqBmAFgGEASTYAYAAgHXrvJoHIlUAYQAnfQyg+ACuOXyAF7mIgFmMflLIlQSIkTH9HqYAogEIABADgKRgnhlAObOEFKDPQgD4Zj78YbiOABCFt0AgGgh/9wqXgeOo33VbAtgu9ldUKXC7FACNBTg+ePXNy/5IoM7hz+L/gY8v6/jv7RtEAMgscXynZR/AhGIATF7KZcMCKAWgGzIk3IuSYwZwkwXBrIPOiblRrxv4pCkEUjcAT2McSRSKeWABLod/Mp58mgQGUMrLECBdBmQjAAAAI8A7wZB+jUQ/vS4DQW0b0DU9OToQmPmmNQ+wia7P/m6MfvXoVbsdUOcAJyJGBGjbL+YQfwrQzYNlAABK7AJmD1Ac14SMjKgUwBgBfDYgmmxfKKALsFgcVktBhocd1ATTaVX0m2fVH10/uubnZwDzxAAWMooCjJ/rMBBw6V4kAvQfESAQrdaDkdiLzXXs3YXgXV+1twauWBtDrDxAh3/D3gK2weG/tvr6ULgWCtYDCgEi4XuX2tvVF9AxzgCgNACaBoYMIJPJsAawUC6L0lkWBFisCAMwiz7QEUgHPzAAXKeedUw/wElVB5AFITgRZEgGAiRK+Z5OeKB2wKfxo/gLAoDFALo1A+jsEhVw386gDPuEE15pgGYU0BRrgEIAWr3ATXb99q8xtqpgcSysVcDLtghwT6mA2FR7GOtCHgbQ6WMAJcMA4A3zTGsmqF0GOOkpA5zV00CoGdDqhCcgmHTQEYRbgibSEwQALAF4AECSAoqgJaYAiADjvQYB2r89FAFiDggQpTCthr/7nlb94uB/KwdoeONfVQBW6NE3PWBNxf+bFzU4/us6AQhGjn9owh8JQB+lAEsZDQCkASADKDMALMy/9z41N+OAAxICJiaVNdChJ6TIluCzpg/AzAQwDICNADIUjOYBwJVP4E/DHYHT/ykqNfCYVwDQ7WcAXcIA9reZUQC14xD+1z/19QJP3a1pAhBu9QI3lwjw79iuIGaq8GB5AcUIxADwbazN5ADHFAPQRgBcDKL5wBYGgG1BMhGMU1GrDujrBNLB71kJgGZAR+8ASqXmJiq56Vk/AyhrBjAvqUJGZEAEAIsDdLRfPV4TJRCS2kB/oFo98XplBUBgDY9wvSWsYc8G8oGCJ/6ps4Do//d7wrV6XUkMkA+HvzTs3wYAZAALC1YKsIQMYIEzgNlpyHCm30dnIH0jCAAp/O4RBB29JmzYWhDm6QiU/UB6TzDNBWcIGMK9TUn4seBP5ShSAGEA0g7EK96UBsgMoOtwyAwEDX91AyjAH7UBSISAt5cVAARjLR9gcwHA3yKsiqFjnfeDbREBrvYHDQDs3ke0cF+XVgEVA+jWAKC6AGgJ1VEGANUN5HoKgV4jwIVtEQBe8/jKxwBACMhVIAtmAGAGUPaLgKIVQAqAlUACAE0BMB7vxdCagwwAZ/1Wq4Hquy/fPG9wHrCm1oV4cOAR3x79z+7923iysf6/Z7FagCoM+FzCXQ/N3LeOf5QAx/0AUFEaQIYZwGJ5fhbjfxohYDqNPEFSAGfyzqQ1HEDGAqoNAaO+3QC0H6SkrEDcCoibQZKkz7q0w41aAnE7aKfZDGIAgBhAF2uAauB3KPIrAIBb/l7gH4XqSloNzvyl5QNsqkLgZz+oBQOMAFZHsEoBLklDYJvWAdv2c3H4vAUAV8xQQASAeFIlAHDUJLExAF99cg25Qx4GoBMApLCFs/xqHvU0AiEBcIj+41mYq0zkcEu2Lvmhp94wAC0W2inAOSsMAQDCUcMAyBVUCx96/XxFVn/hQkA1H1xVBjjVV6uEzcwwHf5rGyT+0dmvCMBWAOhVAJBhMTOtqgAZBABM+OGzs9NypVIIbIsVNSzM4STAMYtCz5oFAcIBuAxAEFB0aDO4LALGBWFuKe8WioV8vhTH0/8oIHWeAUCNBWYG0CNVQE4BdgcV+Efrn38CGcBvvPG/9+K1WlDznti/WhJAU12/+0dYAADOrH7LC3jZawXCngHsq48eNgyg268BEAAU4jIOBE6aRNKlMmDCLSoD+oVTp4a20wAunLVSgGFPOzAefHcm4Y0WgQIAYOefrgKW50k2Ky/o+GcRkAkAqYC9XgZAM07qUfy2EQHw0A6Hf/LmOQ3yeCJFwYZtDoY0f/2Rrf3T72m0CP2NtdfPwssMo/UahwL2HMS2AMD4+ODY7du3BQDmucKZTiMAYA4ANwEAcwAEgPmFSspoAJN3rAGhPBJMVoWaOgA7AU5fcHA/eMrBHkJau+44RaD7ThZ/cZPcEEybnF0zBOg8AECnlQIABOzbodlfqHZ3Gwlg78UvIopEBmqtnSDNlgP8JxakgjUlcH4V8JJYgdpkng08HOMekS4/A9ApQEENA4knRhLJvAYAsaE7xdNDQ6e2tgLp+PdtBUYGcAfTX2mWe1Cp5OYUA+DTnh30VEhT2T96gQ0B6O3tsBkA6p6GAdTrVbxiQAIaGwIB6Oc1eT+rfGurj3gkAL7T0D91beDxD5Ffq9Wr+KA1gG0AoK9vDHBpac3pwggAACAASURBVGHJLvgv4BdMuiAA2ZlpxQFSFapuphQC3EEaIAiAMxOsVcF6S4jqBkIAQOcvnPgQ8Xm3hG6BvOviR3Dox1EFTCZK6Nd0u40T8AoAgGoGJAbQdVALwKFdkS9v3LpljwPj65hhAOETrV7gZhMBfh8Ux0o9OHPPWIE0A2hv/3k1pCba7ArtPsLaUPf5zvOs/F8570kBComeuMiAI4meEvUCJEZK1BQQTxQcp5AvFUqSA5RMEuDVAK21IGIKBgJwJ4UMoJI7I9uApQ2AemaQURMCQD49NjhgEYCtAKAOLA7Uao0QINz/8g2lAU8EA9DWs07KAE0P2OTP0CeojUiH/yvM/gO1WhUxABGgJgDgTwE6gAEQAAzAib9UZqsP6hgD+AlBgzPTGgHO4HeYE+RTIwLoGaHwL8CbQKalAggDOA3Pd2kkkQDMhcCPuwAABddNlOD5d7kSCAAAP5B8Pq9GA/sYAIsASgLAKzJ144OPfRLA3qmP3jKY19oL3JQiANcBgsHwiQ4PAFxiEeDygeU2jQA79hEAGB9A53mxAuKbqwBAZoLHCQBwO1geDiM3Hi/wxvpiSZyAXgFQLb0aHvaogMgBJAxu3szO3eRhGGiMqeQqNCYgbef/5cwY9wMPAgBA/PsA4P5M0Cj1HPzV6kO4UQlY3TAn+ybc9EDz/XG78GP6gOb9KgDY2ETnL53/8G/xPycAEJi537ElBegbGxu7nVkq80CANBYz0b9UwaagX8KdOzM7KxDAfv+shD8OCSASQE1SfOOadeECkgSokSCnT6Ptf2gEk35g/gkXEoHC0FCilHUKcPC7pAIgSGsA6N4uBThy5G1LAW775PoHW8aBTV1TdU8EgG9aGmDziQDEiKmT692raiyoRwX8KrxDA0D0IL4uUAQUCtAJtFFlAAQAbo+YgfG9QE5g+C2eSKficQh+B0AgVTReYJUCjKrTbNSfBODLfpIw4P/sXd9rW+cZJsGqbZ3VLSQmJ3UuRpMGciWwEjANzQ+LGdkOSeU0cedOYimz12PCXCEkNWgXG1RnUEGcixDCoCXd1gy3uxmsHXQXLdldC7uSTjQY7ML4oiiSUmzjxZCy73nf79eRlT9AoOPEVd3URJae5zzv8z7f+5bFL2qTYxEAc8AVQwFyYsAtPg2oK4BnEYCAfYSwzxQgrugWRICEtgQ58P543bo2GP7MAI922tEgIm/9VUUnmgA6FMBFVgAk+G+trqp5BpQGwnUD4mY2PYvnJz7SZXxYCoCNgKn5TDmX8cqCFu/whCBTBCgGEApA/JfK5ORljAwp4iRgrpicJAUQK4AAYrEHsUTCF48NARwTsLeCgOI6vN/kQGEBvBNaCSAtAEMA/RhQ79UAX1AU6CEPczAmgJQA6jyQqQFOkTmsMZ8AAWg9EFMEwDYALICiL953yZh45BVYAVTEezMHAqhYTYALqpi9FG4DelNwAAj9qADK6YwARTbNy8DyPATIZAB5YMAtPg78OgmAZxIACn8XLGAxgHtm+7//eSTRv76x3v3a0Ayw24oG9UigL6aT4BkEMCgVwFmjAEgAyEPBEv8wAa4D/pgTlEsT63WUAeJLggEynAv0psISgCqAaXgAmdL0JE5jecWk7+VyFfFCoASL+QWfghqxhHhYiOupgKmUJgAEAcULPfby8IAigIPOtd++s3clwFsfMgEE4lk7P+nHgHqtBPjxXz/ixT8Y+OQaE2CC4M8u4M8jA7oGGD4Ab/g4LQOSCsDKAeB0WeEQNf/w/kIFWoyL911cEQDuSwVMsaIltrQW3AgAg/9QD4ByQAR/UgA5yQA8BGyNxgDYISA6CLCiQwAggFAb0CiANm7fAH6ACqBGGmCx/QPb++tS7HfDP1cBG7ubVaeKKkLh36k6NVd8u0DAwelCABQEECXAWR4AsiwZAM9BKgCmgFmGf5YkgGQAVgD0jykogAw0gAcNMKXXhGgGYALwBAGwAkhCASgCwH1fvDw4EIiTwTFrPbBRACwAxk4NaQIYdj4DAbwRIoDRE6P7FQEEEffv/RhQzzHAn47WmQAw0fm1kZAEuPrm1UE2AYwE2HdYEoDpAtCCcN4KQkEAAf9YAtsBCnT8VJSe8fhkqTQPAsh5pUIR78aZUAFwOQT/UBAogxiQUAAe3fdEBVDmAmBWCgCVCVQZwLt3OQWo8W/lgCwCCAQBPN5ZrGkF4DAHuItHdx59R7NCrKshf69LVsDdf1M7COr+79Rqi60tlymh2o0A5ubOnSMJQMd/zEgzCABcpACyaS4DBPrBdpl0SAJkSAEQ/O94bAbIYJDBPxGA+DOFycuwXCQB+EQAfxPIjxP+HyRgASS0B3jMVgDsAT5vEcDQnwUB3DwRJoC33pMVANxP9599D7DnCOD3n+M80ENk1yLVez8L1wBkAoyMfBLdZ0yAl4gAUhAAKekBLByz2wCFeIJ2BAD/MAUxjy42LUsAJoCMd55LgPOhCsAigJKMvU9N5XJwADJKAuRgAmSvy32gNBYgxAB0FFjGgCX+R7oRgMBt+/H6zmKUGaAmJQBdL2z98Oj7EAeEXYCNjcZOqxZV+JcE4AgKWWw/2Xar7AbuJYAJmACQAIKi7t/lFgC7gKoGYAWAp5dmG4Bnhpc1/jMZLgHKHtUAU153BTBTkQpgRisAwQYggFIxETs5Pn4ycXI8MW4IgGcCWwog1WEBDNQP3IQFsBS+/7/xcTSiS4Da130PsOcI4Bf/cA9yH0C8irV3FQFMsABQSYB9HSaAZQKmTBtw/FAcuTOfgqZ+ASMCSyVRAiSTigCEAigKAhAFKZUAqgXI20DUTsCwAsjm5jM0JTeH9z30v60A1mwFIAXAfUMAFzsEgE0AtdbjRmNn0a1KAtAMUA2itfbWzhP2Atc7sL+x/mR7sx11ECLWBADEOzXHbe2ubz2bACQDYCjYiiUB1paX81ICzBIDXM9KE0DUOxmjAeZVIiBThgSgoM+dKU9Fg2UW6LwigAwwP4NEoCCAEv7FlyXA+MnxBzimNR5uAlgKQHqAHxoL8DnnYxoIvKTBj0+jJ04ZAnCO9mNAPWgCfOXy6r8hFV0JKQAigF85/zYmwPPHWQEoBkgtLJgsYKJSVOFTGhFaQQrFFwQwqTyAXNEvsgdAWyx0CEArAO9SqBHo5bOIAXmsAHIZbQHQdIw8mWirlgC4jyAAHwXe4wB2EMDR9Uaz+bTt1sIX9wWi1SOtze3dJ7sNkADtBl1v7O7sbG8dPeI4VQv+VD8I9e8I/D9tNkQJ4HAvYC8BjFy8CAJAEOD+yq1V3QhYDtmA2VlIHL7/kwII1QCqBAD61fFgIwGUAiAPwJtOToMAKiCAUsGfpBFtPvVnYNOAAHx7GkBnCfDi0IAqAQacJVgAb42e4A8WACeWnlNNgCDift6PAfWiCXCkqhVA9BrAP6hMQHzAFbh6b2h/OAkwZlzAlLUeeHycNgEQBQD/fgX5PxwGqGgFUKpgilXRsgDMRmDgP+upEkARgFwCWsaNr8zS2HgAYIBVLQDuUhDwdR4Gskf/WwQAw74FAmg+3Vy0oF/TfcFItRaNCnJob7ZarXa7hesFAXVU9yZAwPBH9V+tuZvi2zW2FyEInMDpQgCDI5QGpKkgTADKB9ASQNUA6Vk8U9CdoYB5lQgQlRDQnxHg1wRwwe4CKAXgF8ADovpH+KLgEwGAnukFKkgCUIcBU6mFsQVbARz/0bAmALYAfjc6ahQACOC9QPcAHy5+0bcAetEE+JKysVAAkeq9X6rzQFIBUBJg8Jqzf0DFAYdfoRyAlgBjiI+k5EgQuRpU3F/ivqAAnwaEJ5PwABFNq3hy9U+2SApAdQE0AUxJArikV+JKArijegBlMgExHXOWUwAhArgPC/D2udu3Gf8TE4N7rs8kAQRBawME0GyCAaJMAPqXDgiJ3w6X+CT0teMdWByA6j9w29tNJoCI+LPia5HFz/YQALIA6AScVQwgxYucDyxNAJr3JxVAjvGf7lQA89QdZQ8QJcCFsAfACoBCVx4rANBBvFIqmbUAHQoAp4EVARyjJuBLA4YA6vdgAby/NGoLgNETygLA9dHXH/QJoPcI4INv3YOcBYQEeNuqAVgC8H4gKwnw4nFSAFgLzgpgQUsAKizlJ/QCCwT7eDI+jbNpnpdLSwKwFEDxsr0R+JI3ixmX2gS45F3JW/CnxpilALgHuKoFAHUAX587JwTAXFf4D3IUuF4XEG1tALHfNJtb7p4KQGL/jG4SVHXIhyz+jvt/UK9t7hKdNHbch7j/B90JABoADAANwASwKgkACuCGUgCC4K5zHyDNHsCroSpASCEaDzDPVumeCuD8TIVGBakf9iSEQKmQjJECwLxm8Sl2CHrNV00AvJ4C9rYCeMUSAGwB/HpJo58Z4ICJAfUtgB6NAn3l4kAgDXSwF4TJPiARwNuORQAYDDiW0n2AsQVmANkIBPp5KDArAVFqIglIB4KneVw4XXz/r5gugNx6myMCuCCFLQgg683Pcx9QkIAyAbOcA8yvEQGYDCAywKcvnj53+hnw57MAdRBAffP7ZvNfpAH+57qmCLA1QE1WA7Lil7d/dv4U/vE/OEe2WU00m0wAgVAA7qcjI13+BhPwARAGWJHDgYkA8qYTmGUJQAogB/jDCZgVSijDUcD5jAC1GRHmhYJA52USED/jIv+osR+Mt4AhA+TzMIAENjnHeWgTRf/IAgjnAA5YBEA7gW4KyGsJAPz/9DlTAvSHgfSoBPjDHwO9+41GAw9qBcDHAWACDBsXcOAlOg0oSwAwgSIAvRuUVoTL7cBxWguQpKGgk5NmIJi9E4AkAN/wZSGMPVg5qQByvC0kCxNA4L+sWoBra2sEfmr936X7P9w/ce+fO32xK/xxfepiWne9GtS2vm+qa6cdrYadALr9aw6IVFn+VzHuOyQAuGvQ2m3ob+XWqScoCOCTbgRAvQDOA92V039XOBREdYC0AbPUCSCS4/2hQupw9DGfzeWZLpg1rmSt+UDaA9DjQJPqUqtBY2YxMOUBrKNASgGkWAEc3qcJQLw73sda4CWN/1HqAbxn5YDd/jCQXjUBojwXMBIZCjpMAEEAQNLINVsCnJIKACIAHeMFeyyglgAxPg/kx30eR6Pnghdwf+JF1qwAipIAaBWQKIRv0KmY/A16Z3sQxjfwtStZnAWSqFBrwIB+Sv6s0O1fmn9zcxMj3eGPfccsAILo1ndcAXxDDOBaEsCYAFL3o+Zn9If9P4c5Y6uh8d94eqZOfkE14l5781l/C90MAHOtUFeQZwGvLl8h/HMWIM+Dg9KvpmeX9UVjBK+oeYJ5EED4PCAdBrInAvu0GtzsBmf8gwBICYxb+DdtwONjLw9o/B90Tv2GmoCjFgOIR5wDlscq+wcBevP64FtXb7Ecir5rEcBVfRzgLzgPxBMB0AgkAuAKAJGRlNkOZJUASgIkBQlIBvAxomqmMEMpAOkAFlUQiLv+hG5KxeY96gbyY3w1ixhAGQSwll/j8P+yFP73ka6Vg4A7w38d2HvNeRjUYei520YB/J+96/tp677iSopd+141qxZb3JYgbWuC1KdIsaoioZJAREQoCoWIQJvEWiJB5kRKsG5sT7qLkofiSbNE+lChTGomKg0qOwxlD9vU7WFrlZe9g+1WmvaAeJgcDA1QBBLJzo/vr+uQP8CSrw2FgiDAPZ/v53zOOZ+zurpXFQiwqCiACn9M/AUG1FzUPty5XTG+0GrVDiyiCBCwWi+9/goEoI6AUyQF3mIAgH8/QcD1Yc0BLg/TysBhIAAp6hgcvk5tw8MpyQFQBU3oIoDBAIz4ZwIg419vBkcAOH16Pw2AZ4HeU4MAoTCvBb6oGEBUSgDKBMlu+IHWrQjwB7U5U+8H8ncC3C1+JzyB2BdMMABAAAAARACpATS/hACoAWR5OyjuqAECwBSgy6gDMgXI4DlG5YJEgnaE0+Ui4SdO4JIKKBmAXA0kUwCDAOx7/Isf69pMuUgcveg8lwCwx8UAFAIsfxqgLjXo56/9Ly1aDtJ/QAAJApUNG8uA+AmBq/RdX8EBhpACnBQA8EB2BYgVYNwNAD8mxvrl+CT3CxM2pvg3QNdC0k0M1HoCsSUoUQCxEsCIfwUAEPeUDqgiAMW/SgHaqAiodsLYuBLkt1FxySLgx03lkrKTaUgAdSsC/KQktwNErA9G/ZYAchwgFAyHJSU8Rp1AVApEuYhzgJoMQDMAXg9OKUC6G1fWsx8QtQHllAYwMOAfBfDOkAboDXhuktt+kpN4JSEsksQC8nk1APBgDs7POWECtM/xb4Th3WK4LBp3d1ZWfdd2dQziX8qBi/uRAa38i+zfWdta9p3/q8ubVoARI2DdMbCnlgK0D3VgNfDk3Ge35lRPkFQBkvxITiYn3SQDAK4AcXEPAG5Nof4fb0A6Ag4YxsBqL4gZ/4L/xwz+38wAoAgAtQG1tKA3GO0FGnxbTwFESgdvAwB8Oh6NagqAEkAxJK0VQg0JoH5FgL/YTXoB5A1/JwCPA7w+a2sACL0pAQD7gFswB/jEoADNp098y0UAAwF4OXA3awBAAXLaE7SfRQByA/BE+AsDbG4NQmEcEuJJmgRABoBdACltC0rl/7k5uRC0/eXoh1cXJuYfFWZnr/QUOf6XrCMvlkUZUF4rW2uOpaTApUX90BUBcfhT60/Agux/hb5KRTwrCADCGiRgXXn8+PGTm5d4z/JLTUHnCAFuPTDOf+oJTCVlKZCkz2RqMh6HBAjedCdddyHJzb+y/0+4ghkEoEYD0BmAJgDNEgBOSAYwKBgAznUSAxg8FtIAYD+8x0VAgQAMARcf2toP1GpIAHUrAvzVkQvejSXByhKAxwEsBgBpDj4oVUBSAEgS0CkAXt9y/H8diwlPaloMQtsq+6QGQACQkZ3AGbqdPXzqUQDsCIRo//AyNQKKSUAV//e/kRoA6oCUAdTEPwX/6I07hVbbsm3bspgAQPg61e8rvhRgdW/l6c6mM6ayAF9vgAQCfG0L7X+puouzAiYDAADYpikhKhpYjmPZgZme2fmrjKM1LKDjIyIBNB6M+8+uC3cAxQCw5cH9EFsgJpENEAVyz0hvcG+gv98wBlcA0EWWqy/Fv6EAIAD8vJkIgJYAWlgFRFgfpD5gtRIgQhLA1LvjZvxDGvBmUe1abEgA9csAfvbnAJ/sBACFfUWAG4GmJj0ZpkSAwWZmAC1qU4hZBzzOGmBv79dYBeQk4CypgNIRLOdzBPX6zWFAeZ+fGbl8Get/VAXEImASd+RpU9DP4OyH4Kfzf8jn/UGH7rWJ+Q9mLKcYDgaD8DOESgwAtrP5DCJ/z9QBcdRnd3NtzJHlgEX/Qwt/8NpyNrZ5NlgHPz86LXIFQQQIRSKRcKloW8V3Ck8u7KMEEAn4nEWAL+5/QRCQT7EGwBwAf2C0A0vgE1/kcgBP9v/IBEBuCK/RALIKAGKqBCD83EwAEAwAK7s0FtT2miYAYes3sghoJgEfB8sKABpeAHWMAL9vLTfx8j8gez1iO0C7zAFG6d0eNgbkO+JYS4tmAD4A4M3g2PfTK7sAYrwcMNt9FsK/W2gAlAKoTuBMv+EHIOaAPDUPNDIC4U89AKQBUg8QzgCK7t850v6p+c8Mf4r+S3dmZ+DoL6l7OUT2fZAA2GNbz8zjH99im6+drSoc3IuLi0uvuCAFcJzODT79l5fXRfSLRKCyvOHYyhaIQBWuppJt/7Tw5Np+ECBsQpUMiIWAlI5/N5mcHpmOwws8ErQfRC0HyBjhryWALrUalOIf64AxrQHKBODECcUAjgoAQA1AUABDAghHSjNT96aoCDiuESB68ddFvW15rGEHWL8A8Lu/Ya9/mDcF2zdFDtDu8wUTxoAcRocVAHDxGF9YBaTyf5o6/tLyyqVxLpB3g5EMmE4jA8h1mX4AcsEV3dDCFdiTmwHjNAfkSgLAHYAY/hD9J9H6Y2iow7//A9uZLj2ePWA5ZbXbju9WEgAta8l5/kxxf37ZEzZgK+u7m4ABSg7wXxbw+s7q1g4OCVbooRkAEoDKytaYbStfMPq2VDsJli3ryOxLGHCofQg9QjQE5IECpFILqaS4AADEbpRpOv2nE2JrInEAnQBoV+A+VgF0FTAWy7IGALwsxgta8JkVfYBoB3b0E8kABBiYfsDWl/dwJdC4IgBRlgAMALD/1ZAA6rcQ+G/roFQBVCFQhT/nAE9MADjQ1tKiGYDgAEdR/2MnAIUANBZMhb0MNgKLYeHzOWkH0mVuBfTY6xYtLgwRAG/9OLH/pAh+sRKEop90v1P+0h8d/qO/KsxYVjkSCZkX3Kvk3ANR3PniP0b6jy97lRXy/lgHJrC+u71ZXXPkBYBhYeQDKKxV2SpguQKHfWUdHooBYPgDAOw4tugeUAjAwRQMhixnpjAxWqMJtp/rkBggXALyeQIBXJeOT5fsv3A/GP6GzkwrhTSjFwT2m9tBkQGcRz8m+GX3neX5TFwIkD2ezaX7xF8nl80er80AxJDH4GDbG2GfIfjU1BTGvikDRg+XwyFRBrAadoB1XQiMNEkACJM5uM4B5EjwpRnZCIif9ramALhABjkAUgAaBQQCQIc83GNZYP5893leOkf1fVpo7QpbcHMasH8APxBPuMkF12cKjJZgk5z4YwdQPs8LAW5h+AvrT5/rH779y/n3bQcCrib+sWcNB4ExmFuf/Y/Df09CAALAiuH9sb6zu721idPA1TW4qhubW1vbuzvrGPz8WMeAr+wZGsAq5AQrG47hDSy/N0sskWDJslsfXR2tkSrPyRFB4RgMMJDPD+fzhAQAAUB/yPxjmtclYiEgIQcCzhgZgIh/eHpx4RvqEQITGOSAh9Gfhq9sTNQAmgdFGwBNeVEG8JaxEzp08Pa9qalPx6NKBIhyF4AE1UBorNAYBa5nEeDvZdXzXYpIc/BRMwc4dMUOSgAIl95r4QZAOisEBxjEtBIXzuC9hcd9XxolAGAB8PQSOZxEo+lUtKg2TcEzgvsn+IZe8AFAIhHH1VZAieGRJwSg5J/in3X/c4f80X/hSeE1244Ew5GwEfwRWgZK8b9kOdbY5o9P92T4MwFgBrAsmH2loh2AV9bhpF+WDkFkEAixj+EP/9+fAMAHf9gFCmArClAyAChAikDRCvTM3xitKQlgZyD3BAMCfHP9fp7DP5+HH3sBaYCbEOf/CAGBm1rABMFNJvrN7cCCAXSRZQitB6IRYC/Tn0FczorwPwuPrJwEUgSA7V7x3WP6/MciIBCAr8bN6I9GL35ZDsu14IGxxlLAus4B/mEFsd+LKcBjvy9ozUgwflbgjTYFAMQAhH5MGmCMGQBefgDA2zCRyKAnqNfHIqCyBEIJMMEudz4GgKDgwu1P8c8EIG9I/5+fqu36H50ovFO0S5EI/jB0gwYkAFDDOvXvW87S2PMfK6oIUMF6AAAA+/9VNARUpA+4zxysIj9ODGBHfxVEAPz8KvYCKQZQkhBAngusCtpO4P35m5QLGKahHaeEZThxAI0AlAi4C5PutLBKx9xocsElyHQTRgagtgOfh/Pfy+FioAyf/ri4Gf40MRH+xABO81KwQYUA5PRCbOCwlgAiVgEBgCQAkwM8LIYFrAXszj81CEA9A8A/i99JmTxszfpFgAucA9yV5uDIACJv1QAA5wDUA5CV2h8xADxxcggAmIKmEQByeM/SDnvfPCAAQJzKXK4BAGgeBPEvyT83/2HL/AOK/4862nXRD8/+iUettlU2ZthCQoZnAHCoSQ9TANt68b0uADz97w4iwOqKL8CXKz4nYOMj64r/wysEj52nFaEA4Gf9sO2oGTnINhYRAICN4LvIQ/ifFLIdq7UwcaG2KnBK7A4FDMiTGIAgsEAX/GawCWCatBLyAgL67wkAMAkAOoLERxJeb293P20JwyQsk0N5JsYM4Gw23Z3upSKALAHwLiDBANoOGhJA5CsAgNv+8I++O34gpADAudIoAtb19ceZkIqYwJFrhicIIQBtCOspGxTgFy0yCcC7himAAIAYnzB9zACyVAVAAABEgP94ubTIARQBoFZA1ADY4c5NJgwCAPf8Ql5csvX/Fvv+/J+963ttKk3DWJN6cs5SByfFU2tvxk5gdi4KlqUDxTSNbGm6pbVNV+sow3TZ6KSFdUM1EY4DIm6ETdFchHF3odgu9GhbKV2YZXB3vAh4sXvfxnTQzYXkIsmpPY4j0oXqfu/7ft/5UfcfqPScpqZFpT/yPN/zvD+tol8KqJ1/tHBEkQs+N/rZk8eKCpOP/d7Dx8aCK7gLZFVt+dEgAmDSfbP6tAQKgBNAzUEBIAfMZ649IRb8TeSATWAOo1Su8Qv3BrxUJRIcLWMdLUFmB7wyA7/kCgpIyAFH3uWA0VBXVqgARgIOCmAiIE7L0kSVxKA2KGIAUXszIJgrWCAQCYczfWEuAJAA0u1cnUEsoB0zglzz2xYAHYBDABSmb7odABHA5aJFAFJstw54Z19//E7x8DSghFuCXRaAPMCiGA7OMFX4AI99oIBAE7sDGAm0CcCpADAZAMhnGgA2g8GOaj4RKNPtaAccpEHXGicAaA6OTybg/OfgHx/PU+UP0//bzv6GieW5A4rsJdsvWlgkH8OYrMzMnjnn9TDAjY0dYOd/EMr9Y69+xKQ9XOvGk+rTiiCA2jYFYDpHg1u0YKIFAAkA0YPNarVChz9phvLmxgpZDv+BlmP71dj09YVpr6r4wQVIfBMLrRFXICb4DgcM53QgAPb95sfzQAEUB2Bs+I29DoDdDP8pIABcr+hSAP2gABgBRLvDfAKYlmqHrWBIzZEHQAE8CdhqhQBp5xOwwYfOpaDoAK40Nro0wBnmAAQBPFZ364B3ugdQRC2gZC0IsvB/EqeC/H6lTngAyVtHpz7EAJvgAhJodhBABDNNnAAY9GFNeAbUfzwTTuF2UB4FzFiJQI3B/w/stW0rgDjKfyYAsO8vj7HxTkXXvgAAIABJREFU/K1sl7PeHzJ+E8tjh1W14LeOWIpnsMNLXZk+feVeLqTXrfnYiQv5uWDs+U+x1dibKod/bd0sVUvVp6bTAtj4rxH0cUVoDZ6gKgD4myQBgACMarUqQgcUM3itMsUhUTWwqsYun8jdubgwE5ODHP72HA2J6QDl3TrBzwZCOo06u0UUgKGAJcyh0DDAHuwH6u+Paxb8RQ6A3S4C0CgjCAQgLABjAgoBHHSe/4Gm5lbKAdgEIKEDgGFAbg3wQdEiAOXIbhJwpycC99uqebXlpFMBCA9wskUiCeCD3/khEfsPCPw3BYawBrjdCjIlex0WQMswSQArKnsz8Umtm5oBEP8pEQOYjMe/ANsfp4HXYP8TcP7zvZ8MD1k91zngLvT/cnlsj6xKAv0uia2O3czB4A1dny56QAOsBIPqy7dvY7HnP5g1QmzNrJQYfqulrdfrorjHQr/pCAKYz1zWgFKAZg0cQIX9e6PmWiDwSuY4h6JhtVHX9a7cnZEWdZW+QMdKXa/X5yvI8pHF373TKxDSs+Pz8J0TBYACAE+EE8HYG+wGTmmTPVFxiRRgNxJADxJANMLxr0XbSAGIK011gK1DvA8ggASATZ4fOQRAER3A9cbtDsAjCQKQ1O92k4A7nAD+8veCRxAAjAYddSsAKgZU9vByYHZqfdwcGApA5IgrALiaWx0WgDn+ZHsbKoB0Op2Ja/BJbTLT2xthL90+RzsQlwBxemFDIQBIXZoevESJfxr6p4cGXMN9GCl9tTCjKL56j19yIsoL4t8nBUdud+a6unR2fyuzb88b9K8cfl16Ym7E3oBkx7dNwn/1ibEFpYA1C+Ymwd/Em5yAybMElgjAKqAtE/+Dsi0BBANggByyDg91vHL6yMwqfHmuLxYShX5fUfZ23J94hwNyWVA93AdQIHCJIqMwKA1+RJOa7f6pDQAeqS9OnWIE0BvNREB/QSog09aWYb8LXgWQTlrjAD93KoAhlwOAUQBzmATcTgCzRRFqYQSwmwTc8R7g36rH6giO3d83KvDPL3gxPkICoN96AfaDYAGgbQGYgcRSICg8ZXd7up1bAPYBbA3NEAGEIQjQzSuBovZIgMEejSnbb+BVvUQ1LuzJJciDwexc/YSzz49afCfuTxcVHxgTwprXTr7JqtcfvMvgnwP8613Zn0keHywEffNDpWJu/FQhbW+d/8wElP67VSuXTe78ayLd71oPxpHPVYBRMYAANvE/qFbcO8RevAoWUQEoirwnr2fZjRSwEJPVmIzzBTEryTkAdIHCOGD5bMO21uGBE/otHgmcR9gTAYA6AgpgP0zL+hP+2fWfCFiAFDP60UxfilY19LUfb8tk0mmHADgOXQGioDsAG1+aqLSjTuK9IezhHQECOOOCPzMDvFkQfvK7DuA9IIC/Bi0FIKkdozYDEAdgX92Mp04QgBcSgYHmWfbukCUBmptxNOBRayJIGyoAoIMkI4C+ZFqbTLX3Zib5dmCrG4A4IMVumgYk4M8EwKVfMwWQzQ03bEf/2eWxNaVYX1fHgxcEJ8SToq4cu74oe++FcsAAXfoF/cJp2QPpaoZ/wzBfmwLIZqUqrqfG1ibDdMUo83QeP86xNhiRzQUAv41KtWRAEgEiABV2G47EISYDnweDSEnqLOIfGeDEbEwdmzusqiucsBSncPEqcv3cVyfd5QGQGwQvQCOAlhKJSV7eo/Wwo71fG7SmgFAfMHYC9Z/qOTXYFwmnoqn+ZBgGgcM44GQGxrNBVwZWAZIDaKU2oICtAMgBEAE8nvkakoCfbFMAp+skq1l41wG8Dx7gH0VLAqysTjACwL0g/DqPofY5ZY9VMlz4qBmLgZqJAEgBNOOCAOoIaucEAPOocTMQowBGAPFMMv6rRCKFU4EwDEB3FKaB9ZDzx2uJKv/ZsZcNfbat0nff+a/n6mTFU1e3JjyJxM9Uhv7Y4bkbt/ddVOQzIdL/QAD5vUX2falvnrwwXpTNmoA2AJfO/2rpySaTAADlikGZPoz4OZeDkgDAEiDGFJwAaoh/eGdu3yNuQEWQV1p9mEX4AwN8H1OlOwPXrnSsxlSFduqt2F4AHooyTVbApQMahnPZ+UsJRomJS4lJSpj2aJAFGNQcTcDiAgVwSuuOhLVUdyYdho6MMPt1ZMCW2XNBjx89aCuAZrJx8NEHkh0SVmav3rzhdgDnGs8JB0CVI//aTQLueAL47T9lrgCYGo0t/18PsCw7COBDkIzMBjQdYpeQAEM4UeqovRmAjwRox3pAOIlSqaiGdQDQD0hjgZgR6B8c1Dj4oegNSt8SuCtz/pbeua3Sd3RieW5GVSXP2ppnzepOIAsgx2Krx+7e6Ry+PXznU990DhUAw382+6cHsndVUTfeVnhNHyT2Bf45B1S2ajUDD3OQCQB/fvCbViiACgAQ/vD3TEYABoc/mIDaM4cEePbC3M/A7ZFn81muALJdl2PKbGgqNBy6N9Ihx1RaNFBwxS88BcU/tnzewXf86XAuP48dUVgCTCETxgFalDYC2AQQ6Qv3wceRcDoSgZlg4SQhP51MO8cCgQXAjUBUBUgK4POhwB67KkSSP7l64+bNkW0CoHHaIgC/d2Z3I8h7wAB/k0XHHBR2Mfg3OBUAEsD5ek+9IABvfROVABL8MQsAWeSDDgbgy0H4xZtQcUZFGJcD9GHROhz+PVpP3HK2S3z+fWLeJf3x2ehvFjskGYr9fDSibM0aZiSxsz84dvfa8HDn1NTU7duX1wp3Q7kTjAR0WMGRPyR7mR3f2KyU+ZrfchlQzMEPbyWGZxPlPLwxL2AK2IsUAIIf0U8MYNbWzaqlAEqGC/9MABTh69r7EAKYFAbI+4Pyg85cbirX2Rm6utiiqjJt1rRJ4LHkr/cV5JmFRxO0mM22Aw2QGJinLQnYBjCJ/RUYQ8HFwDYDRHANA3v0wkQQmgXQdpy/FwQgVoIIATBLo54O+exSqsczFxkBXMTqf6cD2OtwALvjQN8HAvhzi+ITBKAEv+QewOKAUbEeQLw0vB8HUAMIBUBRwFZsLsPJAHYcgK8H4ZPBw0lcDwJjgfqSePpDu7AWF6c/6v7E0rxuK386BxvOPlr8pRyTxfHk81mFSXBSqXLHlWvDA8OhqSl2xE4Nf//z4i/YmZvN47j98fGlTwteZUXd2DR4cX8ZYS40AJLA5nqtYhEAPJgUwKtcNkz4syI+T3/U1iEFWLE4wHjmoIDyyyJMIPJ8CyG8fFa/l9UvPPgfe9f6E1V6xjMwB8+c0VG7Rz3c+gFv8dKSSCwmExUlUjBWuWwM1a3RpCxLbfYStswmY7uukTGpBPkwOTZNDLhdcAfMxA/TNDabbqB86fe5UbpOWQ/pzDjdkNTNxi/Y53neyzlntH9ACS8IkxEShfn93t/ved739/TpmS+AAGgFu0duTU9wDuAjdnknU9d9fi21+ejM/OVAebxpcCw+OMijAsgMhOw4EMS+CAV/JROUL/rNwO6/YwfvAl5gBCBrAHZ9D1iVOwAX/l0OQDf++vN1Avj/X7/9E+8DUL7Low1OBdB/vr+XeQA7OERBDwAWgPBfQ/ivxiqgOxqQigFcAYhwYGQBSgYD9Iew7hduC5sDvK5N1+Djs1Ny62fg7706P3NlAtGvszvoGSIAHx9WAPCvn/nkLqIf30Za7gan4nt8xlzMzJvD1Ev4VSxRpSipVIoYAFepSAIgZ7+hpy854M++QNIE+1OQC74cTxEVHRRQkpcGni4/96E8yT6OxYeHTTMem71zJ/ZGSqu+M9UZjUoOiH44yTkgi/iXQgBzhPAYkd788P23Am4/EBiZjeOIlF9+8LPBS4ODYedkUBv/HSIOiMOf5gLNMfyzIwCMAC7wWcC1dJpL9AAEAeyji0BlAsDhAFSlbv0i0JqQAF865oP0TfJzQPaia/aq1yYAGg/gUABkAUQ0oEgHY+VAxgGCATrAATzuwN5UAgjgXOIcFwBY4QLwxwD9rlyvwOX56VO6ZuAdP51O0fILdiygcMHnN45duTnSjXv/CP0JtkzFraUnB/xVJkAvb8ICDMZ/COhKJVPfvEAFIHbzXMEuAqAJWCkWCg4FwMHvfMKmgGUSAPj3Of5VxdLKitj/ffsXFhayc3GTVt6y8h88BqSbw/n4FBqTKH6MdgaDv/liUjd4STDtaAlQpCCQgKY3z7zfH3BxwNmpWBxlwOClS8OUpcgpwGYA8gDtEddQANsAtPJcwB27cCiwqAGiretq4D9a+i1PfCh6AE4KeHvjugNYcwTwWV1GEICi1b0V6LUtACgA5gGO+qvsO/a7qQhYwyUAe/nweHDZDJQOgI0H4i2oSKQDG1PwnsC0ChMEgDlIha34rLT9DPz978wcrfD702CMdTqCCB5ZYQoAX6deRH/zxeuAeTDWnbj/t7REZ+NLS5ZlXfAbAL88YwBY8YNpPLie2vmixAUAUwBcAFAd8NkzjnChAORD+6P4VFj5d4mdIpBlQGQA1jcA/O/3LGQPDhP6zTwu87DWNzeMj0DjHD9OxwMZB4xfu68bWpKdZEi6zwnpCpHAlYfvng+UcQBYAFAAbDZQ6IxjMFgHjmEjA3DSFQna6J4MwJoAF4QDQAVQ27Ul45MEgGFgo7celAuAj2yNAA5gvQewJtbv/6LJIkCmbz7gVgD9PBTAJgBlE3mA6gYpARgBcBdAbaZWYQAamxj+kQHoegDBn6KCAP8DgP/BAYl+MUij991HkxN+I02xmnaoBuyNTAB4vVlDu7ft+giiPzqC74D+sXie4G9Zi1sMJQHQszlgux//d8nNq4XSMgey1AAIZTABzxw1vkKZGHBwAD4qMQFgGwBWBwANsPzimwXAf2X2BxL8+byVnzOMN4gPkAyQA/BkAMYaRIHAxt+8pzAO8ItZxEmHH1DwysDkI3dJ4Gx0FihggEcEAwOE+GSA06IAwDMBm0iJtXL533pojmUBYsmWXeZm+AcG6KoV9wDw3pJ2kTkAOwyQRQFkvaJLkK5b7wGskbNAf+MeIIONwGlnGwAVAF0Iuqrbx4VUbw1eBK5pkFUAJACUAHxOIGw01HjGI4GYQNnR3k4n0VhCXSIUFrs/Hf0H9J8NOKbonJ+frlc0kv2yJaWQP8FhdFgAAONfMT0aJfTTAvRPxcwlDn8rn9+rGg2mQwKY5lYtg0M+j33LCno5OgeIOz//XCysLBcdW7+oCBYLThfAH5WEAKAWAK8QFAvLpcJ3db7K/ZWe9I842BkDLHoM/9fyCcsyY2Pv4UkFjDaCf3x3y+j0TqPPr9gzCIkCKMuIIgTSGrgBliNiHxKaig1QSEDbQFsYbweFeEegg+H/JOEfaLe9EdOaIhEpAIip+TgAdggAbVxXQ0baezVNp4BuyhRA4QA2qfbVsT9+tu4A1oYH+PQP7JeK91S17/U7JUA/kwDYB3DEbB2mwlEDxz8QQDURABsVDi+z1h1NGEOH+p/iQNojeB5Q3E4NJ7D6n6DYqsHZ6BEG/l5K9PwYtn5N8+t6lTPVS1EZ+nH/TxuGfv/BDRv90c7omAP9jAL2pLQ5lwQABgB4HVOSz1/KDgCiP8cUAHwsrcgan60EXlEA9ATYBf5NBWEE6MtePlcXPJ79HuWg2PxJAFg1hrHHdEoCK2/GfodnFalbCTIgGL2J5YCkoACpAXSRJaSyGQP9jvZg4O7sIMDfHGgzgQHwPGUIb1idOElD2TuwBxjBmxkgACLwW2i0CWCXmAPKWwCkADYq0t/7jPvXr4+W9wC27fvIDo9YdwBryAP8mY0Io5xXY959FJDfCX7EWgXsoGglngSoYYtbgFp7UDC+zppuDxEBNGE8MOw+oTCeSQslWFDlQALVfzgcp6ofgz/F+jQrhqHo5Yme4jK9L6P1GROTN28EHfCfGoublhv9IAEWf+LXH7M9V6yDWcwEUVI7V3O8CJjLCRogFLPigKCAXOF/KAA8+isEAHxrQeK/uDqR9XgqKj3qXif+l6w5v7HRMqUeYK7AMuNjFG7WSSQAHDB+sd7ZGbQrARnhBtIa/Pdd94eZDMA0BVYODOHtoNOw/Xf0nOkAAjhJBNDYGhmKYAwIdQAYAfAwYMI/rtpqn2oTAMUB37poZwGySPB7WanJlIn1KIA15AFI4GeEB3ArACKAy3WqfIH49IYuYQF4EaDWMSocj5o0UixApKmdCKA9Eg6T8wf8J9oSlBEaCsdg8w9I9L8zcyoNL3/7dp8q3lhVHI/7aPXToyNncaQGIIahPwbot15d+R9v8h/Isz1XiIC93hTtrwvPXxK6pQLghqDAqgNSAOSc/QCHHCisPC3k+HcXmAgg+Dd7Fyo8VR7V89iJ9CXr68pUspFv//jhHOI/j//I4V+8d5yLGLICI6PTE0Yf3hy2GwJuMtAVQ5vgWULcMnV/HhfDAmhkWIhOWYEj6AHtT2cuGlspsb2JjwajLMBdu+Q9QHyD3+DhjE/lRUBfeuIWDwNzVQB+6rFvAmvrDmANeYAqn1cQgL++P+DGP/MAkxQdxLeILVIBcA9QyySA8ACHGjEP8DYfDnI7MkQEEGbuH+z/mZ74593AK71HaAARRvoZ2OpX5b0+1RGcAU9rhlY/+WA8COh3bP6ziH5S1K8ywCHdaOAleI5F88kmyuz0qadWc7h154rSyaMgKDiqgEW7GVAsLwqSAMiJFiJ7uvjyuZ6t8lRUeJQDS6YD/otLi7uTyWqnJCAK4FYAZYCkAJABwAH7mnUDrwtQipCLAliBUE8aoAMeXbXrJkeiMRqlEubzAnp6em6H4RPw74nTQyeG2FFgRgBsHBAfCr6HtQDZ8kiGV8VN4Lcl/OnDm/dtAaBq6w5gLfUB/JwAwGZr8xteJwHm/fbIKJ+nunaPgwC4B2ASgIRmK6IfA0FC+N7OCCCUOJfAI+zhnsQNdP58/NjHD+9lDb+qq8prFrn+vmNHr31y9yyO0kGksOM0uPljwY/hPy+2Vbm2Jo2tbtzlrX8ZKcSQWnd0NfcVFf9zNgcUS6Wiq9hfeO3D0tPlnKgA8AJgsfTt5mxFFb6lGiwH+hefLC1+X1EOW/myZdE7PTBjrCfI65nB7mB0dFtznYEVAVX8THAuMa8OoCnwGyJEgFFAACjgHI0MORNiJwPPhMLgASInboMEwBoAEgCbDEZngJkAYAVAxgC7na4rfc3ZA5Au4HBaGoB1B7CmPMCXmpfH1WV8xvQGVxuQXwns32mHxXi9DV1uAnAqACKAIWz6sVSg0FCkA/jgNHoAkKltPeFxMX8gEOj/9aTP8Gd86mvhryRhM9x85eGNbtz6Wzo7o+Is3Vg8L9Ffhi2LKYKlLYax3Sz7koM+nN2R0ZPH/rP61d9ZBZAsACG5VKYAXM0/UQIAA/APeQoQbUKx8N1E1ltRgS07Zbv0+AD/xUXEv77ln+7d37TKyEDIAF7UbAkGW8YfTN9jSgB/Cmk/MAAumSOgAyfoV+b78SdJNBqNsyFreEPwv+xd309TWR4PyK2390pH1+vQdsBEGCGO4zah/DIEsJBZSiNTpRODSDK6CYvrJss8uNVkXSe70U4yJcoDwd0HZ+rsgIqE+GCy8zBuwu6+7WvtLdOxcqVKYcjuOsEQfGD2fL/nnHtPC39B09PS0kJKy72fz/l8f0d90SgEBL0eb08g7Pd0YZ1mF0sA4r0Aa4Xt3+0qF8YYqFU3IAvgkDgSeN++M6ftkpUwUswCKqT19V9lu84y7RKxYcsNaNoAMCTQlABl9t3v1Lo4AbipAgAGOEnbAhBTk9YCeDx+CAT6O7EEIBqCUJVvrp/NId7pGJyJOZ0J2c46ZZqw5+AfclZN/+EqQX8fgT8hAK79b85STPNd1FwTWVMGZP02p9I0QR8aLD6YXVjCYb/tWlxf2/zxx6c56TxWuc9W8JtJgIsvEP/M9Cc2wHqNirOItHZnSQPnILL547Va0sq7t27/QbhmuBAgpsDc1Pg4Tgwfx9gg5AidABJoJ/8DJS7BUAPKAKo5fEiTVTU2fR70GcxIcEz9OmROCg6FAv7OCKQB+71dXWwOqIn/k1gHJOz/bld1mUgAW3sB4UAQVaaRGKKhnP/8vEgAhbM+/7tql/kZgDbAqVP9eakAxAbgg8LLwAZwCQKAZpLxUGA9TgpC/GMxUCQC+IcWAKBOv2S61TH4yYMYkf40xzeXAbC+1xk7N3P+FoCfLAv/HVOg/XPgJKAfbrgG+IekqO/DQ8OkAPLLB96j8761hNS8+R2hACHbf1UQACt56b8c/0QA8NKAlWdPl9f/q8hE+pMVl45kGP8Y6VSaXFPp6idaSR19Et9o0IoCCAEB+DGxBLCGedzkAEoC0FaY/C9g86cEYKkAGbKEErunPx6maYIfzoUYBVwKXQp3RkABQB1APbP7K/BCu/8iATD1T46iu1HAvy7dtdoBmz7AQ/v2JqiVCH+7smgBFJQbEGwAnTWuVSYd/Rb84Wa4BecDJLACB00A7SAPA/J84Hc4A7BcQI8n4ic3fhqThhLAqC903Pf7UQb/h82Q5Q9nmy6x0yqJtbGypA4NDVXe+ej8aB9DP2OAE7BJjojw32JbW1YAQG5AUdQmCMQZfMGz6bfngQIkXUvEa17/9J1Z9CO4AXNyAgUSWF1cfLHCrYOVlY21SiVpLwP4S+rB5/wvG2myUguphWq1XWuwdnr6loMU/ezZIL0DbyahAEwPokIAEwVhAjIxByZjoIZg6hjwANyYFEB0QCI2/VtKAV9eCnEJgLUAfCw49/ybDkAqAFzcAHC7S6yeqrKCE8HEXkBgBJy5nKQHCkYCOs8VYwAFRQBfx5J8J5YTb53NLQhkJYEPnLQIF2/2ogkAAgD2D4sAsCioHlsE+qH+xOvviYR7EP4E/4HZDyn+z7YNKQmzSS6cU0gAdOvXmh/cGO1raelrvWWCH+z/Dtz9jUyuG010q1sMQLdVl/JEOgLgovAnJjlyQPd+O6GAhK5piWTl2uazp09Zpv+r1eU8DSAqAKgOXlxcpTyx8uyn1/9R4UMQQiyV5d6XJvGkAP7ka+GgqmkHmHeSvs0MB74l/7P0rYJQyd6H1IApRgKMA9ApMH7vCpAApAlYzkCJzRrSiNKZPIsUMPrIRxkgCunXSAAs9efdkwz+WwUAOX45LkA6EexuXhDwI2oBMAIoxgAKzAb4m8JtAN3ufLiT9wSkPgAaB/hUki0CsLldggJw1zIbgAUCujzE8g9HoFc4DKMMhMO+qC96PPBtC7X+H1YOaZrYHhcjkHICEn2mr11lO78If7L1d4yM3c+mjDzsm2QQ3KoBsoZbiatvZzIc/sgAQAF1S0mkAN2uJ+er1jaXCQdgiG91JV/2rwj4X/3hh0VE//Lm6+ZKVWEolPTehozJM6j+0wvp7iXNZnuf4ZtSEr/QwEUmK1zxOSM7e/PPIyMduQsThlsJCRy6HUcOEKqG2Ag0u1OacTAGoMOCO3t8gU4wwTys+wcXACdZN2DL/0cO4V7BAkhq13K7gbI0oF0JiWs1qb1oARRcHIDn3uqa81yLqADMVIA2NicYOMDe6OIuQEoAoAAGqAToAvBHwpiD6oX6f7r/hwJzFP6D55zJ3KCfDp30VSdB/2ejBPzHjo3yaH/HFB+bffPCLBjy+fBHSb3FFuBGQKqayOU9FJkp80Jexni5NB9PEAbQy+bn5+01a+sby99/v4KlQts6AaE1COz/q8urG+trVe2qypKW5LjU22BkKcukUqk03f9Tdb22XSUHzMhkViQANAOC7PtshisW/BwTs/cvjAksMEIVASscuntHGzLTBTFLisZPNNk5eQoY4NZjYACcvRQNgAvW7+2iLkBuALBm4LUC/qtLRRcgWgD58wDOXE4wCwASxtuKFkCB2QB/qTFdQLKkferIxT90BsN0YD4ksMy+wy0ul8AAFdgQ1BsOR731XRCHAgbwRUPRe5j2t/OXleR18tr5y0nnUGzy4nhfXysDP1H8I2MXfnddSKHPsfzZxhm0dDSsX5i/wDbd1H6yWy6lM1QA0EVlgPHzPfMJIgKwv0hCjVfWtL3e3OCBgFevll8tw3WZ3r96Qb7+t/Fmfa2timz9T2jfDjBZ9KWXQCgZCn8q/xfSqYbDtl2lB6wYxHbpSoJ3IC+aOTFxHQYjwTxEXEgCUx1YQIwcYLUOkNjwUZvSDLMdd/Y/DkCHoCgUCENfZm/EQ62yerr900YgJ2uZ+x8JoFGWrfkwyqE/3vj4xpX8kYC3LQtAcxZHAhaeDeA054NozhlHLv6HMRXgbExmAzghGnDQZboABScAWRWIfyAAf5fHT8Afhi6gocA9DP7v/JcKOYVY2yv4/Nvv3L0qpvh3jN2cvW4i/2g2P5U+m7ejZk0rgEfYuAZwS6p6uC7DCMDgHEC+jO4jh3VwBtoBzZoeTya1n32w9nr9zcYqIQAWIaQyYOMNwf4Hb2k62Qdp0E+DucPxkv11po+R4p9SQNOu0h07GtibMCjag+wmyC2ATJCZA9nMNv5MfA6I4CYVBMwzgE0Ebqs0V5BnCmrkgU2pGsR/8eMAtguPRgNQC0gOBTECoC0QmwY4QAcC1/Ltn6xyoRkoLQS8mN8M9LRNQgLAo1aMARSeDfDNF9aAEKX5VK4TcJi6AScVm5kLIJfnKQBsFUpOLiQAbwQGA0ASOm1V5/OFAf/9DscMVPuQbUtwATidtw/dOyagf3zs/vUteDiaZ/Mz/Jhmdc4dz7YHP4BLluL2JsMUACkM0CMNGOmG/e8hB2g6koBd1ufnyYle09a8dm6NLfJNW5XNrtuT0J1EI5a9DQuW7CW9Td1GBgUFvDxiH5x/qed7Smy28joxByGYW7JAeYCTQe7un8t18NOJ2QtjaBNQY+BY64kbpxsVJcEoQKNqoEyJ/QZMtZZHgRBOCgj3EPyTg1HxbhcUZgH+BwQLAJkbjl61zeoGmpMGLA4ESujcApCLvYAK0QaoSpoSQFI/cVjoRwWAbsAFwkDUAAAgAElEQVTzapmVD2yrFhnA9AIOUALwUgLwdkILwEAg2jlHS36nh2QNOAbOWhygBdW9F3lt/9RVTPG/nrsfHt2OAizAI4ayQcu4tn6OPzGabGSrXnpuiOhPs6uRet7gKtfBra6BErDZSgDdejKRSCTZIt/FCT/YSkttGvn80CEZwL/nQHcqk7F0BUM/2f9f9pKXaFzIQpUi4P44FwLsG3JvbLEEtg9o8sSCTHYWQwQdLEegtXX84nRMVYSiQXJRYoNYI/gIh4UQ24tKgPoKD7RmqCAHh3cCpAKAKYBGO0vwwLbPkATw2Zk8AvgVTwIoxgAKVQL827QBYE6ww4wCMAZoIQTQ/0HSIgB5t6gAWDLgADm9KlgjEPA/RWgTYF/nt9BnxOF4MEQ2rXapXab4j6vtk1fI5k9TfCATZmpudtvw/lFxgzSBw7bRLJfYZvyPWQHM1+7ZTZhmR1Pa4AzAhTqVAUb6ZW1jKRH3skbUfWkJzeq3FnlUSh9rABFdLju81FSXBunPXpACn3yRC5H/JVq75DayiH6DSQBEPzxjBA0xM4l+AtQAE9sZARnLd5CdhepBxgDjx/r6/nT3jpYzX8imxMAP4LgV7aEtAoEBCAHUY4dQZgCwWQA0AIhrB8vvgGb/6m3oBHAtD//7LuuWC1Cq/KpoARSeBPjmC5mXemhqzWB/jgUwPIgVqDNKqWUDlKAEqBZtADi9BioY/LEFIM4B8HX+n72re2krzcPrx9HkHM3qNq1HnRHMmEqrSUCjFYZ2XaUklmitlmKDsPTi6DALu70ow1zsdjrDOoXd4nohBhZK7S62Wy1SBtnZmW1ZuvRih701xhI4nBOC8c/Y9/d7P0/UdvY25E0a40eq0TzP+zy/9/fxaiQg8K/ht0AHa1jnIOwnjf+ztcP3Lwl/Dvirqvi/6okO4GecEBEB2lA87+K2zxkAA/bIAUUiBCKl8/79HHH4FPBBegHBX4ukQHQBWW/PlyLxAmz9Ltf8FPt4dex8tEQYrqmtiPs/p4AUxT7d+l0qAqQwQBo4DvyC0IRY2F75DWeA1czMyKOgsbubVeqFzYeQaN149zPoEEgkALQIHYRTWSIE6AGAKgDoGhKxXSCA0xACvL5QNhLwoZoEUJ0IVoH4/8mfv9eVMOCLgHQAyAA0DNigeABfGOEfggurCOxMExJAw5nEEoCvaRHAxE4GS3+eW+AvLsEr9VJQNzRDtzZmBPxFhv+Pgf/R+l9lP70qd3/GC266WdOyvo4EO6WXet3Os6NBgs/CwXBpsu9t/T5RxDll+Yjh8b893zdZau0/KNgi4OcQwOOV3RD4O5Ga7K4vVDgU4Kao57u+9wPkLnxf+QUnPCvVLCw9e8IboWUebJi6rn9gaD5eQV1vbmCpxaPkFd4leBBrgcgV9/90J6sDlHkcp/z1YtBSjnUCKFMAN2v2cpIA/lUVAJXoAX4wRbV30Lw1N+dVAPM0DGjUSgI41cHgjx7gLJ0XQlRAT9s4uIDYIJ8E9NkDNAAvLB9HP3EZFy+YWV03r7NpGU8+XTo8/L/gn+KhNB5NU/wAftgTKYiGglndrE3beYF/xxEagB0OQhavEz3oHj7T2lUqlSZhkbddrZHh4e6o46BhyPNHOyoDUBbo7tP13b5u95CjvcjupBDsBOsIdYZ+6gbwFOE4CjiJ69a2V1anp4ltGr1ukN/g+pfPd5Wm4tYmZFo3vk6CBJiY+DoJLRppP3Aao2GNwCn4yd8uXCsFgN/Y+PLe8j04A1zwzAPZYxbAp/mMy9UkgIrUAFASKKIA2q8D3hgA9QC3jbeSABpCsDrgHxsR1IkqoKenZwCS0AexDGDiSvJvsP833jZFewuf37yYeWoZZP/yLxPvDym+PxL+rnI5uml67UGxKNJwiQiIt+imqfd1AwWgW2eotXk4QDknsNlnC2TxL+J23zlhEfi36JYZbC0o8KewLwrY8/0+JZ9GSq1UOGm56jN0CQfgIIWQqZvW5siNp5ohOymZL7Bd0CvCADAlgBcDIwGkaStQyAJm+A91tEgH4PftYR3QufIQwJAaAvxnNQRYkQSAJYEM/0Fza8SjABbn6aDgC3uKBxjqCDEO4ATQycqC22A8IBLA2JXkSzwAmF83/PJFeuvB6Fcfku3LMNufrKwQ8X+sBfbu/C4H0bso4KoSVxMMQO/bnbWWZekt/Y4AOPPuPHz/PoSf9CkgiUR/n2lZ2XBv8ZAjViUr/OFTrvIkxD+kgNn3UYCHDpCMlnagU5J+fy4zdeeSKRhgb/cL4OqRPyZhTABUA7OhAG0YoqERgLMYAkD9BiFA1uotaDxcZiFAqQHIm5u+nCwErKYBVygBQEmgmA5vPFyc85wDLs7P0WxARQLUhfjiI0KAA9Lpa0QCjNO5gGMTyZ05DABetPyi2N+6tbp6d/T3OlGwhrHz6dLSscdfQgK77KjdFfih95nH5rF1EVYTTHBY5E2DKCTHOjSLqIDm4YTtBTZlAYddTkY6XwkP+gn+o2eaCPz15v68+KG4+ndVp8+MAD6JFOUEnkbk8kIF+cii+p7yH9K19m8iAMzmr6Yyman7l3TOAH7zMtq1zODYxFgyRgmAKYBrqADOshogxP+Q+HsGg0FaB4QhwIXT4ubcY8PnqyYBVH4qwEf7bASoH7oCBJREQAgCoAe48ZFfaQ02JPDPx4SiAiAmoG2czgVNjiWhAHiucQvwz4pYzMdo+x88Jgxg6MM4xMdzCCawj5ZbwF9lAa4DCJauinBbURy7q1TAmnPiIwdDPqI79LrWXukBynSA6urfgfsEfRdMQiLe0WASYqmL2EVm6Hn8T/6kcudH3DMKkOindQrqkz02NOi6ggDXwuSbWo8zM+Qy9ctLhjgKsLawZfDr2FgSh4IIBUAPAWkfUHQAZDUpBJCruXNv+d4dhnxGAQuYBOCrJgFU/PrDf3UxA9ivb8yVeQCYVBlo3NKFBKj3NYU8DMAkwDWMAhD8gwKIvcT2tW8sLGSl+v8CHZE3uuzXsoZRVzwuzsdC7bKEJ3+UBrzuOqUKgvLYwGGRP6o3FMxm9WxDKF4ok/fsMM8L/4QX9vwjeFNwEoWCE+0f0qBSt+ZMgeOzyLZy+lOm+A3B+yyN/LvK1j9Lnt1s3v0FSycSQUqWpsCet8dN4C+naO8B61yfyXxMLlO/0wUDaNZtbBu8E0vSzV8ogE6wAKIKGDRAWOHzoL5B8A9lANwDIA+c+1zLCQVgrFdHglasBPjmrzwWRP7eNV+MqBJgHsOAOCNI9AXxKRKgXZEA6Z50z0AMFcDgDlYAz3+gYyH7HqEAY/3R9OoTHJHZsU9EgXGgNMnj2GfF+xL+bl71AR4KUKICQgW4TBhwcSC2XqSAhixZey2RXn6GR/EvTED5ls8x7/koxgcLB2eas4DD5k4Gf1dqAL7VM7RL/yLYiH5CUJysJihbmKugwp98fTFCvq/59nVmFIqmM1NPTZlc/VP8W2VwNJiiAOAUMA0EIEIAoWa/sjRsBsqdv1AADw3WMhb+62+rDqByw4Df79Vjc3iUAFsBjwVgYcDGDaMBp3PDCybXFAqH4KpMCoYgQLqnjRPAXRQAG5Zvlza00ozg8ujPYUQu4YDv9iEbqMT6ZbDguVysaIcH6MutgAIpSQEpNUpYlHyikka+t72J8FF2tzY83FtwbEUEHBPpU4Evdn+yyG1vBDd/U2vpt4XIKNMo8s5skVFBigF/VlCdLFKw88fgHznAVXZ/uNpN4ACGiZIaHc0QBpjZsmSQZRPHB70eH4yJ0aDsFIDmALYzC+ARADQE+FSEABkJ3KzVhAPQjP9UQ4CVywA/0DAgegDtQ8gGXFQZAMOAb/R6kQ0EEiAMBBASY0LbzwIBpKEtKGGA2EvsAAAGgLW11fTfjq7icMyVZ3/a7vOTF5W/wBPe5F4t5b+yXK9DPsoCqbLjAbcck/wh+UR6Etr47uZqwpGDgs13f68FSDge7CfUO8T4R8JB6NSVreuI5z3wTylX+i47AUi5ni+iT3RWeaLK7u8NS1IGUKjRtruJ8rDqi2vPpqFlyujHmcwti88P0KxPGqFZ6A4wwHiMTganCkAkAeNf7ZQqAIzTohPIghABkAQgzgA148JfqgKggsOAdEogKwt7EVj0MAANAwYuGw3iJZNrDlEGoBKAdQYgFgC6AvYODn6dAfwv/kz3sb7WmrkBGf9EAKysHS5tR/ZhxkRE5M3JV3gZ9iUHeISAPECTVFAecjueAlw73tpSC3V9ubrJ1uF4tED7+JSf7yWUjZ/bgEQ0Hin1+bBFV224v0APGtx3rVQ5PfAAgEf8K+inRCQYCe+LskP8KUMoAA7z9rPpVSSAqbvrOPkEQi365Rvwm1+N9aICGI8NjA/0pJkBEDkAoVCtIgD2Tt3HTiALwv/Tt546oL9X04ArOQz4LaYDs/lQF29IBwACAMOAjdAXRJ4E1ocFAbD2cigBetow+2QAI4CBTUtD/OvZXX39Ech/YgC2yXa35tT7cppRYwv8F98F//JggAdUXl/t3W35g/JeDijEu1pqaHF/Q9Nka3dvwmHd/Nj+Xzh6DkCw3zXZ5EPfr9WE01GX9iJ/J/JTR4lgloX/lGpCwQCOwL90JTZPRmL84ERrCf4123Vt5/UqY4D7Wd4zOGg9H5kLjAReDaAEwExAIIBO2gmQ4b+jxSMANvk4kAWpABZOf85Hs4K4qCYBVLYE+AeOCKI2wK+/CSx6PQBKgMV1pSYwdyoUDlMPICQAI4B4LP7dDKQAfKIb0M7WMLKGYT6dfoIGYBvzaIslaAamD3vsfxn8bXbxaID8iZts0eMPJPrZY9QHku9ZGD872YQUoOV8DXUtpdbh/u7ugwQE+BOJQgFucUWj8e5IV2myzq/tZnU9q9UMtfckXZg7SEeACVzPcnSr4qRcBiju3y3b/5kJOf40kmchO/YZnRBAFzYhy6+sTlMG2LRyYnTIr0bmRkZm/sfe1fy0cebhDckkM2PMuhsXBmirQjFoBaaSFzeWog0ZRZEVVKIKVpbrckiqBSJVSnrIIYe0S3LpJWJzQEEbKQrRFvJVRY2U1SrZRqt0e+ndX9VIo5lRFPpn7Pv7vd9jk/QMfjHD2BhkwzzP+/y+n56gJkAu1zcCSUAq/oeH93NTzjTTjY2LrBPI0tuqArhVb7DGrVWjkwSwy9fNZ3U2IY5cEfbZslQAigSA9sBCAnRlqBNgOE4ARAIM3YMMoNK7Dm1lSwyAxUtriP/p+/Q6DsfgwqolPc1Z1wp+X+UAtbtf+DqIaYEEnmmj/SQ28Z2sDCcPQkuAY9hut9Ewu1LbypqdnR0f7+5K84a8VWN/vh+aAXD0t6MjueYlMagU4YWu4DrXk5WFanERskDEPwQDoBRJEgKoFfFvFYRbWBt0dO7au46oC9wkAqBw6F4OFQDOBK5UBvkkEMoA+QOyE1BajANZkhSwtIQuQDGwpVMHtMsXDArmBGAa1S8L0AuEM8AC8wIspLW2ABkqAZAC4Ag+gJFcburDiSenyz3lQ9/RFAAYaeFsoPd/a/oFt7e9WYhe21Nq626ZlS9c4p5StcO7+XgiSag9Gch9X6iGGBUwtwEIgT/9OJpJpqu1Wo2BXPYDadJXX6uRW804mMxkp6KQTh1Gy5+9GHDmzYtfDmh38dNjB4UNNJnjemo3Eb75B5HP0wz9KKAfXAPglwkiQxZnPfpXCZ5sgQZYP3r6KwcirSgC7HOHCAMUnuRoDHAEugEprcDhf9UtW4GljYO0DEBk/9CvWAfE8W9/0KkD2uU2wLd/ECMAsS/IshQAyABYEPBA9QLs5xIAGICc9yMBDMF0kNswtu4LlgIAIHJ++GTrAiiAkGfceUNQyGZvi76aoQp/3mGXc4AiAjyBLVfJpuMgcwXy50PNdyAlgcyvYfm3YfBqZCC/zyQsQOx7u0bJIJEA3NcQ+4eHe3Hjl5VJLDjpSReDG/KdPQy1g8f3/JC9dMoZMvYv7f2I1xfgxq9yQMS1QZQhL9GZ8AJawhA9ugAMcHR9btMxq0gAafsIMQHKPVdzNAaIE8H5NBDE/0BeZH2AALizsrK6cldJAqZWQHdTEQCdOqBd7wb8jxwBmE5snCkt625ATDA5b1hqSRBKAMoBggD6cicqz3H49wMUADQ2tfkJ2v9bN3j/DHI5jxMJULUmw5cvNfOfS389Fu7H4wGMMMQ2rO70nqd0Ag3178gUu1B4H9AeiCanRkYHMvlUkq/xVJ68q0puLGAzSX7VMhWZUTKv6wvOMR5HvniGgn5PYzrm7EO8o+BH3CPso0hTAeTemGXbtlUMuHeweH+a+gGubiR4i7DF7w+VC+XCkz4kgL4REAByFtAAFwDcBLh7hboAlQgg+bjT5EVA5N/0z04McNdLgMdpEeQ3oT2wRD8qgAWoNe85m4hLAMoAmTwjgL6h3NCJa4D/80YCwU9uNhoA01vTjwJfpNz7vXDBJrK+91Kx/nXwB20ZgBsLyhbv8r1fTSDWmgG3fieWTsCG9ITCK+fSaUK/6q15RDqOwiiuvO9yiwAUiG59sIMrXlXM+kd8k9sp/DpD72gUAOe9BP/2dqCYBX8HK2D9+Nxl4QWwNxaIBCh8fYIRwIjEfz/4APKyEaCZrhMBsLJy8W0tCWBpiRcC0wTDTiugXY//92/+qy6ui7R9UjoBKf4XcPrEOSITTJN7kFOoAOAzn89AIgCaAEQAlEqlMuQA4v5PBCSLALzQUm5fNYgRUB2PAsX95+sxcZEL48ciAoIBNIh7sf7fKmGo4kE5hkp9YfvuPNpj8QQ+V0tYVhWIZCmNqjzlR/nbnGE2f8SOEZX/8pOd4GkSCGBIxin96OMt9AMcv3bEkUVBPSABnvd9mIOpAJX+fkUBDA90Q9KnaAJz98qKHAgqsoAvWabMArI7McDdzwB/fWwriX72T+WYAkAJUD5ZtywzLgEyhACGKQFM5EZy12DE8Dmn3mCuc2cTMwAvXA/1/S6FmnUq8DgBtMJfKdej8PeZ98yNZwkoCYTtMgnmqfQOPU/ngJYUw5ehUs+r1xqocYpQ5xy2t+s5zApFzXvaQ67Hwhs8A4nrfobytgtZYCpRs+19k7RfCW1ZUnyE04PWjq6KmoDqsb/1lIkEyNEBgWwUAB8HkBHtXwwDxgGRtfpHtQ8gCIBbTTG73bSfdWKAe4AB/vGsKSSA5WyW4zYAHxIkCYB6AchCY5kQQHZkJJelAuDsokldgIadvkdDgDd4wb1Pa+nRBrDf8gOWFaO27OTF+TIThnGA68stlOppeqa61l0OTLdtUpHbIg1ibQe0UoPW+L3221wm6l0vvsULlnC5naIQl8z8h/dHkHyqHd5bCWDbQQtAeQL5e76YppNEWUYwDQUSM6zwvAJOwApvA8J8AEkxDswwTfvyFeYC1CmgG9NCKQM4/+sIgL3gBvzZ7uItIq16+nyZxwCYAsCSoOUPmpbmBYCVT6EF0DtaqUxMgABYLv9k11kI0HCW0AC4cF9imm56r6BRSDUZBaJtt+8p8Fdy4siaiYUD4stVq4c0dLvtsB+2rzTwXhPa31lfKB4HxkohJyLBQTEucunbmeFkGPEv0WtWEE0eIPhPTEA1snxy8eMLMFFt7eg9WRhsf95TKhW+7oMgAA0B0GGu4AMQAsAUAuAzFfxwuGNSEwA7DXVigHsjFeDbDToF2KITAlpsAJQA3zkHZLzQQgmQZwQwmq1Uch8RAbC8XDrrmCwFAHOAZQaAUABBUJxNGA2jPkQkgBYSV6rzfYyL+5EWEPBb4LQTI/zmFbYtO1KDjF4Ytm7x7SjAa6MvtMddjepo2D9680IBkAUPwL4xzFXk8I8CiATAmnuwKFuvFYghVng+2FepjIpewEgDUgCYhmU/vEIIIDYQlJBAngmATi/APRUJdLgCMK3ExkKJoZ/hn3oBFn7flPg3u6kASKELoHew8lFf5SohgDIkAScwll51Lh9XIoCBogCCbKLRMBPbMFKTDddUfH/o4EIFwOE/w7zzvoZx9w3A99/MDiycr2YPtmQUhi1uR1d3Rno7soPX8op8ZbJA9Bu2fr6K49DVaLtI8F/k8Mez6zgyYP3qO2JikHOOSoAKEABUArB57kQAKAOBjY1VIIC/xAcCXqLbgIkK4J1OJ5C94QT43eNjFicA03K+L2sK4AyRAFDh/9DpEmEAlAAE/5QABivZkezT0yVCAKwNAOD/1hp2ALgfaF03I2oDNMkW88sk9NX3taCY7L0N0XFMiGXg5zLAZSCiAI8JbVeDfzx+8EY1EHqtUcP2Fr7qj2jLP/FHXbT+aQRgBgUA8/3vgHhakUAlQDEYqhMBYExE4jF4Anw8wTHia3OfLRqsUbjzZ2js1PN8FAoBs7wbODkeNiT+LftBGwFA1q3mAe4CgHEgHXDsDQa4+W/RGqxhJY4I9HMJsEwlgCmdAOZ+MAAOpzJAAMQCmBi9DQLg82qClgFWDecHTAG47vnK7s/iXsUUSIB6llzcFNdP1Rq4iKIfTADASqSlBfmePDBN4Lbf530+EzDGAm473McoQDsPX2NshDvYHK5+7sc9nZjwrwOeb+pFdlfs8uSwTfDvJMcEKeDT8fACJcBxqAsGqx2S974plEqn139EBhhEBsCcbctQBcA3K+0EwKdd7CrAocCdGOCe8QI8xjA/3x2+Ki/IVGCQAGdw+tRD54Al/Ugpgn9OANkKEwAPFs16lXYBuIM1AFuPIllyHwXc4/VWglxg9dmiYADp+acGAM+Jp3ZAxPfNGV9aDJ7IEfDV+kFXabTDlIIrJoPGnruzVR++0b+wA+zduCyhTCUKnFz2brnzLxJwV2HNFAA+HhSjsV/ABfBecXKSEoB8RnF+i44OvbvYqFMR4ByBzo6nV/v5RLABLNqQAqAB/R+vrPIkIHXdaQoTwLQ7dYB7Z9GaQE4AZ8ssD1g4AZYPoQQwFALYBwIgPwxRwOzgxOgKEQClL9K2ST2AVWcVCeBFvN1GhHlvUxZcq9YQeLKUzZ/f6O7oMzdgpKkAhBD40mc8aREgvl1FG4C7Xb1LH5DCgOrxNjDWc4faEMFO/gdfuXksbkmDl34szxkiAKdU/a8DX4Kf7fbFqLeesG1rQhAAfQp8BpP3odXi2rW1Ww7BP5ruixchHjv3tH9wNIteQBzkcFDu/2aj6yJvBKALAEgVpnkChmH/t+MC3DM2wPs/O6D72OVhfFnWAoEoAaA/sBwnTHgimYIsgOH3wATo/RQFAPaoq9ahCniTNgG8UeS7vshyD+Cank2Qy7WOXq0gUIOEgbCOgRsiWhcbzEhvgE4FzBDgesCVO72AnFJfTH9AMAa3EVyxd7c3+lXHgh/3LnLFIU8ot0jV73LR4koLQNn/BdyjYlE95yRQLE7OJhI1e3ZsEpbGEuR7AR0cSCRAk3sBThL8r5dvj47yOOD/2bu61zayK46TjCOPkqxFNkZxGoNs7CFZeV468QaWluihDBpw6EIx2UQPoqydgl/6sA95CMrWBBaKCHkwiC0kdprGa7JpWYr7kSXeNgt9KH2VRyqGYaqH8b/Rez7ux4wU0z5L144UfSSW5Ht+53d+59xzBACcN+x/As8B9ysAV551GeGRSIxygEOEAF8+70LgRwzRfkmlAJoB1FEFqP/YYgQAIfAEAsD0dGHh0u3Co+t3V1bgGKAVhmG+nT/YRQXwbU8Wu5qat3Bii7BZw5MJttpMNewnphD5ruP21Nl4igSq/X0zI40Bh8rlVyLD/Phu6YoPGScODVuOjssPHpNaqPRL/IeH/JPkTcn+K3o8aZzx/+Kdkj/XzUgUAwAT90unrHbemkL7Nx5gBPgDTlzYFBSgyyrAKg56vXllmkMAaAVqEoDciYdZAkBngiUByNE0gBEADJEK8JciAkAXAMDiYiApAkAiACnAS0UBQCs6cw0YwMWLU7cXvm8pAhCG7bADBADWnh8b1W3S+sW2TcZCgIAlsb3BzF9j7P+aj8NChkxYhQOPUYU8IgGkCYOeFAMkB6hIG89wfsP+U7E/26fCjAq33Tq2hEAF8hXl7FUt4mFFygwVZe6MQtL3K9cfyAoAZf/ClB0H3ikZveuncaAHtH9GWHX+qscAkLJ/13d7jxEBgAIg/IZWcQ6GPN3cwJmgJAKc11MgZSOQgQRAFQrZc78d2f8wUYA/Wl0aBguRABUDGZUAdUoEPGjLVDKkAscn5+dFBFBYuD372c27d5kAWGG7E76/SwqAH2dqW2O5cecBANpHsKX1rG0OAMQfF6zCJQRgFhD1ZBffVHWAti+D+quA+1BGCmk+YDppLSIcV0cUHQ7gEmlZUROSKPvS1OuNBY2RTIgVQMdBBDC9v0kCXN+5CnEVfFTEFUz3Lz4ihyjAjeaTIn78kgK0ru9PLywUkALMj6szQOIXd/KhGgeWWue76qBQbvXPoxzgcGUCv7PpEBgAQLi9vpLWAes1HEL/gikAHgzKnZ0/giGhlwrft1oCAJgAWOFE8YKw/42dnf/4qUS3H7OPExt3qWNZnfCERxSgl5UKwSYkAhAJAAhQJUKxeWJYW1pFfuv7gmx7AZ1ByHYeiaJBgl8/h5CWX0kBieYb8BJMv69fhq5zUh+J7yIAOOzPwaWnQEB8BIvQnG9iCTmRm8EIAAX/8WaDKAASgLBtFd/DOY/Njy/ScSDqBS4BILw3kADcMQlA+IPfj3KAQ5YJzPMpUACB4qtbuiWIMP86qABi/dJWB4KwOyBqgLdn3qzUWnfrkIpuC/vP5be3draQAKQlbop4ad8mV6HrZDjlo5GbEAB4gFbhkuglSYDslBfEEccDYFbBwJkalf6bhxIbKqkAAQ/nVFSmbiD1T9EEFQ1oOZHyEtL4j1v4RoJYl/OCACDeasIIYFi2sn93GZTVDzyXIdF8DpKCZA9FgBZQALD/dr69+goowE2gAAAAs+MGAOS2kQDc6SMAkx0NAKNGAMOXCVGjOX0AACAASURBVPxOI0DOvlxb0faPEFC/BTO/mQJwX9lJBIDC900YIfBq1YLGeqHVse8LAiAQ4NA3zF9eu7xtj6DvRH6ZdK1YYwDGAEQACAO49C1iIgDPCXQLffKuQZSSBqJowO2+FQySE9m+jVoCM6VwGKUDCK1BRO/6aYE66QCvvpoqAJT2T0EAGrfLX5oAeOMg7c84ihSl7R8+pLcAAEwBwP7bxe0aUYACAsCk0QhoIiQFYK2fAEidQLDA56MioKGjAH99OmF15Eho+xuTAtRrTAFO//x9rQFM5MZmRQhwaearFXjOXDEHe6+dsz8kAvDGyQa2yAAYAMqgN1inIAbgI24yNRbJuNh1TQSgdnkB5wuqkQEBAwwuGGjm2XycacBs+ZFh+pkgv5KpPjIi/35YCSjjj40/6K8BlTmm+D++R6IArst+X+IAx/gFsP8TZXgKI6Kyfx8AIHG8vZ8KBGjeaM4VrXY+zLcP2qQC3NyfRQ1QDgMBdb9z4h0E4FpH64SjeYBDWArwm28FBUApEFpBUGcgdR6gzhTg3Ev7FAMA9gWYnr1YuNSoNeutV6uY/8tbVv7hpkCArcc911Sz5TUxe7Fvr1piQ+anfC5ukUdjY44AOAogn6dkBJIIsVYQ44AqFgnFkS4YjChfGEfykcGeeaC3zpQNmNG9fLyixcVjmH6gWxrERtd/eIvVSOv/0vwRAVzXNQgA/8X1nQ+gSfeylzgJokTiKveP/z7xkqT09oYAgOZH4neAddh5qzi3IihAa2MBTgFMqrgN+gBQL3DZBlgfA1IKgCAAo2kgQ4gAn/7tqSDlXWQBVqcIY8LMUqD6OqoAD7a7PEsMhoSMTU8vzNxv1evN9e2ixaPAnm1s7ezu7OyXfH+AsO24TFxnQ/H/QAzgk49XZYKxz6SYKK+jSAA3z5SpQhDUpaGjh5VFgzEjQqBuHx8LpOuKMmmCyEwqGCwiK/CzmydcMloaVPmmavavNVHXNRCAKIBCAEIBF4sABCAXElziyZ4jnT9+C1jwEq+KMmBTUIAQzmIqCvDR3vz07Ox4TrcC5F7gP8uY/4UL56nGA0TgidE0kKFcX35r5zrdTpcowIfUHNBgAIICCBLwdfGUqgUQFOBi4eONZh0IQJ7XwSMEgLdlz8/Es3iBrg72exn+j/a/PV8aONt/TwMAywBOigQwhZYsoKe6DUNIUCX/L8UCqiE0B24a7fgDTRkGxQn/z5InmZmVcFoz0LWNfdbf67nS/l2mAI50/WzbHAFApHSyjPYPNKDkKHaA/96DVXpzA1SA1leCAsBXvg21AK1Wc3dhef5MR9q/BacAiACsrckmIEwAKMGL8V/u6d8/HQHAEKoA/yyKX38Xv4gCqGpAYAD19RpQgPp21ygIHp9euC/sv9kQBIB66a++2NzaEgTg9ZGneCpvVwQAz3HZ550VW83KLxJGGK2ueton6i+GgFi3zoxVUgC0NXmOEC0f7qxiCTGBgh65x0eM1SDOKoUR8cA44B2ZhSDt+mUIQtWKarRPwFKFfFX4sqtx2v2b9p84Lqn+2r1jDgAAYNnzwP4FAHilRBo/VQF4JbHKPxQUoCEowE+KIZRiYyLgeqvV2NyfPZszJMCuUgDSFGDtGv1WSQD606gKeCiDgN/9wxbkX3AAy6QAmgHUV86du3X6a/uUPlZqjX0CBKAJBMA+sA/ExaMGEID9o0JJ+TK1X8VFySMGkLgzYa5j2UeywrWnaoUdcxkQkOmTozODFBIgFECMLadqBT1ZOGCM24xlMZ4Ei1jd979mDAzTJ0SJ1RX09lZDvdTxpyqF/nGW/psRAGh8yrPLT83xvTFg5QUwfmHqAgRKiUkAXBftv7S4v9kQq/WwGFIm0LK36yvNxtbjSzT6zTgF8DkRgDU1EgwIQI4YAh4DHvUCHtL1638JCkAhgEwEqEpAQQDqVAtQm1MFYwIAiveajXrjwXaxbdsCAaAT8JZYu4tHhbLapL66BgAgCpA4ZdxsV0kV9I1iQW376psqg/1038xqnEIA49yAMkLMGvSkpcdSIYg1D1C3BkGAmUpU3QliLS8qCOAC5ihl+HhHVd40G366hv93JQFIUnQJYdL1pxBly2D/XknQAK+cuKlVKuPytgABmtAiHAAAejK/BAB4ex5c+wSreyGOA0UCYHAAcXW5wwTAGp0DHmYK8DzsIAeAWoD8k5qhAsJah0TArdOv1IkAsV3ssc+bjeadVehabduCBnyBEcDr5ZnCkjtoCTcmLsHfJSfbVjufK7kZBPAdJ8MB5LWfIQExOdZqT7peOmZTxW89WSPoGaJALGfxyEu2fniWIRT0+OxRzwCJWIUQePdrzT168mfLFv9VOeOPdY2U//f1p2EEAAklAoyPCgSQZSgDFBEAEIBySYBAOXHMj9NhAJjaAx1wo/kZxAA4Lzi0ftHa2FzL64Ct0ynekwrAmpwGDBdX7skYAX/xIwIwxBQABsMTBOQOQAXQDECpAHef8KbC3rHFT5qNDSAAgv7b+eKPhPlvbb05mpmZWeQ8vrkEA6AYALb8EeQM7UXfQACfT8f0Y0BfRlCCgCwR4gtzrp40Q7J0nxV61uWyzEHOLjLqC3t0gbFFgHV8AYYY1TjLNSTYqFcgz0D2t/3ztYNXC80/ccxoCWuEXW8MTHmGlL5BAOCWlspLsKbebG40Njabz4rcHCxnv6g1die1YiNMe/sLHAfKY4DX1ESgJx3qCGeNCMCQU4D3YDIslwOGl2srNYMBrJMKcO70N3hsgJtH22d+1XoJBADif9t+uLMr1u1lAQAFVbpibtkyxQCw3xdDq31gH8mH1UF35x2L64JkpyzDqWJ3fbyI5ANwK5aPgBHu7fnK92e+iQ6Y4OKb5/HNSiaf+vKS+aufN7ivf6w1v7jf/F0nQwCSNLnH2oApGLKQWxTs3/PKAjv/y971vLZxpuG1LdnSTGoyjS20bDJ0WLpDImlyyHTiS3JwCWMX1EMJQmkMSQuxDYawhx5ySJVYGAJF6FQwXUiVpHUikhzCInbxrrRsTBZ22asseSkYo8Po39jv/X6+M3LS+Ox5NR2pqURrV8/zPe9vN48IgGZILAr/gpf59ClhgEbt22yPzwXY622UzmooYpvKLssUAMc/e9xJpPlIuHgb0DFPBPw3m+4nKbqhJfRFOaIAbi5BNVDpoia3R/WSt16sa1p3FxKAIAAI/MEBAALIi1y+SOmDecwHgO+9m+h2dS3noEA/vSAgFsjImIoF2qI0UA3H5dJfLNjZHyxSSC6KcvtFuWBvUPmiDRPIxCq+CAscHHRev24DeTXrzTq113X4OyJomsra7U6n9cs+n85Jx3rvL2I5Epl9cKA2/YXgj9BPf06R5ldOAPvhh8QB2J3Iu/TstwgDAAHI3yncgAAKYEbr+0b1abX2VVYs99UvNh7qM2gZ0Kk67QIC+CsKINcnqYRMFMY1AMdZAXz084d7NBLMJMDp2yUcAyAEQKuBplY5AdA5lNrMh7f4JGBdewYCoDMcmuADeBZy4gWCPSoBGLhzGvlIwpXfZz4Bw+YMEGAGEEFBJ0oBI7Y4iBy8AEG/Tf7DKyACDlQ1ruQBqhCan0PD4zT0PU/NkUfE6D8CmyttVpvtTmvfR1P638vw6W+P4h+Je/4bcs8RkaSdtCwW64ebF6jcCFwug3+hkCFOQKPaqDzYhSwO/X/TfdQFIgfwk0dfvw4C4O7yssA/44CzjxMJSQB97d+xADjuEoDPBSCS8XkZK4A18AJ4TxBLGNFYk55lg0D1JBMAr/8A6CcUkMkECPz8CQggYD6AYwIB9LzI2e5QRcwFQIA5AAmJKAMsHsID6pmAfhPmms419/2DA5RxRJ35vt9qTDMKmAa4T1EmEHdKDIwcBCGsVOudlu/474t+lftX6X/u/48QAEsNOPkE8QC0ITn5BQN4eVoRrJg1yFPwEzM+ffq0Ua3WtqQESOlsyBPjAO0xwf+DDXnus2dixZTaGhxHAI45Afzwrz0YCcvnA17+uoQ8AGCAtaW56fL0bT44mq+RZ10A3d7lDSCAa0WTKYCM6UaOb5spAC4BnDwMD9MMR8b5RLEgfoQ5QPQIyvmYEuKYBaJ0cODXAbrkKnV8LBAOUP0RedFZmXoPEyRBrFxpUw6YfwcNzPMpnm+Bv8C/G7g2FgDAB0afeAC6gRSA5wFR4PihxeAPDLBNJEC1sqrzIECS0Tib8ZlKTm7IImCFf7oNLKEIYDeOABxzBvjPj+m+GA84IyQAhz/VACUoCH6eZRRA3QBWe9JNalvVhnQAyN003NFofgEIIGBfcDdFdANEAVXdryIAGRtHnoByApwFxADvxB7c/dYX7Owmt2rLD/nloVP6syY+5H+VCOi90j6IyAAf7+7gT9HUvywAogrAhZ4eN6wAAh4CSBU4/uGRyQchQiS/RCAAgzKACU4AkgAM/iD/QQA8h3XgG7PI+6cvr51SAiAdC4BjHwb44W9oPGiSSQBWCUwusJvlchkKglNJuUYeBoFCD9o3FUIAOwz/cBnBSCA/MIAAXP7lndCTupZDCoEWxFNM2K7IjmMRwN9FWWCBCYb3kd9Ok6MVrNQe+G9dx+t3NtFb39NKzX2HQx1v9kDzeyPwd+yoA+DSK4L/IEcIQBvLs+OfMoDpBVwCiNSBWzAMI2PQ25fNCiGAP17mEkDMeQZNp5+q378hBIB6LLNdAIIA4hqAWALAXAA5P1J7XlI5gDXqA6yVCANMvaQVAyIV0OvyNsBG4+rQlI+MzU9yZKYHBMCUr5MDApiMRvok7CX45Tu2bfsCgdAFEQlYGKUAprjnEfwGTudzBWryotY5hDfEzq1fmuWpozLAVLnu2wMBegn++YGa3OWoxgaMflvBHxEAUwa2NQaFErm8EgBekROAch0Cz6AGMsDc/r5SrRAJwBWAzAAk+9p1EADPZiP4X752IqUIQI8FQCwB/vQPTU6GSSW7qyUVAVxjJABdgaUreloMECIMQLcBPqs0Gs3f0bOf3TKhcD5DcdG0GAOQ77zzsU4kbtKKyAQWECN/nRcvEAc4qE2QFc7yFP38wA8t2cLz86sqhs8oYL0VVu3q7eTq1KaOTgErHVut8grP7g7V9oXRb3P4U/y7QagIIHC8dLKra0UG/jzcjXMefbsKHLpB3jBMwQFmp1apbD4Qq0JVClB7uH6fKICrogdAcoASAMTiOQCxgQRQpSMz2a9WUASQGU0FviE0oQgAEvpnqkQBzHL8QyAAFICK5jEMO8Ni3hUEYJt6srereU6EADjm+TGnPiwoYFvkA3wqApx5UUEw74eWa/HLbqugvqCAcn3goD2boBuQdK/PHZUBgFR8hy3yCc9AwYk9zAABiv+7tNlHZgF4EpCWAem6aeUFA1jFD/JMK9gidAAEYBpQdkEZoNCsVWq1S1o/rADS+t31+6sgAGZVBTBcdBmQjADEg4Big+mAaAPQjPamdBMpAMoCNA64lZUjxPrAALde1hqNttT/cCvYOJ5Ppatjjhu0sJV+fQt7RDxkDWcE/vKQY3ogzAAiI7igRICjJg9JCIrXTqvMU3uRI9vxsbOOeGPgtGpHVQDkX7DUssXSroEfOf3tSO0Pgr8rHiIIyPuDAseEEEAyw8r9gQa8czmLEYBwHKBE2ORGGKBgbtdqlc1XWeL291NIAFwkAqD+4CzqABQCgE14pR1D+j9jARDbbz568mMfEcClpSWBf2G0HnDt9F5KOQHJ7JlqpQoRQBUC4ASAFCsBbmGcS4AgsNx8gji52WG4LF66AOKFLW7ICbggZ4ay/rntcM3uPCriXaiIeH0Es5WW44cFu5xf7PhHSQcIETDXsQeRsf1OpO8/qv8Zml3OibhHgPy4RSCAdIEqAMoB5kTRYu9kUQPWI2AoAjCoE1Bbu6KnkngXUGpjfXW1fleMAOCNgEQATNDhjrRdcCYWALFRAvjur3gJoPZqJRwDoBKAQOplVg0S7ydvbdWq1c7QVBEAUABByOBU8z4Yy9DSdiAA61yv183mnJGwmL0Dr3Yin6ZvuTBSFMQb5Ocd/zALmoed/yx01xw4Cq/hnVt2p3RkETA13Q5CI/3Dhb/KAcDef6CgHNgqTEAcJJYEGPfywrzixJA2BrrMZ2CWN02kAQziBKwtvdIw+me0rfXVOt8GjOaALM8+3JNrodP903EEIDYaBXjyk1wW3J/pnbm3xCMAUgPQesDSFQ0xQO/RRq3xJXX+pQLIyBi3eLJtKzcJp5hFB1y4RSCAsUhb3I6M+2HqgOt8pCz4AmIAZ2SpBoNhW5b2HQLYUoc3ITHZgJ13+7PK1NEpgDNAqKsnIgBCP5hQ/9RCGsHlSYATCv/GuQmTU4X8TIgAgALM7cq9pZe6mPAP+O8/+vb+6o3wLiAqAu5MptTCEO3v8S6A2EYlQEJ7sSLqgKQjQEeDvMEEkNIeb15Vhz8iAOHjMiS7uTEqAWhnmzWEWveUG+qKx5xhkwf9FK0LCA5tEd6WPbQ+ywyq+drwqgmli29J7dO6IJg0Mn+oeGjwor/pI1QGEAZgNQr4/A/l//AP6aLznyZHpRE68GApaPYkAz+0/Awnxgw3YpbrmbzsAvAPt+ubtx+hLT8E2s/Xb9yAScDhSaAgAOTCkHTv909iARAbkwA/02XB4is09jWXALwSSEiA8iXhBNBpsjPLv0U1APAwUIRLcsDH44kixT/0t0Gtq9azHFT5z4bfcR2wQ5MFFP6ufR7+EC7uBzi26jTGowcdH03Wc+xO7Z0Inru/jdbyLIT2blVHCoB/lQ2mO8E7wB89/gMkAHZcFOmEkGAGCoG1IgE/IYCCaWRyYycKYfBDl0CBdV5wCoAS7PZjPZGW60Bneg8hA/hgdmQVwB35JlgH/Jfv4m9+bMxgMkhfMEBa21pRiQBm95ZoV+AuGx7EfcgJWgGsBMDQlIdbwFUrpP4mx8cNl7a2evlCqtfVtUK4LR7evyN1wA487eA4wI4tgwGOqghQvkDILYDBeu3S26v7yJ9vth3bV5JBkYCzTxuCocC+UtvcLJXmeDTxXSRQbtlv9f1x6Y8b4FiexYN7Mu5JCMDsdWFeAkE/4QCzaJgTkzmPiidL4B8emTD8iRX3ZG0/+ADJu+v1GxABjDDA8km8DvhMPAk0NukE/PmnPd5IQo+HNyuyFYBzwD2IA06zrkDhRI4XhyEBMBzmBfrVzS6MjyVO8tbWvPe//7N3Pa9xZEeY6elud09LQhPGgwlsk1YQjdTdo4Pf9uqyRzO5dE5G2KzATthYBsPiwx72kNX8wGBYhK7GC17bSYzF2oddGLKMkbIwmxyWXJWZ1SWHHLr/jbx6v1/PaPwP9JvxSJZlwbS6vqqv6qsqDADX/A7X/8CtP+GWAK4fCU9JOECel1uD1IEjXW0CoSTh+Wi4JKeP/+mQ8ICOPpZfX9UJioHR6Ozs9OTwyS5DgUskQeNS9r/s/jVihNi8TwKJMuMJGYHCAx1QQSb+NKOimRl2Fmv2T2DUL8Vdvr/N53vAL6/lvRr0j+8/opPAVQKgbAPFAcBPFQGojhoCuKKQ3Gr8Yb8UATzoET1grzVliSYiJ4mKgkUA5LlRpGju5HHNrrk+Ip1taVr3oN+1oxYA8oBmuYjvF14SI8CEJhFILmCipQNKs8e6vysl4fLw7MlSdd9af5xrE/lVu+dyIb6sqzs6Ox4CCiyEgLUrg1wT/nVKk7+E7kdN5ZF+H6Taf47WQSfp+YT/R6t+sW3YBfk2+kL/T5D6fhkCRHs/aQR6cWdw5/7jrdtlBnC7rm4D/bgKAKqjnKf/mjpioXzrnJQCHyhZwB4hAWtvxL5wODQEkBBQNBcAAFq3a3Y9wQEAJrZx5E2n0A6US/0fOLhcyY9pGQRaIeDmfx0KAeBjx6w7aP4wdMiJum8JD9gjPEBQB+b8/9fVXjg1gBHeo9Ojy8KKs1DM/Cq7f0X7L98bs/9A8AJSJQm2yZYfH+y/MDI/qxu1ZkB5PwMMeGkXQnrJkGDbVTYBtbybw/79/uvb98oA8GwqM71Wo9IAVUcLAX7+RgEA7yPRECBCgB7oAQ9ukMYBriWPuPUX7I4MOFFFPNGF8k23VnMykLYkSbwOAFBHoVIppHxYWL/GIISgKM/nx4aGnYUowER4+ejwyjIecOVoxNIJegjAFULlg7/57HAJCQgXCZyZe8+RgDYlACBz/9lXIbY3zs8tzwIAaNbrRbFdN7YTbvYBnxEQ+wrowp+NSGnvx/b/0XDQ739+b87+v3BEmtBxq22g1SllAZ6+4wOlXSABbw80NXAPAwAhAffPufWb+EAIIDEAnwRxjyVDAN+s1VpmM8ABQBJn3vnUswNpGjgCiIkv5PahGgvxkDQIkKmAjrI6oDyHWPbfwuent5a0+mJ3fjLOFfovRAGa9cs8I+z2Pl2sFjoN50r/qvtHqvNn9j8B04ZsAIsIEEqgi8+b+fgyZWbkZyv1WhYH+omDlEdbBQOCzFAYAP7Vfdl7+PD+/C7Aq+tyvYNjVRqg6pQA4NPvLdNl3t1pWS/+eKCWArH99z7bxwBwCxYFMfM3bbNe8LsRQGCjaEp/RRNd+OZOjJphOBEwgHaa4QjAm7EOF+L4Q9AHCO+YI6R+mCCkagPV1QFMF1CCAfYX+oV8PFhbxgPWfn8a5nqTYVeTB8olhzRh0A3Hw0U/6ok29Vsr/Ym8H1LfGZv3g+P+lAIAvgQ+KKw9p5mm/oWxXkSr9VpRAgAcRTXZBfc3sPOHT1ZNEQFY0M89HDzsP5qrAG69nDoiBHCvVRqg6pQR4OsfGqJRFGYD8RCAQkAPDpCA/RueSc2fnKgQEEBOGpQgAKEYc1mj5TQDAIDCg07CNmcIdPlNHAjjmORq+oDZzw7JFeyEc8pAauvXlfK7ul4Qv+RnR2tLB37cHeWhzgHm3L9SauxgIvB8wU/bHevCH+H9ZTlUwwFmzggAIMgZHmxYFACSJLJrURZFKytNyQBoHSVOyVXeENd7IzNsCgDYui1r+qI/wADwiWb7pAawMpMEwPpVpQGqThkAfvOXv7oCAVrWf/55IOsAPRoCUBLQurCJ+4cjSQA7zVLMCmwgMg3bdlZxBNBMAACmDV/IWgkAwOjwCTaOiSJ4pe5faAp2ZEXwemmJUEfRB0gZboevKDjdWy7lYTxgHgE6XbG/W1MbDBcCwGLlT8n9I6UIEBMAiBMcDSHS+ZPBbF/P8RP/ArN/AIDVROH+tEO4yfgWgYBN/Kybagpg+naIEeD11fkAQCEA9p/+/lUVAFSnjABf/VuGAC7rClSqAIAAB2u3bq298Wo2O4ZBSIDqldJ5BNg08fe5jh8nzWbhnU+njYIMvsePOCAAEAeqdUy0SGCHRQLhXJNwJyw5/Vyk4pSJ4uF/ny/jAWtX9s7CcM72pbi4rDMIx3tLAEDrhpTmn2sgEMgIIE6hdAran3idbE/GABCZdXcli9ZXiQpA2D88E7+Q1o/tv4hsW6YAWo2Xw8Fg8Bg7/S3q+Ln9ky5AoRS8UZUAq7MAAf72gZwWg3ni2727IgfQIwjw2QOYD3hwY4pJvY0f+NiUBMjTDKirkuwVYUoLiapaO/F9DADnViPj2BCn2EzSRAeAhYcoA3J9YFhpnWBnjDodMZRcagbD0d3l9YAhBAGlloKuvrhTFR+ezv2w3TGfZqb0Qs+18ekIQCIAlKYpvg5E/LdKIoCZ72O8nGEAwI+y/0+bKt3CIAAZQJsDQOu89njQf9i/yYx/iz+vbj1Td7w3fqwIQHUWnE9//EbEky7kAfelFLBHQ4B9QgIsfIsS/w8IUMt0BEjYQBsZBLRrAACmE4GIdWpNrUbEq9ox9n85BoD4ErOfUNvf4SQgD0k+IN9ZsEsUnR3dZKuIVfNnPGBpPeAWFweLhF+3bP2iHzlcEAJQAFCoP/f4+aI3Rd95QAEgSWMMACkGgBpMXfecX2eu4VorWZZFBZIIQE7CzR/c/2ZWZCumzX5lRMP9Zjh4iAnAlhICEPv/QhQJZlarmgRcnUvO0394MgQwG6/2pRCQ5ADwY4+QgEaNEgDDvsAkQEEAHJX6op2VA0AamQYkDt11fP9OMQXw6jELAWIYGZq2IXU4oeY+uTQCIGxAtgurIECj72NsyGXhMEsUonH/vcnATleS/m5JYawXHA7LIcDeWDV+Ie1bHADIsB5/nmAAoCLpxCQAYG2suubMWsUAkPmIbwihI0JSX1xlCgIRpGE4ALjex2D/nyv2z2nA+kwAgDOrBgFW57IQ4HtPCQHM6XcHeg6AkACQAz2b1myDYAC8RPK2xE6pSJj5iyggzsBPQYYx8zfJTHEjhX+D5HcScwDQTAQFEyklmEgSkKtjQ8tkAOzycESqhR3ZPEj1eTkavadJ8KQbKmX/rmw47ijKA/r58zkAKOn+LnH9sqWH+nRM/hMIAUgE0HZhnr9nba6AVj8CAGirGQDYCS6zrZtwqTOCwybd9OvOXtwZDgbHN+fMX80AWtUYgOosyQP+0DCFzs90nvVUJSAJAWge8I5n2OKYhATwP2oIwEAg9i94paooLBwCeG5C0QEHtZj+J800FvqhgNk+yxIiFJTCAKkPzJVpoviBI3PY8vd8jPK5/UTYdFFIeMDlqgAyLKQz5/yZyE/ZZpKflAHgSJ1ktMT46VviJX3APhwBkO7fNG6S1SvnzoetqWU5BAASLf4PFAJAEwB1Yf8w5s+6eSgIwFUlC6hkAGczx/ugKgFW5/I84G9/4ebvtmzv2wM9BwAYAGsC1r714NaDB5QDGQnIaARQtDX7x482a1dzrXrh4Nv73GnTobek9R0DQBIwU+dmrz41CNjJNQggKQHWcXO2S3f57Z2GSFsrImZujE92l/KAw1G+IOtX1vjOAcDalSF6n/FLjTRLfsTAfgLY9AkxAL4OPtu+6k4xFXCx+bOKCrd/ogGS2T/s/yODMwDI7XuvSAWgzP+hCeAXMQXAsq79jbDCmQAAIABJREFUVJUAq3N5CPAzFfqB1M9tOdaXB2oEQEIAvinIsJkWCH9cFe6fk4BUiQLiJGOVBWcWuWSLTZMCALnzg7bfDJjZT5iLpOQXSUFhoIUBeTkMgJGjp3R6xy4YMpqvFECggEaHS6WBu8cLtcXlMyhHACeBOux3odtXUIBJepIAxXTRL7RJpsWUrV+2GABkRayav0oA4FpvRgb7BdAKwIs+BoD+n69u6fH/vU9eOsq44GvvqgxgdZYgwNN3U5MDgNtqPLt794GWAxhiEgAI8N35BXU/AAC2sc5tn0QBPpi/hIA48WtcrD5zyCprn97XBADitu/HQYBUFsD/itSvl6uCuUSBHZQHmJnv4gfZ6dsfo3nzJx9OnywVBRyN8rBz2V4/foblCOA40Ob26hU/HtYoLb2kM6odi1XfAACbUxYCwAWysflnfhyLAcEyA0hzLZtZVmPmj5G6hbH69SEOAB6B/WspgC3YBCA3BlW7wKrzf/au5rWN9A4jWZrMSPashsjjtGEHJkQ1imaykJ1M59JeSulpdAhhGDc6OIa1AgXTgw97WBwrBALB+Co2kK9lgwPZQxfSBlFrA9O9lL22VvYfkP6Nvr/3+x3Ja6fneWckOc4HjtDzvM/z+3p/mQG+f8Y9APpgfYFNgIgBIAVATED6qlaucAKAXGDMXcAstmT4Qw9ALIZRwuf7ZOayyXcQ/nIcP8DtMRIJ5G5A0Y25vABrIgbofXZgpmkUAQek0YU+9wHr8mklyAf8af90H0C5Qwr554Z7imijOhrUXRz3k9lLUjVYANhW6BL429gGxJwA0MsSTgJ4niQA5AIAxAHxUoUTgAFjAAH/h+12LgK4LQwAFgDvighgsX5xPf7pGZcAevWk9mNfUQBAATgTsPnpiVbhBKBd49s/frJhcxcKwHYqPBONh1bFHP8eEMDMFuGxjOt+uamI6oHAna8PIurbHSUI+Aj+wAEwFpTmA9SzSvDwrUU+gM0Rh8rAY1JSeF0qNVaOO/p8mCMAc+xOTwG/6wbKJQSAZfkhxb8NL42qRAArhEY5hUIJEF/4re5Q9AMBwBjAAUQAvmq3BQWwDACb9wwnhhZNAMU6KxX4LTUBmAD0S9QE3JckwE4PTMCPVUkBaJVOzDwAxKdmfojlfUgVgN3R2cQ6TAIN+J2QKIDQnrUcV0y8YCxAHzfU1qJ5DqBdBeMIhEkEF6IA9ANG2AdMpemj9LSiYHrUVxnAFMeIwPf3wAesyy2+vMJfpBvkOqKRuzjmJzCv/Br2dSR78M5P8X/Z71R1RgD6pAPvoiXw7/ny7o+eGmVq/2nz1i4zAAr84SiwD7wESJ88+1cxCLRYZzHA9783eH9pVf/iTV9RABAHJJmAN7UyiwJAV1CHgx+rALq74wt9xGNDqkXVqyshh3/oWehD7QnQB+78CoAHEHpuuIGaFvgDrg8CAjhGoO9i+OMnEAHD42kwX6GPGwsO1VEBpiQB0Pej16OphP/ckQWjKJ9AzFy5hIE+qY5G4TcI6Ttwsh8QgI0FgL1cpXF69FrBb6ItZJIvGwB4k5ck+BuSAeAKgGUATtisR0QAtb8XTQDFOnM9+alWFkOmTpr3epIJgCjgDu4JSJPf1suiL7hSEvDHESwGb5hwZdvOz3pTIoAlP+QLCCD2JbRnefjfUJoLeUjQVWJtzyOgpW6aUiGAiMCM9t4GgXzuGI3UrwcujApQ9L+pzAFPjq9PRaGxcmBR8DYfAjjI41+YmED9yTkDwGQ/yw4JASAGsK1SlYVIdL2E5ZTvURUVEgPgUPi3Zq1r8v5fqZ9iALbbX36YMPxP9GqziAAW6xxxwG8/1TVOAEbt5aaAP8kE0kzAjqZrEgOsYOBzHWAJiKMPuXVNlyyArtn0d/AE3FYrtjnyszNoIAjkyCCLD7rZQZqkSRdTQJeZAUQBhyMxU0TO1LnueJOXBZkqAWBxcDBen3L/L/0DU3euGWjgcdWvJPsDWcKog718RgA2JgDbtyp8YKehr5CuCq6RbEduAopnJANIc6uGrj0C/B+tEvy3JQZYPhGznvXaP58Un+5incMEvH8mWswN/b/f9VkMgNUCUBPwt/rPEgGUcfUa7P+ECOzQFwRgx5IDQJ6V0gPOgNlxfNNRZ99kZAJGNkcEgRwY5IzgBt5omKDVBRLAREClQGoOx/LpulORRXSDXdEiZKoL5wOevw2m14UAYPThHs5lAUNJ++ehPy8GXBICEATwG/RwdEEAFVJWyVWS70hzwIBeS1wA4O6+O6QEqC1bAJIBqPP3fKLX//hNYQCKdS4T8K5WFk3m1Rd/3RSFQFQCQCYAcoGlOQZocSsADOCHVObOKsgCNPUm3Oif/TWBPyWAVtwKcdFgRkuEXY83wQJg1hQdEMhRQfqVd7ubJLcwBaAbcUDaxVeaRNGDt0GwsErPIyPDzDz8GQuAfIAxA6K+H253P08A41BE+IJFW35+sJ/rWYoCQBxwRRrZSRosHZ9JJEdtAo65ASDdvXehAujwDsM+EwDb7ZcnE10c/Pyf90UEsFjnkwDfvNBF3s6o3d3kCoARAAwITM3exQ9qGIAvHAiwcaGrjz/ljqYhE6rjy2jqV8hHG2lf9IQUQOzPI38NPa66amvxaSs8TobDZIg4oJskRAughaRAlCAf8HqEZ4/NFep53ur9HPwjeiH8p+YFkA/rOfJw83VA5shTd/3grJ8WhwAcC/3fbbZiPLKrifXRMm2sxu+eT4cACAHQkfb/ql5/sT/YHwxICaCkALbbG+UTnRzjpk+qRr0YBFys80YBHr+vabjCFCxm07j0XU+kAQn+d3b6YLHv6RU5DLAU8xgA1KrNSIkLxLhtawkxQBOK1pACaFZb5PuCACxa9pbhB5spAveai8lAlgELIHVICICQAEiBW1gJIC2AbjM9XHdJk24uV+d5X/UY7lOTnCsqOACxwAL5sIl/J+Wc0fdk5AfuAs+SlwA2IQAPE4AFTzer9GQf9CbRA1dokaAl639ggJIIAEDa4CFMAXu4uiolAIgEQAYADnIjFFAtzgIt1vnX1+8gE8AaAyfIBEh5QEIBNBeoZAIq12QJ0CIaAOPctmHQFaBfxwTQ8CkBgAyeNW42HE/UvZEKePpwc3YgJ6bZejCki3LAMOGWAPmA1DwYT/Nzhwg4/WA3wXBOMQPIF5EEh9fVvzVKL5hK/vAv4ZkCRfz8a9wBAAH4FP7o7eFDO0kIgBGAb+Ph/6ILOF4inMsCAG/2wADQBkAWBVANwATGgLwvmoCKdX4NIE8I1bXa3d6cAtjahP0yeSqbAKNCA4Et6gIcKgEQEcTaUllvUgWgL2F7cBkTQAgE0ApZ6xAF/hq+XbmrkKGIMwJ7WvOyg6FYhAMIEVAzkJjR3njdVep0iGP3Qn9jB4cLKe75zUIBvfG6EjhI9hDiHu0+ROsIrd3b4SlOX0Cf+hv2TeIArBAIADEAun61JMy6Rs9ZIezJ5P8VOgXgmjwEhEwB3N+/vU07gNt8CthGuWrwAGCzXpQAFOtj1uN/PyuLCaFwUIgaAxjs0NEAW5psAigDiMW2MdufaaVl3SAKAL1Y5Pu4IHbWaTQauOwlow+xrnoLFpcIDF3h6rA3HCocIAwBpgAoCvjcXTSYI/S/vBdB2hBnDkEIRPQrGgkwo+dTVxzPPRqPRtl69lmWBRn8fFnmLdzvZcKiUz3pLzzfwUHAMMToxzagzJMAeoke+QHZQTUBCAEAjRMA+tM4ALC/fyTjH1/b7ad1jn84y70oASjWR0mAJz/UKzozAWjPvtdTsgA7WztbZD7Y0YmUCzSMciPPALTlzVkqrVSaTAIYDi2Dh1C4gwig49CiV95DwIlgTdUAHPl8Vi4igPHwAF/KusV5IEmHhyPPlaQ/78u1s8OEVRGbvIII3ZgC0JPZw9KBJfg9BH83g7WxsbF6++jhoB3Kuz5zKvPwF1LAstD+D/9z7ADgS6dCj/ZEQqBDD/0FYlBagJA16JAhQKxSs370ADHAI3oMkBQCuPOyLtIKevPSP4oSgGJ9ZCbgk4qIAmj13/GhQPepANgiBYHpq3pJIgCDpwJakgawoR1AWynhAACoAL1FlQGSAD4igM7FltRAGGZqP/EpQkDYg/B4eHDQQwyAHkIK9LESQK+3EPxdDv+A1+rCRILxMAKBIEoIqRggjzQaHq97cjePN+jvDAaDB/c3N3v9BPTBaqiC3OO3qlQ4JYSIAJAGsEPfog7AnlH8AwGwU9ctgf8Wkf+zBpnIzmKAtTcP0P5/2N6WTgEh7cAb2sQgJwGBUSgMQLH+DxNwCTeakr4grfamx1sBiAcY7GzhrqDe0w+awL9RWVYUQAczABBAXF5ZIUEAKC6IiTHABGDFFzsXY59An/QPESlwVUX+qSzgXR0gAkD4J3cvLwVej2D+ligh5sW54eh5lJCEoVRCmPKXqAt/VZEMWSJqh/Cf6WU5iIspngonCD1gYwFg2TwCgAhgwjoBqkaM938IEnDs01brDsU/tmVNrfYK8L/PDwJs80ng7ZsnBPxkttsnhQEo1kebgK9/YNOB0GeoaVR2eyIEsIU9wBYpCd56QUuCqV1YiefiAAD1Vnm5Q2IA6K42/MtEAYDVjTudix3LY7XvHpmSR8aF8JYiahH+vAD/YbZ3wBZnAmYKDl6/dT113ggFcxgcD9P+kNcNdEn5UMrrCLvPBfyZyr9tpvJKokHIu/Zd6StP6eZXPIztEAuAxT+54irDf7VM8I8UgJizhPf/VlyqMAIA/J/8j72ra20jvcLoY5QZWw7SZjzrkGaooN5gzbw3Jfs2N/kJY2gIwusYVmuKtGBYfJGLXKSztggEitDVgmjBkZ3sYpNNIYWUolTegqAXZW+9jvsL9Df6nve8XzNj98Lx5ZyRR5YtAkn0PO/5eM45e7siAZD0AFY6jw7Esnf8z5vLNwHldqlKwAe1Cdip2HubW98kkoC7kAYABnhsqcoUMEDFTATWuCIIDju/UK0VuBiQmVX1kBY88HSXa4FKAigGCKlJCPp3mhBUkEAW+/12H4IA8eCxABKCgL+q0htj+d7Fa91uF5MEggJQSgzYb63d6x83aFZwcE1in7NE69rEaxj1Cz3Ep5G86biACgeAH/9oHl8LhBTQnPHz3/dF6/8ytldCAVCMYXX5ECDrxgDw/4zjP7EN9NEXjkgA8PDN+imXAOV2CQL4039eGKvAK6c/tGUJcJc7AHBtcbT8OG8QQNkppkoBoAdgSG+WalURA7hWwRP6AEh2zaJaLVgWDcIhthAaL9bl6BDjl4Ie8Ms77IML0O5n7Ojd3fA8fU4jJOOjBy1ZMuhyEjAoANKGkzs0q+MJ4+uYKVhFllhbWyQNyFOGF2cpEhIHrgKSBIAeALNAewA1JIAZ76oQJMCHgDXlKOYyJFPt/WcQADxPYh9FQPtnCv92+ez2yxz/uV0uCFhyFAW4xbM3bRUEbGIS4JvNNoue17r3T4u6O9XhisAUA3jezaBaCxQBQB2Qt8GBr+szT6EWkVCDHHA9VQ3DVDfGhsZLKojhN3TQj+O4D5dwBNBGx3dpdrQAPOh0Mmx1h/LiN3QERNVw7WhMzxEe0TFgHpqNsPeQ8cSUNkStIuH0X5iwxFEAHuIf7Cb7qioC4DlAhn+OfjlnCUQVTb6OiQ9f4A7AU54A5AqA5Dbwlb1ToRLC6C1PAOR22UrAK9vRsHb2v97SOiDpBHRBZ7d1w6640lcQmmAjBgAGqNejUi1wJAFYqg7Id93D+7ww4wBQui44YN34pfl7bp+O4pgzACcB7giwW+/4Tni+Lp9+ethn8B+a9QJggO4DlA+2wPs3F3Oq0h45vgfAbwk/AVIA5Hy004togPqzJAEw8wuSAE4qqAIQ7RSRmrIUFHENC98F6Drzrxn+v9x52knvAe6sPLFxUwhPApZP80UguV26EvCvXxxbzQitnH61JTwAEQPAE6QBWte/rNhlgwCKCxkfoF6fNSUBwBTbGdYGOAH4s2U+BJNqlK8bA0VSpt8mKIKM4x5ngLgNDNBHJpiMwzCtzhHbCBZHw7R1pXgIXIDh4E5mMS8+06PrCP5V4Srcm5DGBfCn5zAB+1M+i3w+AsAgAN8vyxzASYkTgMC+esyCAl/FislW153/HcT/O88Ws9ap2rpTwJ1//33uAOR22SDgLz8Zq4Lc8tybDVEFBOzvMg5gYQBXA1x7Y/EOYjknNJMGiJZ9vxksIAFYrn0SgT4YcIBSV+gdEvBeV1BfTz1nbJ13zNZXJAFI68eDBPzNojyZDgTosWK4MYSLOwGA/26rdTTWnkOqpv/b/r2Whj88LZJMgVJlKJMpTTneFwgAwh/DAfAdqQM4CXj4PzObKmAJCCxk1vg/3ecJwMfJLeByDLAaFWi7dj4HPLePCgI+OdOVAMdyv2zLOuCmSga2ecX89XzRlXog2BeWYYDID5pIABZcNZyHKQlATBJFm5IUyC8wghMH6pO41wMOUDTAAnia6cRB+NN3MYc+lAi5YACrhRsqDugdqyYjreORDsBYwB4jBWb9KQ2z6FeYp2GYrGVQGgV1ZD4OfRQFLsu53ZYVifSfigHgjue/IoAP7iHD/2DwMHv8rxwYO95tZ+nnPADI7WMYQE0H4j7A3J7oBQT87/IogDkBG7we9tV8xSnrbUEl4xSToqBSVRCA7VolD8uAnh+xGABaXWCdAM0gn4jJARfBnxCyPmAEwA2eGfwfhUT424Yaj9cLyfjIEArIeuGG5ICNYTyBvOFdE/6GA08nqBt6IO+rOzQhU6LaAzAKFdoVYGy1UPNE9sNXV/RBru6yZ7469rUZ+HfKFXv+EZz/g6cq9a/P/yciFkMHgAUAOf5z+6gg4B8vlBzIsctLr9u6EIh1AHbnaoD2bYMBGAc0M/ivNUsiBQA+gI85AE4A2PHip9FP6C3NASQNfzFSYL0+HfW0xaPjhkcz+hvh/U+EXBBVAlo+uCEEBNAxYAQO6QpeOFrDNsMh3rurhyQd+BuHvpIyUaVhoFEp4t2RnofY548bmAJgt2Ia+2AlE/9Oee41nP87T/UOUDUEsHPD1g6AY73KhwDk9nEE8OuX7+cdR1PAL2/b0gXAHMDu5ubmt7yddtuFD5+YE86XhWQooCg8AGCAGcFcWD2aSd2Ll0A5kWMDCZF+AOeFdXH4yzYjSAEIG/UY/OsKbkkj4XGc1gkMRdWQc0C/904nDs6t6E2HLTFtAK/usEPk6a88/zCbvNSv6s3CTDoAIPf1eVtAyRI5gJNiFv61UkXjH/oyDjj+Dztm6X8lnQAAe5FPAcvto4OAv70602eKa0EtULUDcT0wowCeBrj2ds5WSQBmyVIAzwmUZA2APT4XOQAvilgIwOWvdQ77AwoHPzwT81J+AHyzLr1/9nVzEjPk7452d3ujybROdLHAPL8pHR/1+3H/PNvAuuHkLpUz+xqmrldFAOThqtFpDLd4ShNpfypPf0rNoqb+LioUfL4KhI8F9UUMUPwghYCVLGuiAEjiv3y6t7M72Bk8XjSWgAsKMBMA7J35IrDcrsAHAEGgrUoBlbmDb2VDMBz/3APY5G1Ba2uvl0wX4L/ZUkDT4a1AkAWwqpgCYB5AILSvvk/0JGEZ5hO1QRMf6AwI/HMtwe8Z+tnhD/Afe16yXijA2aBkOkClkLySxuB/hHUDWfc7T9xHJ6sIfDFyYNgayBYFECqY6sRzj39KvKBYxVEI+BdGN2Amx4FlCCBg579IqyIBlM/2n4MD8Fy3AKohIItfFPQYF8YUeQIgtyuqBSpdGayh+bFtKoGYAQdAW9Ba9z5PA1SQAcoVzQABPNilMgDso14XDBBVI0kAnjrwjZNfeQAZjwDslt9hDgA//cd8xGAyW4CHMmkc9/pCKYToT3BA3O6z0IGqsT0J9OuWhLDRa8lhI6JkcEwaSQfgXOWCNr9UqXHHh/gzSQH1eiThb1mlBPrZVTKmLbD/gw+WKAB09AQAlQL83DbWBX3YzyuAuV1JEPD9v091b5ljW29lIhCFAGDbmAjcun1WRPyL7eEJH6AWRWVoBcYygCX1MLNmMMNgGF0A5fCLqbhEmfkz9WP/MN4d9XoDBX/xFuWFs+D/4VFfSwTifiyEw8IbANXQXXKBjNdUHY1T0qFhf0zNrP//K1eiOxMV3EhGADPl+CxY0gOwF5L4jwz8gyLD4iMABoOnnY5ZAEAa2DszFwblCYDcrq4WaDtyNoBTkWkAHgQIB2BzGxsDt39l83yViloDfZbBUxGGgdiMAthxt+zhYqzZQjPyhSLGS578JvypvK+br4n32U7M4P+I1olEv5k1pCGh40E/TguFNPpjyP0TegH2DZc+JMctqRZACmiN5PGvOxXSOUwjZqHEbxYqmAOEXl+Jf7+o1ia7qX+vkjFtDbcA9jABqPCv9gCsHJzBe2RL1tw/8x7A3K4qDfDzkkgD8Hh0/j6kAUQKEGOA7c1tVAT+0RI96xU9JDDQHkDVRhcAEt41D7OAfsBcACyI+XWSAnzS0j+7RUh9OtqZLFJPE4TpMLCoezqJ47RSMEEGo3dcNkAzep40qMlRKzVz7JCE4blxvzzyNZtxiwqVAjZBYN0Tg4BIzQO0eCt1IDigFjR5TsXBO6PgpR96EAA8W+xAE7BM/aEX8MTRFUDHnft7XgHM7coY4M/v58uqMditzHE1gEgBYAzAKICXAq6/ma+YU0Id+ZHGQ20BP+kufNhLdSSAelBt1nzZGZ8++G+pG35DE24A2HRKvAw1CD+gHkLwDyJBkAqeRwO94wZJ5AwTQ0gS+J/GUi4krzFRh79+IzHPfOmN4HqEatGtogJ6pgnAD2x0ikAGUNMeQAD4l0c/nv8Hu6gA7mgJkJwC/KRoJABc65O//iF3AHK7MgZ4yWuBAtWuffKmzeGvqgCcAUQpIMEAZScxHyRw0AMAAnB8XIxVj0rVZiR18ekTPvP9rbRb4JELjNa9xVGfY18/4Os7zgbfASFMph4x6nTJIUQJ+FPyUCuH8RpdFPsr+aJ5/BMyq1Tc4H/sXUtrG1kWpqqkmipLMr6T0sVuTxfDgAVSuXYdMZvpf1CLgRDygqRDMA2C4EUWvUikyDQ0BKNVQ5iF4zw6iejuhQcyM1GwMyDoRdPbRLZ/gf7G3HPOfZWk9GzirOqUVCo9LMqivu887nlQN2Rq9EUE4BkLwLE8AIF/zPsxy3rYAmiAPQC3FPzVIMDqie7HIAjgfTEGoJCPSQC3Xj+jqxG1uoDwvY5sC2Y5AbgUsAw5wfawECgMIj9AaLckIh8As942ZD1g5nleYpkAH4S34QBOzxpi4/Iz8zzAwflHrKO8kNBXNCB2w1GazhYablqdBvIOPWQRY/0A1RBce/gynce/DmDO+S08TQQBbEgPAAv9KQOqFOgYQFU5/4B/t2Rn9ZQmj++bFgAmBCjHAJ0Y/z/0iwBAIR97LfA3aP6LRgCOpP98u2c7AHIpABjgD9f2JnkGsAqDVnAZQC55JXI05tRzHE/FAZnC8hODai43jXK+rl+j1xu55xxIgYHzL5G+032hkwW7VtLwJl+wYL/ZnlvNQ3PiFRYNqMajYAGMaIL3lZkE5Zzh3zZMxqCnJ4YAoAVKpgggC8zo9KpZMwX8m7T+IJw49zAAeDe3AKgDgKXQBADLb4oAQCEfOwzwdslq/h0uPe/pPAAjtBQAXUKhPYgvC4N8xQDisvbRAqBVb1f2xYirrmCAKRkAaAJwBfx0nVuqnUu1j4cNIoYGAV4jH40KAbH0LmF/v7u/o9D/Qql+OPpeWv9WmmH7Q/a8eDMeU96wbDcIZDBcWJzUzq9SmpNvZ74bOUhwRACUA80S5QEI6yjRHkAN11P1kOZgEkELsK8HL+tmBqAJANgJAKXwWZEBUMjHJoA/P/3lxLikMJSuo0wACgP0t8UOewQuH8D1GFmVQZ5eCPDJAqDuVzH1xYlrvuu6tZjRnBwJZKPeAeSg89e1TcBlMwF8h3PYN5BMqL4gZWw07Eqgv5BFAjv76gBfGdYpWWB22XBhwWE7ZZe7D02zMXx8eMSVc5BeSecyFNs5xwVIqSo8gBqnXshJQgTA4rhF6Af8B4nS/4ljreljpeBdTAB4SdhvWlPA6k3IAFQfFbz76NciAFDIR5db/3ym0tHhkjwODjo3Zy2Am9tyKWAi1Ffkm8oAleAmLABKBAwoE4AIIAECcDJJAJQeQAxgrHzZPiS1niH6pQkgVT9p/3gMHQII8/vyEUwBRQNYM0Tqn3DanmMAO5TfbvP0aL6AoDtObad/YZbSFeXCiPOKfdePspTaICVCkAAYZQHg7HRKAwAGgAkAJdsAqPyk8C9HgFspgFsrgW98hWipGAReyFnYAA9+fWTrpMnjez2dCUACpsANWgpY8jX+IZFdMcCKC21qhPaHVIBghXrixhng32nFOCjLwrKQdWPbqygAjBRdV++s08ca+g+Edm0fCYTvK7jTg3wmDw8p+JdaEbvZQkRrKY+no/sPTdfha1Q88PCQtWU9UtuqVliQvkD/DoQA/RBrIAXl1WqSAOKNUijjolGgVgETz88TACYAXR98qwcASwpo6gCgYoqo8uZpgf9CziQQ+J/VU+0CBGFlb9vgv685gNqDPF9SDYKwka3venRtu4FKBBS3hMfYEGvqCfw7YAIoG0DDWbkC6aw9gJ8BGyBt2BzA4vTVUMPd3PRd7IevNi3tn+qcQ7sSSR9y1q4PdmW/4Ru76kHcR9xW+e10LnfRBDDxzADUTkwGQKvVEgyAGdAJARctAJciAIlnlf/jDLDnfaH+B982bVFhwCdWCxDxPUUAoJCzCgP88GZyqn3NIFz6atYD0JWBy1AXFJnSYN8/pTiAtAAiCAGUq1yOwKi5jowD6igAsyjAEIKEvz6elZiNBgRzIwb6dHD0BafA/oyvPuMDpNi2Px0fQRWxnTxMfUd3B3xhsmJ++dLAP92App5cLzImAAAgAElEQVQJOT1Zq0oEAFkA2L4zwkQgV+p/1/etcWvB0hOJ//osA0AGoNUCTMizIgOgkLNiAOgTfkrgx93qj72bMiHI9gNgMfCv1/4m0wEkAfgOMAAEAQOEP9yrDUZFcZlDJgBNzEJ0M31oQV9H+fOwb9CUXQ7OP0C8LzaN/Rk5HPF0PkVHHHOurXUKJWyOmkeHw+6uLB+ysN+9IfYj1l6csSTRT9EJaZ6I00uAADI8nra8qrABgADY9FRO8YXISAnUf8txDQFgWv+ecP+vD+40Z+AvMwBD2wFY/XfRA6CQs2OA/z46Dc3Y6WDp505O+UM+ECYEXby0fGOvIhcCqD2I63o1TARS8A/KpTUGGTHxdNqCple0FMgl8Jl2CGawnj9uyAnbAP/0SFj/w32Ef39/kQzrujAvj1eh6seb4/F4dHm0NapfOBzc7+9QqbAuIuya6kGxH/DZL7Bsfr0qqfS/AD3CmmZ+J54QYQJAGXSCIVWMiwblwKu1PMf1ZzuAgP6/c7XenDcALnu2AxCu/qsIABZyhvLgt9WSHjsN1ekHHVkTaBYC+lgbfHG583kFhoGH0gZwgQLcSFkAQALBX5hAADDAius6vuskcmimPTeDz7NAjga09meXhfXfH/YFBXyAAYZHX6iK4Rz+eRqvH3b3oapYansE/lyvcZsDLrO5HCWeD1RYdor4N1agr5eH/0om0O8JJ6AFHYCdUDNqOQrgV/JdS/2HYQU6AA2uz+EfDIDmVi23AFD5Y5EBVMjZBgLfPjrVBBCES4+v92QcsK/325IBbj+ulAQFaC8ALu1IhQDQBjjP43jFX5lOpxj2dt1MgR7jeYoCYGvwBUJvgYJlV7YOBcJx64tdXx4b8IP1n5oUfRu9PP7mvq4Yxsoh7C68s4ADVC+BQ5bmv4KnM1v+NGPBby6FAKaeAwaAYAAY+BPKQZ5UDSR/KyvjivA/WIR/wQDnrSEAQXRcBAALOWsn4Ic3lZJEPzLAnpUPKD2AbWSAixeXv/5TGcZYGPgDAegQgLidazCWhWE2nSY0986LJd5zDMCMP9DIgR8dABq0PR7s7AzJAOgjBewrDhDQHw7Fw6jN59Q/qmzGrqr6ACod6PaQCDo7+LDTmSOB3WGbWajPJSErsz+1zRN2Hn4AH0MACeAfKSBJslZgeVSCAGbwX6pQB8Dvrtabsx4ATAG0hgCI26MiAFjImTPA62cTc80eB6tf3b49kxC0jTaAkOV75eNSZLkAvh8FSv2XvyyXvTW2FntlP9vI3BJ8spQYrc+xca7FAZoGyCLQvj85C+lIgJzwD3DvDxH8igOGR5s8zTv/cnmes/GdrqwZ6growyaOe5ISOt1FhcSjOJ2Besr5YhsFzzL28FeAEEDmQOkDegFJK/MUAWBX8EAOVch1AIUOgBe25gigmce/IIBiCkghn4ABHkB/IOkCnAAD/NgxaQAA/v42MEAPGODSwbtj3yIAQQHYErD8JbGAvyawsRIEXpY5cqbYVBv9YDjHygqwsS7Vqrxx/enNlwh4gX3YtP4H9X84ZtzqM2QYQKj/LawP6nV3zNaRoM+9aBkB9djKUfiwMEVSbAN/hCqDKemOwL9DJoCXuHZMNQhLfsm3milM9gZ96gBWX+ABPDkhLyGQAYAiA7CQTxIIxDbB4Ul4QjZA5adOLggAbsC2YoCfK4HMBCL8ow2gjYDyZ2yNTf0grELzW2glVmpZnj+ZALEZoreGr68p359bMQKUJkKftD/sSYT1n7IF2Tk4l+jvUDMISN/p0QOhHaDfy7kFhgK+vxDz3wW+xUryFGs41ntFHCW44unB1vKcVmhbAKFt/4t7ReFflv7n8H9V4Z++Ilp6WzQBLuTTBAJxKQD0PxLAyTu9GEgcsE0iGAAKg8qhQj8RADIArQKU320ISHx2Loj8WlVFCjNEPLecAIsB+Bq91bDjgzJqCGgbDSX8Ef19gv/RZr7LgMkrZPHW/m5XOPvC1KdCwY48IgcA4d9Tx12KCXSP2P9V/PKklM0ydZECYUSy50gBDnCdMLDwX/JzvVQm5wc0AmTe/G/WL3wThlZidjQpSoAL+VRhgH+8qYSEf+EDCBMgOugpBwBuigQ6Fy8JCjiIQtcwANkA1BewXH6/Ao0AM3EpO1WnRAsB3lSb/YYBkAXWtC9gxQSUopWZgOPBvtT70gDAYQHzq/5owcfrLzGsj6AnN0BiHuwBfK1j9w+hMMErlqYLPH0T8uP2SaIkIWZDi/8CsnwkA5zC0qeaCAC50dhN1fj/J+c0/invx5arl0uhb2qFgsnj10UAsJBPJLee/iIu2ePjY3n1VpzvOkL796UL0N/GKADYAIYBLCfAj1Q90PuqwPda7And5zjyI45sDiRRFWsbQNLCGrdiAnSz8oYZMsD/2LuW1jayLEw9VFRJdqMay0UUSDEYHIjUXnamN72cpXbGxFTAwYRYYDBaeJFFYsnBEAiNt0MH4sjtBIfuGZjAQE+Ck4CZLJpsjS39gvobc88993FuldxJb2Iv7pGtSJZQJOPvO995XqX+X736z824IP0X1NTQ8it0/+sC/AB7fkdsEVp/9IhsEhMnj76JjY5BoxdBuPyESBb+zh0uAJi26TDgs484duALCEDtSKwwGaRWqYKNhpsM/yuDwxsTLLvnRXJhCD9V1BYArH1NBvjvAYj/s9EIdMBZVB12+yQEgOUAYF2pAXzHSAMwvycUQIBbMRkBuIIA1HIgiWt5hJ5KApAbUmtrCmAMcCQ1wEAk/0jKjzBAeh3d/9Y6j//huy/PGO5LQuCJgL7aK7T1fBGzCUUCiBOK+ti8E3cwC5KzT+oIITTmvwhGAHBUEpcACP5AbgE5dXe2oQH48EbGLiWbCV1JFRz/tgBg7auWAn7fi86UBjgLrzzr9c06IDJAn3cEAQO4Kg4QDABWC+cA3/OuLx8EbYwbQhWmcXd2U6UCmrFpiXrugmaAAY/+Z/VMTiFhH+f3+WEhvMrXx4SfcPoi9ydIQRECg//2g29TsbCIZAFj0rMYl98bC2KQ/rw8zVvc+UsKQAXAW4B4t4SsAQL+G4fQ/3cO/rNnGv8QAlyxBQBrX1cCPP0EDCAUAGeAVaEBeAzA44ABMsASMgDNBPqCAU4q80ICUAJwpnLDrYvt2UX4q5RAUowCjrj/F+6f9Ovo2by8+UC09q5D6r8v/H9fnTLeVyGAIIGt50ezN1MR/pt9fiQXqaGfmgKAfehWnnaYzhlL9LOP7PhCATRkA5BQAIj/xwz/E+A/u/hs5MqzAvm04PsXNgFo7etqgJ/eX2EhwJligOq+HgnoiRCAEQCLAhgFfLPZiBQDBHzWjUeulRoeCzjn8BhAEoAzndJhQDxBM06b8Tlmzg4n8fEuKIB3CzEZyKU+O02XBz+i/9/aorCnfl9c9Xnq/9XR7DHfWExWlhmdPqbubyoCYP/kTsDVTzvPHaX/Bd3BjlTAv+oARAUwUvjPshtZQQRAATAQlUI8rfGtxb+1r84AL95WkQF4DBASBujxGECEATwPsPTN/4YhZwDuC9HNMQY4qbbRu3d8gX9kAHc6pcCOUyMRAPhqGio70WPE/HL86vkuJusk+glm0/R4Z0vAXwJ9Q12EbWBVgD3j+e7R4pubcZzolyvG/gXpr8oWeLONzOe085Yv+iEpAaD/90kLgD8KDrdX0P8rBZBpLQANALieEbsFP9oCoLULiAJefKwC8keyjb32ss/TgL1tWBAq4M+jANAA3eGZo/w/93WMAU6qHsd2M2+pGAApoJ3SSUB1kG4zldBPSyKADg2+efdtXArWxc3jo61//Lh1B/T/HRz/KZj4CSzhOMyWj2EziLkrQBcSEur5Va0CVn3y2/Cec098sE5b50CECGAEUEH888VJYoXSaLgj8M9df2YKgGw/9OkO4JE9BdjahUiAuz8zBhiJPCBnANgPIs4I6fVkFMAZgGmA1eHIFVNBcuFdWKlGIsCfxxyhIwlATAbL5B7iX7hWia+4PCtEAnMarBs08AbO1bmRLT54Jy5gi4Zls/eWj49v4lKgRO/1NLeRyBqkxn8qr+Q7hfyGwz+S26pj3O/Kzmi4HYWq/Uf6//Fo+FDG/9Lzkygg29cHgLDw3w8PXtsCoLWLYYDXB5XwrCIYgP0xyqbg1VUCf8UAG9dO1cnBkgFOwpxDu5m2hTBWFFCPZaM/DAHSIKApoXZuKuDcnWEA15QYeR2jo0DtJiy3D5wj/gn85UtjcMMr/67riQpgoAzuRNj+Kwggwvm/3e3dlcd8AXBGLiL+fxnp40JgserBB1sAtHZBDPDkA7QDVAT+w2jENwTJCGBbMkC3u7G2tLT2ff/vp64fNORgoM934XTSqxyHc14gRABSgOfM6BZfUgrQnYFmjzDJA9DWvAm41byysJCcf7IgHRlMJrb+xYb31+qEwF/h35nySB+EEgERoUM4SkHO/z+G/n8j9kcOyO4T/w/hw97vFv/WLsye8rkgJACYSTnFHWE93QnAbMAogDPArf6zmhTAY7n22u+INt+6ayoA0AC6wLcQI1E0ZQiQltIAsiT4meE87bnPeZo8d4DEDwYF6DmkxMj8xQT3Ytlp2uGt/+xjTXl+Af5AAGphIs+J8FP99rd5/d/Av9b/Bv7DsLFnVwBau0gN8PTTlUgSAN9ff/LvdTELgBQwwGJgd3UNZgPXJQMICcAZoM1ze/GcU4gBHLct0Uo1AE8akoxAuSeosEUsVj36xaydnjpMvtj0yyRm3j8uwj/N87wl8O84shMymGji0NWouv9czP/NEvjDFfp/P/IbagCQ/bo/2QYgaxfKAD/9tqcYgP9JNjb7BQkAMYBigB9qMguuy17TOcT1V0W5zHWUBHDaSgFcBw0gwI+utlnKAyRiAC+Wa4II/HWnfmJWDuIkNmOGiZFDqee/1PMzCf552xEE4LqS9QxzNQHAod5h9eUjNf+rsv4qDGD+PyQbgMNozzYAWrtoBnjxfk8GAdAQENXczT42Am7rIIBRwMrqbWCA2y9rAU79BWPMCMKuzHnm0tPvXMwCKPx7TAOkWtdfT0juTmbwUrI0RI4H0kF8uT4kptK/5P/jcu7AUA/GBsKk1PObluGf5rDi3ysQQBH/LsV/dFb9BfA/UPrfLAIw/x8aZwDs/WYbgKxdtN198b4akcV2wAAb0v8PEP1cAnR7wABLS79U1H6wscyLOZ20eXV+ij9AkgCe5yADSGVvpu9BDpREgIK4Dta1Xk/KvQM6MVAOHIwAQj+1ZEbYL9w/4L/lKAIoSn4T/yz+94Oz2q9biH8Kf5UCWLzvG/F/ZBuArV0OBnhb9claq/Hp8OFGj/YB8FKgYIC1pVv/DH2e/RLTf1zzu/WrV/O6/InkAI8xAJwYKIZq0zhJizU8UwKQeoDZJVhKFRaSBiQUKFYDSzFCcfIv1aW/HK84/Nudtgfb/zgBlCL+wNcRgBj/Dx9I/GcU/uJqcdkJyQIgRrR2A4i1y8EAP7+tiqA0xEn2mcd9qgEYAwyUBlhbgwUBjpDAMth3nfrc3Pw0KgD8QgLwvHYuMAvQitM5gwF4LkBXBIwcP5X8Scn9E44gLBAXZ/vJjP+5jb9FBcC9f7tTb8HbdxzZ/UgTfurMRH6/wey0cYj6fzETRup/GcO/FwW6/l9pWPxbuzwM8LESiUoA9rIMGQMoCdDFC+OAle4dYIDvH8JgAIsAOP7HMuE3P193pCZABhDrsykFANjmCrkA2hloALSM1j+2hJJCQuIJqv//AP854D/HA35ZAKAJoAx/cmYaw3/UqAWbcP734CHiXwl/KQbuTZEFQJUwtPi3dnnsyWu+KhzRz0+zGz7eEP6/i40A0tY5A/SujRxX+38kgVb9uyk9JqMUAGzP7eQiQmfqOi1QQKzSgZN2cXwR7HXlgAA/ofFEEseT/H+5/IfwB/xPf44AFAX4jaA2fMjw3x1sZplWAJnOAcxORy5ZANaoXfvXXVsAsHZpNMDrg1EUkg71KuYBqALoogbgDHCr/7carsYae+zCAmWgAG/aEwpA6ACOfuSATioOC8nz+Vz7f9IX1IxxUKiJIG3Gf96KNQJ6/1xeMSRAR+G/3ZpIAH6BAPCx2nCXr//ayTIN/yxT87+zM1EQRFoA1D6+fmL/6qxdKgY4IwwQRbWZh1oDDGQSgBHASn+N2a3bL094vy/7HuOmfJ7108tDTQLwvOlOiu23aadeVxyQmgNC6eSdQYUtHennOGCilmgmhdq/MfKD6G8j+g38GwTg+35JArh+dX+A6z859BepAsgA//eU/0cFUPmLHQCydsmigA8HFZkCwDzAzOaqgj9XAJIDNtaYBlha+rXhe2N5aYEOkCXzQgzAgAQ3piEVALsB8k67DSeKkmqg6gvUc/jiTtOcz4vNBaNfbM24PPJvFgHwXSH6Nf5NAvCLBolA16/x9p8uX/9BTSQAsmUW/wekA+j0o8W/tUtmf32qGUDMqU/trMp5QMA+UsAutAStcRGwMww96fnH8tZYL8wRJ+hwFmBXU602xAExMEC9PcMpIDb6gQQs1d6A1NjOYTxOu4jTzxMCGTxoFrZ+4H/P4N/iBMDx357W/p8WAf0JDOD6YbbF4L8C5T8T/nL+x4sCn+Lf+n9rlzMTKNOAvLM9CIeHqzII6PaE/4cgYKV3mzNA79mp5/I0AGK/NTY1gDpDC5UAMECecgJgDCBUAOkFkBSQqq8mHR+SKkFNFMaGKkiL4kCiu0kYRDf+0Hvc+YPVEf/1FvH/mgAM5Ee408cPQucQ8D8o4l8KgOy+ExL/fxaeDi3+rV3SKEBkAYR3i5zDDd0KoIxRQO8OMMBS/4eagvrY021zqAFEO7DTclr8KE2PwQqlP2+0qdfB4+YkCoiLV/H/2buW1jayLDySSkVJVQXypAJ2Q0xo8CKl9ZBVfoJ2IiRYINuEtsAgtMiiF3JsmYBANN4OMcj4JQSyDA6GmSGL9MDEgdCLQJOWXL/Af2PuedxHSUrShFlETJ3Sw7FjWzb+vvOd75x7b+zfWi/EJMGyuYfX5I4e5pdamvxIHP0kAAQFFEMyLlDTRGoMMAZ/Cmj/o/2/u7tdfsDOnyEAeP5PwR93UUw2AEniOw1RBeCgmvwzT98Ewx1eEUyDAFwDVNvVrc2KuNZ6riW7AaofGMUkABYHbAaGoRf6JVhlQ7M2kHSLt7exJYKIzaXl6bW5S7E1BJoSFmJ+oi4JYpQxyQm85ZdAv+/7MQIohtK6jI8Bz8a/293l9h9Zfob/hwpA4N+yzQ1A3KT+T+K79QFe/foJF/iqCjebBQaQqwEaughoV+vIAJvDYMyj/1FcBJhFAKZUePAynudD3l+BMqCkcKeaAksK2kuyCsBKYCk2N6CrhilcLxussGCQSkxSEPpXCn7o+WEx9MXF+C/yC01x/pcEYM3AP/RKjluY/1/ykt9VLQNo/vfYMfAvIsF/Et+3E3gYL3RHWdYAZhFQFdFub1QgHm8fuYj0SCqASDGAXhYsJ4LgIgqAKBTRCije4aaAORS0/NVYmPWehdgag8n/rdCPpl8G0V8MkQLEo3g1oW5a4M+Rij6X/2Fsauz29hD/fTXyKymACgDAv7H/n+OME/wn8Z0zQJZOtpZ/6jfj87rZBEQBQBTQWEMGqD90pQJQk4FaAUTqKG2AvogMPPicbyn8IsjwEgwHLCzEtg9dmoD4D7M5YOFLJLEwxQErAv3iRSDsIfvjG+IhoyOK1//61E99mo8zClb16j/K+w+U/Y8GwMMbrRcEYQRJ/k/iu2eA/5wGZrKznNGghQxgDgNhtGtbwABgBNgq2UesBeIKgG0AD0wAfBCYBw4oSAKgUrxUWlk2R3NmxQ/L3x4L3PALfQF5D18Ic4AXKomSSYUI//RnGoAS//nCc8R/uyyzv07+uBLobvfG2ABUEMDhm5ME/0l89z7AqaOOucWFAe5gI9YFUAxQre0gA2wObSdjrguS7cCUDuwDYvbHEKCTztsdpAB48P07LATAC1ha/p+FJI0VsPjF9/LBjRCvR7ARshJ7FNyxTPHPktbLANWe/3JFfzDOr7detFpY/puNf1X+r/5UuNFmAbRX3AT/ScxFFXCaSxuK17LcXqNR0xRQ1QxQrVMZUO3eZDj7R7oKSE1RQMgqAGS3dt99EgHIAfhcECxwOxPKt98A/x8l+H02+MUrAPQDIwH2Q1X3q+Yf/wQa/5Zx8DeA+SZ7vrcD+O+rwX9j/Bfs/5/8G9r3Q+61kuA/ifmIzuu/BmnDCAwi97i6oU0AgX4mgNp+tbVWERzweGc9i55ZKhYx/PM0kIfVt+8r710KAPXIzFAolUpAA39a899OXXD7kaf8i+j3hSGqfY+6kp6U/jT0k0kp9GP+j9LGnl+G/+8E+aOXIv03Wox/s/lH9/LT1I3aZQna/06i/5OYFw3QeX2dS9mGFWAtdrc3eBgQ8j9TwD78o4Ua4O+VQTrHEwFhpLNoLDD9IgFQ4e0LPe5T8vdNEvA5JA/c3v4p+MsnBX/a22tFmY3iC1PV77Hbr9qTUvvrYQb2MWHjQ1v3AZkAFru7IP9bu01a+zOx/Gf1QfPnXFbvsgYEcPg2wX8S88UAhu9l548uNyZKAHwWHLC7Rf3AS9gjgEuAKDMb/6QAtPcmNIA/pQCKcSWALCBoYEWUBbefqwFu5XYe+j/wuJGe8yti089nK1KbfnJcmdY2qgImgpslywBNAIHzx2BvD/L/fnO1XI4xAPsAzZ4zztGRq4T/scB/sv4/ifmpAk6unZTpfNtuamgygHYB9qu7dWKAjUeuTRpALhGKVQBMALIK8EKEf6jyvW/A35/iAyYCnCBAJjCpwAD9cmzOEMd7tNXAHX8PR5IM4y9MwZ3dfyoAorQ+BziOfzcYivQvYrsM+KeLKIDr/+Zx1kH8j8dwT/J/EvOnAU7e5EwfIGffBOctlf+JAWpYAwgKaP0iCGBtc21wY5HxF2VSM8qADFOABy047MNTIVAMqRCYLgYmoiBv+FQowcUzRXAV6A092VssxT4daw6igDCUO5VA5o/wLqeZMzwAnI7UUSDKAgiCxW71Rasu8P9ytazwX141NgIsH48o9Y8hRPrPHv52luA/ibligGcXb7J2jAGc8aAB9b8mAYa/iF20Aiubw/QonVYzwZmYGZgxBwI96sOjCxD6WgRIHTAL/koEFHGEkJ4KhcJMopgRyDSAf16ZhK9EpP1QvdwM+hcRjgDYaYvHmYxfQ5DND/Yw/+/2V/VZxJoDAP9diX+B/VF2JPD/4SDR/0nMnwaIMUBgW/njaqOqNQB2ASQF7FTWoBtQ67pWKianU0Y7UDnuSgOIe9Ej7Ie+Kvx96Q3GIV2Qer4kZUAJBUH8+gz8pQeAFiDjX7b94hIA9H8EZx7ILoDe/8cN+i/2AP/Vpka/IQFgJKjr0hErYP0J/Gfd0w8H9xP8JzF3GkAwQDqnBoOh/M13t4EBuASgOgDhv9+u1oEBoAzIOZlYO9BcGJTRGkDNBMrLx94gDwX65iK9WFqXCwjkc0nxwWy9YOKfvlMmVO4/8RRuaxhJxRLRAIByAdRQlJ1bvFel8v95uWzkf00BD1bv3lnM4rZ/iP/RaOye/nqW5P8k5jCenb1xbTjxMqccMGwGSBGgjcA2Lg6iMuDxdnfEp2mgmWYQgIY/aADmAA+HgtAQ9IvEAOQNfqEM0PAumMxgqn1/KvvT7AHt9SHdfwC9dv7oSmH6t3Hbc33ydy5nZ//otTD9774sl5txCmD8l5+mAf/iFgADfPr06fD6dVL/JzGvGuBt1lYEgAzgBsOW7gPokUCgAOwHrlU2t3o5K4ONNB6o16uDNQWgFRjK1QGetASLoWkJ+F/wAItKCcwq9mehv0gjAFQB0PQfb2fKyOcR5in0s/t/NET4t/b75XgMVQ3ws5UXWX/kunlX3PPZ0eHbC1H/JwSQxJxqgLduOjDKAMcZjdAKNAXAvoA/XfXKL7g2oH90gwyQjtLpmQSQYR2OyPf4QU0GSCoo+rN1QGHirem6f+LTfJ+qf90CoOFf3tFUL2KK4NRjmv6h87+U+59b7FYp/bc5+TeVDFAKoOcsLjpH3fVebyCi9/Do+sNZJ9H/ScwvA7z656GtGQDm4Mf5dV0CaAEgLhE0GFx5srGetZgBLBqmidUBoSwDYCDHk3MBNBsA64SQC2hIyP96ITAtAFRPgd6i9r+SANQESIV68D9C5CvPj87+NMcggpE70PJ/Zgj8H4/c7vnLWqOxIaJRuzz/x79PDjqJAEhijsuAV7+dBoFcGmzBwZY5tAKNHiDjH3yAdpXHAivDIyeFwLfSdJJo3AlkFGbkdHBGyQDqD3g+rRb6rCU4u81HmDfriKKCPwsMngEISQAw+omrIPNHs/b+DfJHfVj702q1Ve3fJAkgRcBq+cFxtjtsbe3U6wD/xrvL4e9XZwL/ggASBkhibhng4MN11uJ17RathRPVcKNaNRRAW3KAYABYIbxZ2XxSe5iFKVohAKw0ztOTCjCbAZ7JASwBiAdCXQ+EE2sDCOiTjKB6CIx0zw+nL4K/ngCkTb+w6o8471sz8J8bf1rfhfRfn0z/zbLmgLvdo/MGwB8JoPbu8t3Hq7MO4R/iLwkLJDGXDND517VrmzvbOI4bDBrsAdSmGIAGgyuP1wa5cfxUbds4LUCbgUbIzQJgMsBTo0E4LeSriSHew8/0CoENsG+glhnCbn/wNmmJUDkN+B1D6QBw019u+8Xn/U7u/D+619/bg+G/dnMK//I9zad/e7S9tSMCGUDg/3fAP8L/2X1JAjqSv6sk5sYH6Jy8yVuBcWYI9Lh61dqUAuAygLYKEyKg3XVztigg1EHa0gpMGWtw09xnl+eRwFk7IBKABrBzXyRbkFO8ahWQXYheYRhDPuR/6SqwlvAk7ENj1x/sVaZ4yR/7fbrpL6se23F6rRetjVar1m9OpX8lA3pHgzrgv+lYqK8AACAASURBVA5XvXF5Wf/4/urkVadzALcD8SjIoBOLZ+I9MqY+QLcvR4xZkr/Tb8xv9yd+q51nna//6vHX/3/zi7/fOXl7KIAcaBIIctlHMBNUNSYBmAHgYYdFwNYgyNp2LsANNYgGlBGI0M/J1bIT4Tjic1KCBHA4gOHtqxQvR4dCrQ2wacC5X+Z/H6cMfLIaUffDBkDqwEI5pmSndf6P4z+AY3959u95v99vUoDsh+yvot+7d1mpbGGsrW01Lt9tPfn4XjDA2dnZycnJhQh8upqMi6sL/d734pr64ERcXUx+RHzh/7J3NS9tbG38zccMZ2YytJhzIYtXCHT3dh1cObsuuysXyi1oJF6FgrhwWev1UghIcfsSwRCtIsQKWomKAStIRbgLoe90kj/nfZ7nfMyZMcrtXSgEn5nEfEziZOb8fuf3fJwzW1sNYJjHbMM/att4QC9/0sTp2dsUx334gzzl2tZfnxzbSVw5jK3vTOn5QTX861gUqLIBkzMz+6OebctKAsUASAEK/FQ0Yw02IAHkAAR4wlEwRhTIDIKvOvtCQSsLEeAHsYEhxkTvr69Xqqb9x/mPxJKc+Y9zFlZnEf7zyx/W17df//4LTf1jRv5p8s8N1p7Y39//TLbb3v489XbymloK3K6lfe92Tl+MPBl5Njr6gmwU7JkwfAivjI2No3VwucWqnfFqFe7J2sft9u7ubrd7dHTx9bHg6J/g/6BarY7H50OdiHFpVbJOdbuzLR5W1at4/I++n5+f72Gkd+gZAEOBtukGgBwoYEXARIICBAmsUixwEm1mrur2bCntbTG5hnQnJPytuwyUgE0QziJRiBF2YpAtLPIV/V3MnIFDTMMDli0U1MA/PReQ4gOpAITyNwmAdtDGaKcY+f9Hve31Pc9y8tlMy7SszUEbhRYPvSjq9/te5PUti7eejJ6egR0fQzMZH3sx+qzV4iXX9eB9ZU2v6eJSasJSKrm0yifKXLIfPzz8U0oYvlwSH6b3vCdHh2uPDPCzBHAxHelTEtI9HE3PycjpIeLZrbOqSIzKYfp9+hTc2S863YuDzeEu9yqXVxoHp03uOMZFMew8G6/Pp5wAEQ0AW5wnAgAd8PnfLjkPeVlZg1NqcNX730UATJEAoC5vidG1Fg2v7dGbUj8Y0+6Yn1UvZAtGATJKhIIMPKp5/yT0b0z9z5m3MfEnoH9+eXVnZyPianIvMh7/x15iP5CSYP+4ZXkWtiZsJkANrC9mB8TtLZwqpNfr40ihhOHoIbp8mAVNix4GuLAAVlisPg4voC368e8U/zvgPBo7bzz6AT+Z4+q60K/J9igOaWRFrCDSSioo7fvFYlE/N64ajX0PEIhrveh+3WwMcclHubbS2Dtrxle5RUCjg7w/lWCACYMBJuYmySWemRov9aQXgKoaVmjM2J7FLQHckNYkjlMoJ9roqzfEu+gvSNAnWAUeZlSuUeYc9AnUQ/0d2fknBADAH7r/JYT/Hwvg5W9EzCLiQfDHpqjM5ABBTwl+otyJeK9nxbsXhl7K4BV4DRggRBa4SYqeWsyjZNExDBzn2dXjvCM/1663Om4+Bn9P4D9kBvr1PNZJ9JMXm1cX02VeqTlyfLU3rHWfmMuqre0dfbIMBkA0R3x3PpUIxMpgYYvzIiz25s2u5enp8QExgFWkAMS/Cf8QWn8QogWhhavoAPmdTkLAcQNOXxQM0g8ZUwDoAILOPRjpvgT+Q6u9/J4ujlyn2N96JNnFJABBPUQ+yp8ZGNK0YmqQ4oXa2g0CQPiDEcAl0BM0EGr808FKsgQL8tnWxd4jA/xMw94c7TvmKYvwwIYcs9AS8MZc9hr+OYF/FLaK/Hk+cr3R7tAGYpACVhonp03bcAKg/+u51YnYDYhrgokAFupzSABLb2fqLVf1kwDYgCFqgzRcQrqF2tJYvjtaEHeGSR4wxx/Eqcc46ZhXvb8TU4DNSuv1j0tT2P1/oDD/q1ZfgtagAIQ/sQ8N/tMhTXY7BVgk49UGUTRAAQhQS2h7stvX/b9cQ6JL8x+Qi2DnWkfAAOWHbiqJJ4Ps9o/eb2qtdmAzmrvRYAArjHKiCsW4klXLL6T0v2hEccwJ2kS+7wadoRRhpABW1hqbh51mXobvBQFwx1vfmY/BLx4oW1icXUIKmHvzdt1zNEAYNVchAbgM+As8KfQEggkMgXuHcSvtSBjmmP3+fxT6VU5To9+OL4dG836030/OzS1PYfKf7LdMv6eJhkn4A42JXRYsYCl/hFnieVoAyOCkjlHedAHouZVc9O+X3b6OFEjCjP8Nd7K50YsvDytDa2tbjTUsfRDWSNlaY+0Owy227rETrV15QsRZJgXYftH3k14AMoJ41CI/kmaQ5nH8WXiHPO94HlHAkHEA9P4Afzg1e5fdpqUcWqoH4E4vo9yAhABYwGVhoT5F1TG7dqgwwBEwDBVAIJBkS2/a4qJvlagPYhkQWH/T6AOJrtFOdP8ZrEpwhHhnWOZjVPw5FKKA3em7YxOTS3NY+7eoMv1tp8fizARTOyxfsDg+5syguJjMUumJnryhAPBuKAAPiU/39F6QDgSEtyRLpAzNZzPbX788ZPurnZx1OmfCOmenZ6dgHbF0zuQbx/J9eKAfiu3hdtzpnNwXg5VrFyWauokldCZ092kG8HUQQDkG2Jjyjg7tiIaByTGv2TkfsilgyrW1xhbVmwADXHwqqcCXygd66AbUjTwg2urCKjHA4sT80uK6q9oxp94SGcDO5qjkV0zIreuAC1keR9gJEaLju1sC3EoSdjzzF9YeOMp3J/wb6Af82/hbbOa2Pr9/D/CfW579oEt9XvfFSdZyJf4ewVwiuDnILMZue+OuH6Xgr4MbLI14TTMopySlObnn3YMvDydCy2vfKEfZdN0fbgkTmF7gSqPMZfgjwMxIEODqUpIkVj9wnl03KnXvLZ25dlxihrKTzQkFQKsIsh8w36JVUYD0CoQIkGqSJIQMDhEeuBd0h8sPKK982TzEylbkgb3z0+mQwl9MhQJsb1SMDopzAPX6IiqARWCA1dXdvGd46hiw43bBLz7FBdfY8EmxCIcZ9BW3tMQlKRD+HQFADSk0YuRZGfG3sXt3VOQOMOsk0n5YroipTVT/f35Mdf9Y6hfFBCA0gJE4YtYNlA/IZKinzoCtIpo8MIz0D6UogOAAyTkO04wjtJej5ZNKTGJgNptbvzh4uGxg+WQ66bcF6ryrnUSmDDimLRnnZkIFfGjxx9vfvC8F0Bh3WSKKhPtoY9rPLxoCwJcKQDKAGqciNULG5pqVwS3Gdlb69rVRGyICaPzv29Gv15eHW1jOenndbbo8lgDIAH3eVgVBsQ8gFMDqu3WR0o7xYGd8ifxKpfK0An+KlZgCiriCFXJZroW9DgsCSCKca+8uHogMshCX9cHxC3hqGFcdtpMS/0QCds+rzn6kIX3LEztGre+7DU/FAJHC5NAGs/Gaox3kHKjq4uLiOslqGFQsJUUnEm9HXyi/lOmAP3lDNnY7GVm0rMdUkkvqk1+Kh4pORz7zvH31YBKgXPtrmlywMB2hZTFRBkmu5GplMrxqfV+7tyTAiBfXixRkuK84yERvZfZV0pAsQMbaFAYWZfLQ2KzmMImA8uZZszmy/+u1KFm/vP7+aZobBAAMIGKBejwQ9P8yCrD6O/NM9Qrwy6l+vyLvKsVYAJgHHQ4ssCuXAoDumRwqlItDsrlcKmMLyDKCgDphwUgBEP45T4/4zXN0AdzWzkfA/9Lc0vwHs9b/FZBYnLy3E20h0UqEVZSZwiZl6hf6BbWA1FRdS8HPcRHiA/QjB+REO9PcAbBv4WeKvlyKfhYVAEY1c+tHB2u1h9KKpyVMZaqKGlGzBAsbKJPMiInylTh/cn5fe187164lFz2P7IPEXVE2yacDTp88g3585+cchQjsYEqdoSnMLJcPvwXcnX62fy3HQVxen05bBv5RjUZ8uz5bN2wB1oXV12nvPUNHWsK/8rSSPqgKGmrxCzYToT28zxb1pgb0fPURpcvMAQUi6GcsPFn1h70/bWOB+v/v5FskgIl3v5n9vyoDEHLEx72uJHZdG8L+ZeXpywou6Y10u4r3W4x7LihHU9adwWsZ+c/EP9UE4ItOSjKF/OH0uws5mdnMPN+++vJQBNB44hIBhDp52de3Xi92hwbTAdZ4c2vsvjyAf61cldRZ5aKXV2g3sJ/E/8sEDTyXjU+eCWiq5J5hCoi7I1+HhQFq500M3ZWmv3WvkAH2Ng/BDfDM0YEo3aL1z7PKA5AKYLUdJeosEMC6o0zAX+LC7FB9xa8FW0fAs0XDVTDAr84DYarYMhQHhmal70kPeKrqV4z6dUBnbEzM4Ii+92+XP7wS/X48+q/Y13FJVqTdposRVV4m4U/Yxz+CCF5W5I9McQVOZ0yNJ8FavulcFnjsRDNekFpTbVzU2NdfAr6oOBdZkAAnDxQEqJ00KZYniCuUDMBAAeD9/7m7ltY2siw8VaUqS/WycNVALWwQhF60tRbxItEuy+yCkLHAbo8VGQTGiyyMsdqTxmAw2Tc2yJQcG4Fsk3hCOpAsPODMEOhpkjSy0/MnksX0Isu555x7q25JcsJAI09y5Uf0ckpV53znO8/7To6I0saJxQwPqBQJAdgFszrD8gD+tPNTwC+rZXhc/sQtD/fz0f1eHiBOfJ5fR77sFECAT7HhhydfBwJAxwSUthfTZnV3/PmLX1//8/Xr0svxwM/EfgC7igYzoTEJuLfZaMxOJ+usfDsr6f9AFi3phCTjDo+z6KqkQnk6+04CMfoYANd8jgAZo2/mB+/7aT6ulOageHlpc022/kfQ/Duj/MbL+JioZIXngruRSTYB7rIHb3PlJzToiXCyGyg/LGG7xfwTO94eiS01PnHFtC0+nO2FAiJC/OTRX2GeTwrrMw1F7Zxejf+ZWzit6iKgTyCAik9NHO84BZDTI5m0XEwNG6n5wU9bQ+MrTxkAAF3pWprs7ns9pij5lOz+e31grPD2tMxXhAA7T4MMhtiB2AXB7s1fS+VSef66qfv8MlL6I5XRbwEJQAIAEYBp9oyckiOQjcCUn7IQb/CFYh6CbNsk5/F5DX0wKGmlBzHwGvQAh+MpMgGA5AwmaP1MRowmkpv+4NBN//D7EvYv/jCLpT9HaPmP7qzR6L8/Yx8i8RBtIBuMUaAw4KkotJmVLUY+OmZeZiKPQdIMKZDhcBcAXwmnJpT5P4VLbA3rG/2Ualw/uxrBy239XNWlqkbp2qP+Uz9XbyrTxzrKqNDBfDUs/yW3fz0QIWbb+9RKmiMvslAkfk4CH+yM+FiG9fyrqMzO7Y9DCAxzbOdsWcHuYalcK9UOdZN3vQCQo57pxkFjkel/o9G4t3kXcFDy/iPrLXP4EP9BCVeUa6JSEgUg08m8YiZQWjKCFtFhx4v/EUoAAMkxJAAZtP4i3G4kAMDSD5ZLNdjUoI6Vv1T9d+eIz/5gKDB9AZwV8726I+z45eqPQQJiCAP8G6b3eTHjMHLspWFoBADMpxf2X/eFuNmCLgikyEcQYmuaSgGZlBq++NvVyN328wAA4Jx/d3WeH+Gj4HjkNsp8YF2GVDR1Afkba2gxwNzeqEUAYOmO53nOpfp/KSj0IAAKq0PEmGmEcf70a9gVPncS8Cp9Cy8su7TVieVyqVR+eS2I+90wJMCwfOJwlvR/hkoGhSraqDX5ZK7PC23oqrIdYAYFpuZQX2UotiNMGw+uw8sdJZN2SKkuuUxkHR3HkD2ADDkpqShHl2AAvm+ZNzd/BPWvPFiCvr+1tuT7H9HErxUrClv7giLCzoS3BfMXQY1szPpvcxTodXRQ/1FrBX3nxSVxDBCHnNrcCWA/DWH/IelHGQAATKKgDo8BskWXwDfSN/cWrsZUPKTixvPiOXx305rNoR0zFqHE6ODGngq1MMRUD2+O6JqjT4alMgsnov8KAEBIm20npk3aUu2P1BTE4MxJhKoiU5XNOkaa5M5XgxdfQVFg7rTKk/EW5wCmbu52Sm7ZnfsuMCUyR+l2/+bRbONeo63ofqz/hoPef54TADpdjpFRsq277Y2lOk0PqK/Pb85MrzQ9pq22EydgudPgiBigRADixf0BGwEgHUUAMDNrSPuTJBiAFUw8/rGEE8zmgP1HDkBk/3HknxX5qeqgpHBWxDbA7ye1pxfkEwaD++xwpHnHpmHGcTaT95nQpiYyBdDViACEpFAaU5woA0qlBXAvKg8aO7kSAFg43SUCwGSkyKhi1+fJTS9MaH/k7gGm4ScKOQJY3eDW8dAA4CzQL7D/+tz3BIn0ms1moZDtS/VScrdZaMKC3x4MklI1Z0Ae2DPQIgIW77768mc0gGNHnpLw7ti11c1bj8uuW348SnWBpP8ofRndP7g3Oyvaf3j0Hx3gKAnGTpKtaoWV9nylPJJYrjsyUl5vzLSaimrLyVlSMrK6nqIy2Y/OOtYTFchEwldUG0zXwTCkTUpp3y9DdP2FRw9KuJnJg6UNtP7IANpR/I8YQMtK89ZfXYvQ3vHijL+c9qfyhmbzG5QV9ouLTUH4KDjMVC2Oj7L1AVZRWh8MnHwOc9AMwWI0AXHjH+A943yNjo6NjbG/EE7yISeGz8sdH55uXYWl2PoZPIBzC+y/yX51DfBWwkSkxpsgZ4giP1jNAExAdEfowdP9oWUBX1R1kulzVbj1dvNBrYLBYDHisWdVaORtpVJfXpxdW2lmVdVOEgCQT5VHngx99MsvB9h5HkgA0OX+nX6hd+qMBNQPgoD3wcDcC6xY1c2w3Qnicve0BqYPU1/cJDqq1vx2seKSyrM14tJvWuzR8tzm3aamOjxsKFAAE2+e115cnp9fWl9fj65SZTOuHEhL44QyhiptUyxHAY2U5XfqJbjec5X6LAz9hNvRmjT8k/kAbLWbluj0TXNBztotOABZQur176cnuT/gbVRIWoS4AMS0RDqfmT3/45s3b/l6I623b97TTgiTjAK86/LkCXFRZ/xf0ovFu1dXf/83b3egKKBfNHbPriL4lNt+bupEEilYBABgc1hGq5/toQCI1+DQaAQAjItXh9gJ8DTgANDVBIPUDqZcbolGIuHkIskfduWny/WNTkHReA1LHN9WIRwLEZDg2d4XXhSc2/6HKQCA4yVQgPOubl17yRDAfXm9avqJ0k5dtzBoz9XQ7w2xOkpherbkRqexf+EJd2uzHU+RygTz3Nn2mqX+t9z3OAVwwri+OyXUX7b/OARMTV34GPsDLZ27v9GWjX87RoAZ9mMl9U603hgCAJTDvmN3p6Ynqbwp+82c/FHolVMtxYscy+KbR5esj2oWZiHDhNMUp0+UJQid8cFv+jiphThq3aCEp+4PsZ8m4VNjCAAagJgLYBYtXXEgYBF5yXEdFJZBhBgWgFeEoQCAbvVseFnAiYCzWt3mQRZP/dZNrJHkPQIA2V6xRyobLU2RXQD0Amhkjm+Yr6Jr8WUOcV/Ye2gJ/YfzVbS650VM9epW8QhOQfnxWDXO71KzXzeRxGIEgIw/Aq1WmFl3Iyj95Jpa72QVmV+hC+B0psTlwL+CV2LDFoEyLfqvU4o0/lvs/wG1f6r6G1P/Gob+mfpvtttr8o1iAGD+mf7fbWZE411aVwTd09qSWeA2odbMF4gBtEr0+VBORuhrriC6TJlf/OEtqO7qo9XkYo/8UsznaQ8jRgGoDpCnCb1rBADyu9idG+/zQABCBQsB0tBoEzzbHr6Q5bbOAl24iMgA2JGH3C3jJIDd4AsWRDSIArB/qTwEYFnmEJMA4yaPa/kCmD2lHZn+T0umKxOCcqOl2lnZDfBs6C9LpXzjornH9xDo2dTh/w0ILpvXsnBS1Un7pbZ1hICuXqweui5z4msd5gcUaTiG3OWWJvufB/338qT+ine3/gnb37eWDmw7K7z92+hhO+3+t7szwo9zFDiMYtwLmNB/mEpsGBf6d4u1Eqn/OgX/JAoQ+QB3ZtZmWgolMwjeYjKz3H8M9W9uc4oyPdUvMMt81CTTf0V5v8o0+Qbq8I3VG7CESv/lPW6IhpG9DDQI+iI/oPyHocZq73r0diyP7emK7VOLne6blH4SFzSWuD9O5nom/MDP7WeUBKQUAGMCOg+oQ+Ji0AJ5AGwIKdwBQmaOHw+tE+Ak6PYCgGMvflYyyfhHDADBfaR2VNCyMgnwNOYCGIAAJvPHcPOXHRx3sr8Pc1F2dqRt4y6flpS7fP2xmk8HiKtnp4Pc1imFSuC7yMhdkf0SWFD0AQHIDwgCGk2FU7mkQX7k/wv9t7WV++5n4TV5whtNlXhjnmfXsv3K55ZWGADkQZiYNBV59EHRtCT9x+k/6jvreqNWQvJfX19ucL2X1L8tcgBrnYKeNjLRpB/fFuGswlzvMbjuX5GgFNjBrvUfoLuRAmoPBi/U1I9gyVH1Sf1jCHj0kb3OniQKwGxiV+EA4E3+/mgAAKz+EgIAQKchJmFg1ooJFSi5HF3TSOxQ6D4nOrlPrf79cXArowUaGXU8gSGAiABYvpxMC+1BCEBVTZQEgHRcMLxOgIUzEQO0VMoisaMs/BBRykvX1Ai7uYyETrkxER2Zb6nJtJDho7j5+sT+ArsO2/vHT/4u1smT42PYVmQwBiTPec8t9/m3/C9ggWKCff4n/NiO97Z3/svbtbS2kWVhqsoll+shG6saNI0MpsMsLK1NCka+Oy/bi2YwNg7E6USZQEPoRS+EySRxYwiEbHoVHLCQX2SwE9qDsTzEDQlkOriJnYeR7eRPJAv3Isu553FvlVTqSacbfEvWW3Kp6p7vnnPuud93SRMcDw7eazAAaBdAwJ8EAhnkIQJMyJad2DhTcWm5HzB0iLj6P1cq6Zl6/4u56NPMH9r0mkGziJwDWPgmZV/RnUWLq2l9WIshsERJ0/8mwn8s+/0HFP5I87/67fl/yvD//hy2+3A32aYWneNQa5g4kAIAMINk0eJ4+lfMFb/kbMWtNABEQwAAPhXtmHtkyxoC4B4DgIwBdGlQj+falgaAPfhMCgL2iiXKAVqOQzzFEgA256VFzi9tbm7uYjvYPXjyDNXKLukRu62fUQe7NNguWBY/jhm+VlQDwaP52/jm+Sc15SYeYqIIpy8pt56r99f7ZKgvI5U6rnsuCLlBAoDKoDQAVLZOK3gZvL2tyhabehWmuXCHbDwbRfqK7/CFr/QdjQrnqkbL5LCPa04lDHiNpc1nT3Z3G2d7CzjTs7y8fHZ7GxbWLK3cU0d1Zb5TW/ntNr/S/hnFtwZ39HM0qieF51ol6u6tPHyy29jZOiNqIElRqw1sbTdY7gSBfWW7gjVACAAw/jfJG8AsgG335r/OMmZuFLwkL6egZZalHF+kB2BUpz/B+U/4XBs5S820yxF28W5q9I1mh30eaSymaCFGUK3+ZZI4me3WH5yboLq/G99euQmsv1NDl6urq6uL0EZwW1ytrg1NVetHwO+QCZH6H5YCGAGDmVmNUr8jmirSFEDf8NX0Dn5VNUuaX9rcRw+gPNPiAXBI8K4U4Aw/WPWRZyowKBl7CQ9AhwwzH0olLiWgulqJv/nRl8+Wlh7vbI2c7a/hec3XPDF6YXvj4NkSDjyXtHegutkSNS1CBu2J3FinTLbHz7c7ta2nsh/L0W13JG9TEhBDgEOvaVHlohz8zV9fv9pPtZMiFjXpMoBTnQQY5LJFucO2qqYKeqpfxcafsHdt8wnLx9ZNENANmDE+abQUhpghyMZ0hd7IQWOk4ObzTekhh7CFoe25rjiz1diFo/x8B1uDNmp4Xzd+ST/4SHuqN9V+afwC7TFs2J7itQSmxvZor5sHyi4i6T+SO1qp9W5JEABty3u3H8rjxHzVnAdswtgP3N3I310Qq+sP1tfX1tcfnPUUs5JQUYDPDgBGAcbk+KebP+ULvl7AKmCIsYf9ySibsq857GmYbCKSUKoDAOqxxPSf49bXp7PjkP2D4X/2yv3VBRkyoPIO+zdvQANItmNkL4NBNeOoKgDHUus/IFvcvptj1SKf+s/PpQHg+oKhmWWKmM8vq/Bf+QFqSDeKpGECxX2OoeuEw/1EBBDnDE5KJZQ8gjcTNZlwRx88+nkZBYc8W3a4ArDwyF+Zz4uzcuB5iEb/n+fSoDUfH5D3PQJ9LFYr64dGN729y70bBzsDtTzReh1iTwAfH6zHraxOvNzd2ep3VU5dwHskBNi+rwqdM3s8YzGDKUz+GSelABc3cxkAAsDpTQKs9OfZX3F0qHI8FA/0bcP9/2kUC0gEqFpJFyDAhedQGlPIH2muF26FTOh48nw82jnYqLg1OfLWKnLL1/IVeZ2v4KMaPssQjk0+m5cbNHmLDT/b2kg7Ck+XeqaWhwo+0KKq8afkly1fOCNvPRs5aFpI9lz5nwZ2Hm/KeOBZv4sLpqS1g9cP3P0EA03F8geQgXvl2u1KHxk0fV77Zl6e6P7DbXrRUmvv/Gsp+8+OTZmqs5kJEhoi8NETAF4ozX9C2r9EgOkbV89/tnDkHjFJp/PG1jIkivY3bGH5co57/IArGcy5FABk7y4yAATp+CAb3cxZtOIHZI/fv0IHoBxjQBwF/PiiEBMZG6ah6v18iRqx+euQ4dV77QGEvLbGdkJp+ESwitpCsKKAKK8kvouRBkQDm4+Wl+0jG31SmNwR2D9qXk1neo+AeQmuPM/t9SrKvQM6V02KKPuNN7B6BtRMaLkIIIMrAAEOw1jpXWKXhCpuZb59/a7kE/GeoSnd8qc3CfDvGmN+IgfYc//3GHwUjambsRgkJALc+UuQXABmKJozOBVCDv0wLspjVyAICLFkJl8YgMOJroFg90DAY3gCTw9+tCDia34xpFd4K4TqW/HCWwGfF3y3oN6FTY4JrgvjQxuhJlJwyn/h5Ws/b+8+PKjRikmUqyAMEIAGRPsAuyi/GCI63N9WuRqnnqNFuwAAQfVP2H939/ikOrjBrXT+7W+Tb3M0WV43VDJR+wAAIABJREFUkSU/5tGVjlcXLj1xDkdkuDIxPg4ewPT0jQd93hFT6sUrbymLmdD9CTVjzfFxV7xI4Wbal7n+RQDFjrmcNRmlAeA7M17zU4RJgJbxPxkDvD4pJoiMDRrdDct8N9MhBTjzqld6AKR4FgIpXUise2GSKpUdIn7kur1bGy8P+rtgUCI6F2yK3DzU2mpa5+CN9JOZlKmZ/DohvUDZh72YuY2zgNDC+AcDdskfeLEct9flF/0lctrqlup5pzkJ8LjCSa3DjAYA83x3B1sfI0sfa3kwhhf1kCAgOzucXPsdYGFsgawVLS1EWQxEUNK9wWgAYMFWGjhCb2omjQ+3stM4vlbaOTZ89zHhgIP/hZirHeauFjQyCO4ZhDLwsBOZbpP8fTjP0kep1bagXAqeRwcA5GiaNgcCCV0aHEdadX6ohEV5ALlcMR25f1oYEN2nQqDc8GynHOBbZtbyM3a75mATSIgzYX19HBOW4AKMn7t14egNeT4xvS4dVMxixnUN8XI1J+MHxEDg//V6CoS6Z4cZAMy/p9yDKLrmkH4xRPNFnATgcVyBwIx2AvbegsH7JGNGyia+YYQnyQyAhov9eqnE/Gg9KgeA5hzSWWMPgG2W3Dbpe45eEJpNFDsF5W87ia2we66DwNbOwuQfHCVChlhgqsjzMhoAcu8BAC4iBMQg8KKuygQy6usqp0gH1NA5QENNVVh932fVyN5q4b+x6aZAYChILgGHEZn9SYHLOoVNxhfCAxp7CRzsUBszw29I4xHTXguGXNFBcwYp6e0wZqhmkKGNgkJ02hwFAfi6k1TRabb5ANIbJIr6JhN6C4z58RZ6VZNzAHBR++YBl39SqgInzVT1b6lv9s/YP2RZPjPJk1i4k46wv//cCJgvC9LgOhVBaoPQSR17LYv2Lz2AifH/rjqeEys7Yf2SIwgNbEJqJDvAY8s8FnZPhlUicwajWUs1009BQNlO/7s0AIxN9pCVyquStacAoKVhGkBefih0MVF6YpGQEX7o5ADM7Be/5FkDq0dDPzo18YAh2iAeMMC1E+vx8VMkcJJAgVjcoKlqwZP0zCoYFLGaE9eKUr2YcnkMv/jutfxhZXT/FQJcnNn3c1AThU4bE6BV1k5tJcC9LQUAtqFSAMbC3XiQ/4jlq78WCMheX6Ci9WGsCzYdMjawbrJidE7xNmTCZISApC0KhyydWJJaZfA6DdmCdTaFHONBJRYuRLNEF4FOgcN929F6mkKH614ndm1y45oph4PBAj0BOucs5aOkPJoxpIQBjP40bwaB+x/I/6s5Q2n/1xxcKp+zFsfSDva/hg2l3RAm9UGF0tGCjro2DQgwPjFx5QL3f5IoDEmrVMkSAZryQWz1DrpM5uXKZWgSACsaIgIBuYMGM/R0iA+iu4s92pxL9X2eBSzPtE8EAASUT96mAMA0xV4SAMrxLKACAB/sX8TWHNoJV71NhDGm68Weg/CX8ADiFIpoFTKNFcmaahLd06StXjORKpZ2hcmLomUE1glkK8vK/hkEPgQ0DchlALbw7Erj9CYBRjkHCAWLKgVQRee+vbXaejTWZvr6BWjXgpjgss9yaNAlDwCjexJxY0UpNHxyDjqdKJthQI3mtugslOfYYaIQXzEtix6hJLjYAwgRI0LmZXecjv9Sh3I082drfS7tRwql3SU8luLBEVY0iZOfS7rglQzmgNAm/OrEJzsAYP4RlfvKIzuXIbKsnHE5SjvYPwUW87YbnfSCsPu6lYGrEgGy36x6eUVHmyCp1okLZfAhegAJiWLTYPqdXGYqy4W+sJcRRihjlw1eUzqcjA94IcCdha4YAHpfxVUAbP8zOhCQ2z7WMFt+QsrczIj9H1NTgDgLqAEgo/MWCbUU8RFJRT4IxMqTdACSggae4oPQem0gXYQev9BegSoXYyfAtliL2QjeAnaR9ccxwMWTUo4WOSgCxKao7J7SJMDg4JJQ8z6OzxFAYA+xrUdtph+pQb6j5Se9gOsLiTRgQAEWymEKzO1pCnktLksp2v/xdj2vcSRXmOqeac1Y1eNhuxccs4fg4IO7z4IGD8KXPaoPgzAO2kPAsdlTCMYHMewKezD4IgyGBbEBoRpIsC/BhJAsJN7LnrXGBtm7+ifkgy4+pt6vqurukZ2TerRjoZ2Rprvrfe9Xve9rVOLkukvuGcjOrlOE0NSFYozgLzR/a/xDlvBaz9cJF9Yl3kMCH5bnPEtegwMAr821/klNjrdvj4geiMg3lNKO9ybLYIfVyA/G/H/mD5aFDtYCwIM0YphW3Y3AVf1jzyk4oA4IqL4PQpeHx6XP/kQTzE4MJlDYYVZqILABHn+wucTdAnjuKQVwBiCUPBLvX60wRo2m2xRKZvH+3iicJaMcZS1x7rw8eSMA0OgCSCFw8vT9cRw7KXPSoEnev16WAkxOGwAg41h5qGAk2mvtzH3AKk2cBjmts/XOooN4v+9DgCP2/+vs/zt6rpgAKgGAIj98MRHXf1tqgU9PAACgDyDbAPpHb8+PEvwfdwSqZNpSp4NH1UeMe9kxhQc+CULchXkQmwMY2BEKRsakZ2D5ikndjcgOmSjJHQh4eZQefiUs/dJzMlQiT80RvhykE4OKBDgMAixYPae0AtuR8h7/TvqGfqGr9BJxTsCYAwXhVUfs6HITL37B34gUBsml229x1cbMWV2WQgGWjfWmTFHx/ulPVvzA+bNzteF/Nd8f0mipvYBPugAwvTtsMrlo4MiJkoGIalJ1+ujSl9/+DThMBDvpC68znIZhzQHjZKBUkv8iFUF7elmKJFxZ/DVvCa9WeG/oaLS7UEQSFW3XIz8ISDFC9SSOvEjpqa8BTlr7gSkH+NCDJoDLAZRKovxkEu4CkijgzcnGRsnEYhFprxMRV6SEMsTEQCBi4B7lXcxvgIRQdPqVwXVo9PMhpgzI468SHrw76g+G4aoIVoM93y9ev5hMJg3/P4EmQMatW8am9QsX/3lOAPDbP/5bmgBHiRcAfFihUdds0tP6o8fUvw5hADHgW3b/axkCANfh7O2QyeiAwIYJYRQOcCSKrhdLP8i/cTjPkgxymW5ffsCmN9GgwffhnFhsdGx0U+fcvraH4NGDpd8Q2kAF9CTvIwvoketM5EabtgSH8CTxORV4pERqY49xad0TXI0ruyvt2cpldT76Kc/RrayQYYH97y5W4dLg9RrPPQDwWMatGz+1AECYtvA8xP5tundh9RIyT7zzUt8Jnr0n53FqUFxaU8ngF3ylirXjgpyz+WMPGOFqNL9KuWTW26pCuIOPWNXP4O1U1C+gCeAqALNmEZAQ4FW/aAAABCOn2DlsBwCvL26MmVlIKzTentxOWUAoaYv+BlruQLB8FMgq5iQz5EWKokDgiNwBhhTup6TMQnWJnBwFdFnCoWvD2kUUARTFyeuZBwABgZ9NSX5XOxr3c5wE+MsPd5jfoi9brdJ4bbeaOrOeTtm5f8L1u9dREDDfD4ggIwyJo5gpUdKAxzL1jPCGLCnV3QMvoXFPSIRjmhaIIKupEUwHKBgbwRL+X9yAaoicAZG8jUri1u/zdaf+UaBOvZ47Q29+RmdxBeboBVDalQIAxOAdb64EcxRs1isjN3UpfVTHDsK1NYoDqtH09+8c1kT7vp3ILraqdi4fM52ev7ByRlEu5aq3q5ytvjty5q+0F+nRLXUOd1VUbwibAGLNGYCCIH/Eu8RpN6j18QzptElo5BIEPJHptXdOprTQh+0IoNkLmE3unRyX9oSZ6gfjq740ASaNKsDPX2yUEgHYkCdSjYVkZL0Y3oPEUY2XUF6PaJHhpTIxBEEGHYhfF/D3Gb0MP+Qq6Rhyi4QggXyQiYzFCENvoJVdnL7BHoC3fsgDDpH4DHyicl3AH86tCfD9f+5wYjhwdIzRYg9NmQ+2bQ4FpsGT/Odf5t5S722nXlkktoERMQZ5cxfqgTTEACxBpFr7lRtIyDk71zruqGDFodESeWEch7FEY1WHsoYp3LFlmOPo5uKEFwps9+nn/p0NW+HfWcBXQf8wBIyt/8fOPXTNncfkx4hL/NVX86+fbV37/PNrm4/+/IebtK2asv8RfY3qzZ4/n2S7lg6c96/PxyoUbSxddIXXgx2VaA27rscA7o3TeGojQPA9Yq99Qj6vTGMToMLQJDhexnRxMvPA5To0OGZfuLf9q7s92AQQ+59Nuhgws9YBAFAUhSsBRP3DpSWAQ7Uh3IJdfCbLpujPxzRwYwkCIF9QzEgqIsru0V1FHBwCOMTuzwWrRsnolVFev03HZflh1o0Abn+wn5sowSIpNJ/jJMBfL17gWnXuAGC4PV1y1PWt+qZ9hO6/ZfeB/U/rLb3mqaCFuC4NMMCEcarJtDMqz/nc1COnGC7Wyw9ZVg3v3b15hQaWqWaa7O5ex/u7n1kI4Kme9cR9Tr08BEDbF+uj8h/xAEPd3m+xrhAGMAxYGe09vru4spEWFCqWVxebD/dGAg7k4Kv6kVapI2XlAjwF2WyH9csi1u5CtvhcAeeSAbj/pqToMCZlDVLpabPzLjk/LScHTYDWJnH7GbZkP8n+TmOiDIOYnf1hzFt7dPm717ylp9kDDI9X64UDAAwAjsMmgNsHPLv9oSAASL2wYGN1GI4JiUfY/dBGARC5WwgIJe/t39Lo/k0jBAiWGvl/ZeIQ+x0AuEQUA4nYLb3DGVo/7QKmFsDk3mnJezeZDsSutEvnNwlAG4EBABI3btnfCq36unyzM9+BYz4/ODh4aB8H8xuSAiwDgUfxWiADMw7MP0uFAAVtj1TIveZD6GADuI71Es/fRYBOIhAH0sZtUeNG4NEN/v1bU9hYRzt+3XBnepaBMMJgFIAde2YBH6ePR8snKL765nJh4wWvmVUWxcbi/h5nCDyU9XgtClIi9cg7f57XqOsfj/0nbpgBXQ67JAerF2B3u8t+gaeQ6P1ZXQfHwen6nXmCEsNF91c6UyLXsQkAmeRiz4c6MlXyfK3He/rjgpsAS+N/KZLdOz3GeooHAGoCTFplgHsnJdYAyWekiPO6adOAAZRCNuJGlWCZPw9eSxmAVmjJvBOhcRjYkRhpwQYC/JTgWxAgwSTCBgH4dvhUNuJxGYAPAZ6elCUxnOtclMTOsQmAG4GxzC3xjE779ytr9viwBz9Np9cyoAkG2XrKvs3aYuvJ9drhBD34a1o/yRqSsIQBqVcS4LzHiMAjbIfK0jBH0MuygI9ggLvNccuLS4xWnA0A4vj0kj/BIYrJqRColnmYlnmw8bOdlCQDkl3e7QIAZM4PLqu0qZgHiUNRLO7X1ASosAF4VaXBqWYPefoymM2c3j3uCLdzCY+Xs4pyqAG+k/ifErMxMxUTW4k3DgHV4ARLLG3iLTRZ9nBFhkHcbvDvForuXbSNNYFRIzx4qSMPAKczZAPq1gCCvfKHw6IkAMAPbwHgjdQAJ0EMAKNA9nNJ0cKhMy8FythxZVAJ11A5gGJ+6HLmwSIKqskABXpJ2KliLgHI8kL+4hAAIAOI4KIbrtqmNuKZsfHjF3UCX30GABAOA/dXL/793JoA/73Dja6+cqepDmoyezL/KT1d3x6ib3UJTnQ8+FVvP/e2714Jb54eOC1IkRcNpatYzDnQhGuoPgZ60a5W98kQQLvUv+HInUXIBMoZ1p+e8Usd2X6aYBEgTjsI0AKVIvwHiQBBPWOcbtfBaIWfnng8jsdSJhTrx9JBUWw/lBJbdbAfhUin9ncr8v1+bOPWjZ+O046rDmok6Jn6q5ACwM4vSP7TjHVKShEpCmsb/L4zYidzdXfUsv+6OriiKABJNjtwV9ff9JQDAGoCTGZLo3+pkT997wEgSiwAWNTwli9hwAQYBJfUZsgc0RebyFBAHvsuDqd4oEKey3WyCxwjABvfRyTfo+JOAGAIJOLGkvIJgDV9kxjoAthHLLOAGydvJn4GECHAniTMMLBPHXAEcOnL82sC/AvIAKgEILdare2K+YfHjkV2HfTi8L9kMH42dcGCgwt4nu9nLUHoUD1UOuUUc4rKW5oFizZ1RQC2NbO0/tdNAhpxXyMECI2j7Oie4J+HMhe1eLg2ELQsMjWAJkA3/u/gSUGWTxl7yhdCPxNraUxXzK+mIJwR2j/ODUHoEK89q8mM5othGOfo3uJm1aq+1dXObwQARCePC/m+OAV1gP6Axp7hnqek/UrqHURUmwrC46ZC3YJRDABK0u1bTP0ZyRawJ2Me91X3uwAwvTuIHQCoQ6DynHk+kFnb+rFGdhwCQD748MK5/YlLBSaHPVcB4MJRwYV7a/axMWzKEJPTAWG84dUE7ElKIh+n2IVVvMTCAPlwMX4TkHrJ9RV/wHVK+0ccFiAC4FIqbcTjKgAuCbh9iBuYkMKlLwBwfnRAtBEY9jDmUjFLe4vry47na5FucEtGuFcs0S+nzvaDY/rdQgcjgQ4AUuBsTTISFjHJcJBH3vs3NKJ9pAAPnaXLfHRYmGrYZQgAJEbjSnJZW1BHatzAkp3uAx+O/WzjaIiNS/LiTOqsc2anZ4wyHB+ECvXihFSvR6e5P04pwn9eNfZX8nG3GNOcIBp/xub/P96u57Vx/YgjfWXFfpW8Zq3AvsWnLSlEOhsENiGXHiO2woQ1LrwF93kLhcdicjAiz7s2gVxMIBDwySR6tHXYi089NUvL66UHKSSwNPFf8G72wS342O98f+kr23uNbMfZrCzL8ndmPjPzmRk2Ns9UOl2QnEH4yPMb9DlXT4KJvGjLvdzhC1rRVKNQxp+iqOR0lYgC//ZUnVf660T+yRBoFqw1EXwb+JTJJTByD1mN5rHQGgSAyUMU0nCCGP3lRpS+9dLnhx9v9iEJwBQAsiilbz0C2JSf4j0s/okCsKIJqxWSPYAqVhMmnTMkJS4QAeAYakynVmlOt9IeIaJdQX7OQAwLODwGBDEBFfx3/QpMOIEO3DNmDf0MQkfQyHxFlRsXm2lZEH8s/1rO2oOBJc9KJV3hCMCxI9EKgGEAiAgQCjOhwyGuAJ4wCfATdDAnKS5B0DRzrUSS9+FObzfci0x3l1W1nctNgKEyCJFs/skPU1WKo87x0Y8fhoew/XAyrn0aFXO6UVwJAwKfk0ytEuOrdc2yFJHO567YQ27KhltxNqsIZsoFJLDPlA/BxL9paC0AqCvlcPf0Y3/4Bizrm8GH3kk9ZPNOuCLCOEW3mFcCqV9odAJHphu+GkJCkFoIa0e9IV73w7fvxyGWRGenu6nAYvCSTPimck/H5jLhp8tOf3Xm+ZXOlzQ3wdCOOaqWKJpnBwSMommhUzv94e3v37179/Z0+y9l0k+H+7bAg8OWFF8N1WSTtWmbsSLC2q91+v794BC7E6477P3xpBUWNYtnyPhKZmM7i1ZjAye8xghlyqgr1ZGzQvKLb3Pc0ChqEs77qgNAgmTTJAZo5UrxhJUAVxMIUG0vbDpFxKSI3GABOQNh0Z8tllHMB4jcxXG0mO+pIsFDgoZOEi1FeuYBVhNbLFmYh26J8CJelnN8OLItl4tnAgLYxEsF6KhZz2bwhrDdxtFyVlJt6ubHQVr+4d5eEAITuWKiFvDfTzXPBOZdMvKyIGga2WOPyj650Sf8XMsqJPuppDGAruZqfqIukm0/ROmpYkVDL3dOsIDlU3Mv8of9caeoK8VUGgAVx+NjMo6KDKgYk4aV4zIyxBcHa1Id1Vr1T/VPHfyow71e3w5RKp2nKEZ9XGvs7m63YKvDj+3WbohS1h/phfrR4DCZ0JMnbByvf9LZQSxYQUb2YtvKlooewmHpUeGY29v4uDs2ZTGoo93LITBzWJek7g4A5qFMnGR397LAOwUVedcQCrPZ+5h6+dprPJKLnygApN+466SsG3iVjUbHfVfwjPG7D047xoNhcB8AOwHAl85piNftEuSPyp2j/mFe6gVPJxMddYo5VWgAlqeFdt2mOl5XAH6dFvtgH2UoFZQz/+ByZyriZPrsniKA6uYMAP0ZtKOMiKxhozAHNm2wCgHOZ5R9xUwxtf6GrVilRXR7H6zNELldzgDZMOtOLzdbM+p8iSV7ybYIC/sy+t8V86z0Z4v4ThwuuJ+hZEQx9mkUZZotzaI78Y7QuqR6u3xmQ3vDq7jaXIEAzeb57KDAqBcqbTjx5cuLfz7VHL0//ON7XhAhVpehnnkp079P7/UMSpNt2YBZPRsmmoK/higAOzX/GqnhcdcjdDfvjQhbgaXBf+o1RqoixQANVBzwNLiohc27JAwhYfvMeCuxgbQXydZZCv7jcy703ZXiRrxjR5Mieao+qvUBUJMT441O4OywDPePRwqNU6SJP7maKzOhCSeqEpIFqBe3u9h1F8v+MN8r4nfpwF4Sa5I8sAIoUH8/NXTdpiaFfJDHcIzxicpopSw6bVy7a0xs/xgfaTo6GhJOoScAOP4UvU+qZfC0lgKjQnMErgj2jz7a7nlU/bmchugyPfhht5xlEUg7SS/i25m7cgqet/+zRjSN8VD31ovGzhy+zlQluwi+BgAkBIDlZy5qAfFymwUT0TdMaAC8D6dfQjLOtkG2HX1vvrwNWANR1mkQH5e0G5vcxzPNNsG9RwRtOVwBZJcrygLvfAd56oKDSsu7gJKX4Qzbzdvn3P7DDBPkKJn5Mr4nvASmxEDMg+rdwsIa5td3KwoA/1/79jlVANDGncp/5pvSk80FJWMBaUGUwolPapFAeiL2ZKPPF+ED2iD/WAHkyhd8bwkyMAXAGACwwMbDrSRp5Am/kNqI/PBkpEk+tIE+uqtVSG+8DhBhEiuoXlFQLVMR3LOUjlCQ1lknKni9JLKLjxiOB0Cj88Ry5sRnEKKt/NvdsmomZDiOPk48kfNkkU+/+wqWodLpQ07ekyojxnhJavWENZGcktcvOyI8QfJwjoxNKPI1LCb/PDel6IWuu8bAqLQOCoXGcCtVx0mvc979bpQ1OLVNyWYyzAtizX3LjS7JNboispjnnZ5BB/ypZWoiTSzCLOVL6XqxT3rxrUaV1GNjQ8H4jULLAGABWctgshn+p1pmBedLmyXY8Yumi0mQln5aM1DiLoBtgzTayLCns+ietw9eOSSdJRTPdBKlJalNg7cTsgjTkD/IiycxtgCFg6tFzJh8vKFf5BgimoxhPlYQt8Tmw/+1EzFvV6vRXFVn9+SvbVkDtOOrgwJr42xxBfDbPz9lEoCSXC2xuLSXr30m0FwFwK9/HeUS+J/uMW9eJggggQBUAThU/pViY5gnNikFWT1RY+B7+WHDQIK+bqIbd2UV4xfXp6Zk2q8yHUZHlDiI7nUhXc6DsbLMVKAkhdZUYFrl5cmQWusU91kUNgIW6IWasso4MM9AAfBtCA/v8hUW4PLYS8kmaIG6Yii5XXcjZSpESXGErAIT/p66XvmUGw3X9drgZ+flx/x6mJH8e6sbUg0AnnHmVzyWCVFA06iDykq3evTk5s/5/MfRA2J8NgwDoFevoY8GkvVnlSD9HVYOk93go/iNKaIKDOr6ow1JQMGQ5x5ANWhGJaEAlOlyEiQNA3g/sGZsQUNAOC9QAfCrVlrec9vf3NRwqIqhRFRiQVOHxQDxqZXiFNWY7B0DRnoeMdFOtshhiRGsPhzHWhDxb27agnj+YhkwvSBpgTbpY0K/bq4AXvztCbuBfMM6I+n0a8FXIBtWKrLos+26qKMVAEAVgKUr1+u7VyqvsQJwmAeghj1YYEzoV+0WFxT3uzIdawXfyfTzhi4DramMAIzMqesn9pcex7ssI0n+Fb088Fbkf+hf7KiU5G0qhRoWf7GDv5nY7Po1Q5WqQmAtYvMnEh8s+OFf/3JghNjjWDknfz/EOjO7WQF4ZwqflVfk+UmZl8iveFoBPHY2XMXBb8LuVgqTM3eDXr/hKMszeqqapDcLyujUy3+t0Js6QxhCDDoPCiLizzJsRi7cZ0pclIH53rWp0+I59dpdqRf1/EqdWxEMAAindwPub67SgW5njlAAWjRJ2gaK1gFQMgBMHOD/2QgDBuXLjPUa4en2ZnNFD4BsT+I5YDuH8Hho1hBBkCFdmVgNIrNgQCUfEV5hwdvt/9osHgr9DUsRFf823qV9j3/Ao8me29V4DkkA9id+nDZEL1kxMLJ4DPDvT0YE/ok0s8lQBcAQwEPLX5fn1/s3ehIA5PLPEMBmBXDx0ma0toKx7eeFha0k4pgkDulf3W6oFrkCqPFqI6kOsTGVwb0+2vd9TkBgFARsgl6lFEC25XFhTKhNn7OkVNgw9bCfz8uWPNkpdWaee3KlprhiWjgQ0s8DJt7NL05n6Prp4/kVrJTwpXrc9SoCiyR8Cd87MafCB0jqd6Qw5oYNH8xnHoi4AP7l7wZbnreZmg3gqFugtelyNg+js86AOiy+rDe81IUnflsrwytbSFrOyLZE5QdXNL53kyMAUc8WuiuaCN8uQkkBzGmH3LTT31yvlw/aSzYcAK88kgQIRO9Q5gXgPYA5CZETg6D/vYi0G6Z8O55xk4/KUMDkfEaJnQYZQ4xURZ9VgzXIEDlXi2YgcD0T3ub5goREiB8wfX6L3xFEmiiAdlO+kf2jOEhLPxwDiMA0BECGOZOmUt//66l4gJAEYApADI9H2c++JPfkBvfGfyT7nx4zaf6ft6t5bRvNw+gjWimWaZgo0AkZWLpkIfLZYHhNrH8gQityCT16ydVgejAmFKZbWFgaTw1e2p2ZkAh23VyWMtA9hLUP7h4KQ2w6kHHsfyI5eA459LDv94ckt7e8jhU5VvRhv8/z+/6pjzZlA2+ObIZHRZzfBp/PK1TGfn5ABniRmKSmwnU2YuEqZxr5cM7yWZB3f7ofZoEb9zY1JSOzU8kcKEhmGioYLWqPETPFDMHLTwwe/4mrK8TSiuVYCTZ+4mHpAOE//f/hwNA9a3YYEh0knTdZ+bZVhCYGTkNKVbHl4x9CzH4e8pxL9iscnP9uSWUGVbGeOGn8F4vaUVhZRhmSLYR0gcOpJpVaut6R6s136ttSAAAgAElEQVTAX/HOlEyMKVYP5HgHXO0/MnkiiYeCAIrdX5f65Urlcu3qeEtjBt1XpKVGqmwYIhHfSbiI3X/+/JaUGVJLnWXfyKYFVwKaC4tlD2Eng3XXTm0Ft7uzCP4xdAmE0fP4D75bJDkE+GraGP4U/TIHkF+/0NWmYIXmD7ck44NFAa+urnYf/nSPlQCEAK5sfvt4zRoRAogI+ikF1FpT2QKQ8e+c9AKK+yigFAAX5+XSHrqTvb/9bZ6M5VkG3N7AUHmRoBtHodbOByA9uWJMAEwRYd5KLoRZAtLXmhCdhpOA7KHPDVO3dMMvDlBymuLwWEID6OBvRBwOEcBOKHlKyVq88SeGf+YSxevxkYkIoCXgL6sYkPfC040Tw7EMuRhXOlbaBIBfknEeAkWxQeNZKFdlKARBCzpbtpsiAPdJJRQGEFjGHQjIlVjNRtI7YYYyQKtAJkbhIBbmAfsOz9dMPs9WFrQXCPf71UUAUOmZBW0AmsV0Nr/BgjvdQXRC8oVR5ARudn2DEwykW2/wzLu6GmBo4zwDjYcANWjRSl27+JZ3N3Wm/svgnpyxPHUP3bC42pRGXcU/ZQ31LfiHyVaJ3TPUYm0b7zUIYJPYIyUARMzrfUCEP4M0fjTgdy/ZAHIm0CyJ8sYAJQKW9vzNp5UYyDYCyFnjf4ifbRvYFJu972WmYWU4FyxkXLXUYCUPP+qiKNNw3oQglaUQgI2ZbkKLpthBaJVOg0tzIdYpMWGkbkhuUB3umMdI+Xh/ivHP4iEBo5aDme54s4TZKilLA8ruSuXV+X5r28UkUFSimIJzJQeMXX6aQ6mysZOXngktdE1oANgFut6phLGSx72UBJCJVnYECyICzoxeMsU5ctbqfqZO9FU84ARG6/qrKRVAKpUXzXPbzU/QdNGJD1DOHOAZxCgI4FMQ+w7tva2gvy60ACXK0K5D9tCpUoOqDb3xW4kuCFs0F2Oq/wsBjsalRpwhPk5pQPjvNlOjTp/yH+qCBZofPF7D6NHbDqx+c59BAJvoHR6DtG5DeY7FvpDoaPnyxJTqnKU8IAuao0EeAQx9pAAYm70KUMSkiBam3QxY4YgHOj6QmfQyjsJwgAlAJ3DwBnGgoJegNXg/F0TllXuhjEV87N4jW0dOT2gcBDkDKHQAuFYAjQuhwFpWJ8z8Y39QYfAXe0IHTGaW48BPNidlWpg/lfDpX3f+deJ6Oo3/MVuHu1y460WHCnYMJPUnV3PJO06CbrJLildwQXxHtlg4Bcg/MimEA8/kBGCeZCk67pdnFummSIMvkhYHwGObfXy6vjvmFoAEzOaEvRaae7X+8xb5KIz55dt21gSofrB84pqE+LdR2508R7yiWNQlJ+P41hAdx7Y+vpU3xj/dcVuBP0P2J420qpvfIgchRH9XpoB6kzsEZDpg75C3L3WSB1wktYCov/A9VgL885tV2hzVogUQeGpx+BPw45eDosU0AF2907Suj6Ia3LCmPmoX/t7eXnHzaZiLsgz4OeWAg5mvz03nUZ/6uGLm4wIojMz4R1s56YFc7L43DRo407XpgSSQGZ4HqPGnpnXQmUXczEntJ+es44HFmc+B4i/DXr0gzr28fhkl3prGeRqUKdQiX9uLzk5ShiYKLbzMwz+Ez+pBrKJfcM7nvCzwEmxDlEYZVqeS6wCNJbeqzFlx0CpwH6yTBEJdYAkRHc0mdx/VTzPeiFdQEzJYpc1c8bYzsLUnl/WqrLoT6B4vSHW+b41z+4Z8Qk0DUA6k4Ws3S/Cf0gKEk6HevNNdnmh0+0s78w/C+Ffw3F0YLm6f+mDM8I8fXYUF8gflhu6dVqIJZjQIUFh5eH9BgH9vTWkFsiCAwiGIBPwZCdSGFp2NhjQhiQtgs1ZD8FfQX6s1EkgAJRQrk8T7cvALyoFwmSMCWBtl5iFqeMMAoV09XiK/Lxx2hpDRO1n+iVpT3TKs56HksPjM+Um7jhJHw80iod3D6EeYSZF0ScrOwEhzEAFMj0TdZCrTmiEPQioMwbMnh0nJNEmyqp5LAEcxEHmX3IdBszazvhahjJyYLq+X995UlnlmY3XBAw0dd85UAOcQADW9IkbxFdLufQpVr0y8t5cwAvD0OdSaq3KDLPJrsmjmwLf7ycFVOv7Wx3Y6SEDCBDj6h4qGBP6b3Gpfin7qcpjcakwBMG9yAvnVujD9pTG58c/ODM3dvYSH7NJBWeDLo044xC+5RAFAyVlEA7i3IMCff1pl5QcC0YUhyNHnaxfXWq4CYOqzIQI8Bj1e0PFd2V/bcwcy/iWNgmJEdh3yAfYLc9Ocu4OMEhuPitz74JydKyjj6+DC5m1br5McP8No3bE0eyNMGS7SaaWCIJwewNDUaE/wqySQfaQ8ACK5TcT6cIbqkMxZK8iI7RzlHZFAHJzvJ2uIAyhiROQVPZ0pNH9AvqoClKRMxfhBl3QwYxmN6yuH3DkbgC/oDuzcUDkf7XRrDRnwJT1ho0A+n18TIHeKwRwRnKJkMnwRkAAWKflPBP/4diITAIuW/f3WcBEBIHhXFQcBqRfC2EcGwIOPbSaxVTcctwI4EYhF885h7Qac3/L0B+7Kk0a3OdlCRYVn5gKJfyr5GQt00xyQywzd4xtEAOTO4aQXyO493hPgb/+jLoCCzZ16njXKEACcx4331+kkIFoKdJ30sMyPFPw3GkOtuKbvxAz/HGNZhGRGbxsCxpwPs2JptDbXSMNma9oKAiXywIXwO5u1ZNdWeEiTYzsK3s103UlAHs8xNAfKWYp3a5sOkhKmZa1CRUn2kagfV6AQXXRRwIWIdpHZAClPQ6AKa7yIMQcgr6CRkv7wee2expLgD3I4gJVwqB6QKBiYrIuFlgCK/ywVBbkxG1wUqs+pLlgcxVL+BWECaCKg+zigzydOdYqBb46KJkkSQki7k7x5XBuvX3qXXIA3Rb7M8cKEBovvpyrqqedw8oA0DfV9b/yWimuJAYTbTcQDRGcetJMx9jGgE7Mv36byePnJZBB96RR1/cy86VabXTEEF6joJ69VBuj+cOuXaJ8Bmgb069WDewsCfP9fRgCeIIByn0znmjLxX//RVjru8xig546iRqMBIY8fBP0Q/68vHDjDIhDlOghzcY85BC2Dd4W5bdr76Xgh6klgMgJYGcT5ewbvbBNj1NKdch9IIU2y7D9y4C7OQ3rEmnKlEeaQZWcYgYuZjkqU4QTPVZSyl4dWasnURHWl5vQwIEBS6yxSPkrOCnH8onNQdhzRnwIbafBZyPF/fNnNgj+BkavRjP71ZxWgJH1SLgpEZUcOvUA1XtPmaCJs9+OM3dBLpvhOLvDzCUGsxDwgAQwdXaPTzLSZO081+BfF2241DThIAB9WcID/rk0ze0RFPVIbPOKVKM1/a7N0PR59lyQ3wXVVjg2Qle7CpBqAR7N16koaj2LNd5k4v5u7umZBlUXGv2oIdCXZj3lBIgakNvy8xVsRUALYXb23dkC//8d/HtKjWpwApgmE82v44AND+rttU6kB5jfHcYbRaz4aYvXHr03XGoCIU4LgBzqo24DoC8qovSzatjM7zMw/0IcEQG654mz3ghrjjYjvEf4JTjPaQECfHvAEJYHyoW3q00NoANRq6fPpoQ0b/Zf9RoYWyHGCkQHJBe3fGwDp8EL9wSSWGi/LyASwHc9eHwWqc1V6meeNhBzw7OjEcWSlCy1WkyBYSj25wOfjtEz6hq5bgwoIApWtKFvC6+gpxpDQaoJgY0prRpIo9QUB5O6cYfw7XidM+zqCYGem0fRxXNdfzRrG3ZvS7riZBdTxX1BJYOn/vF3Bi9vKGUeyJCTL4YWswnP8fChbHMju8WFayGL50lN5oDxyCT0uyWEvgn2Ht+w7BkrgYdYiPri1F2IoIkshUHBbDDbU6mFLWJsUNlr5n7APvviQQ+f7ZkYaWcpLTzsje+2VZ3bknd9vft/3jWYWV6eHOcY0bCMOe0Xs/RpdBMc5BrvXms9b3vE29um7A7jlGGOAWvXD6WE2kL8t/qnWX0sFrdC4Avy3SM6QABcCojig7zgxeJcav+2bBgFMs1H8+59ubSLw70w6+zBxAcgfg26/3+73+1180Nzvvitpcgb+5FfWU6fb7mYSKVCQjJM0vIFWCEkwlmh3/dQJgTxcOzB1PTpxtrsw6V8K9TxI4eixnU1AMc4kXkLEGkPBTvojD0PtZoewR15yL4ZBpV6vDe5PbYrkhKUQ3n7NQH8eUfOO/aXkUE6yJwpbXUKJgvhkB7LDaSdxojpp7ml+/33naf2G2jR0txrysvysSWugT7xGfEfrc4TASorFYDIe3gQxIEYGfDtOp8NqolfUHQ+DwWBwMnmbq4PQBpAXsmQ8E851WJ5KhkHQTb5hXxR/HfyEfcIIQCEf+Wp+msW5N6/uKxtEPM1wYOqtpf3CvjIjhdgpodQGNhGW5b29zelBVq4ToM2v1svVarnczLyD3ODArIEEoMmrDwdJjC4r/JnAxxa2VgVSZH18iM304gZ7vNHUDxBzGL8UMX0qMAK4I1Ex/lEt//XPtxcE4OuQM+uSIDocAvIzaajG252BTtIUCv83E5sgmRAGJ4o+K90d3Ujy2BEgLuiD9tm7UfBNMJpM8ZyIfZrsISGAMOhsd7+mX1O46TFtbiGfawxnLAPWFNILz+0sSseEGcqPHicFXVoY0uQbOTJxoxzj7gu/Y9tZ70YQAZK16Nz+f5PrjkKDr0WkTxxBcSSoy2koJwIiyt+ewBeecK9RxGp8PNwsB9pJELezZWLZfgWnU9+R3/62ichMCRi7PRzcAb4iX1/tD34OA8D/AMOw+tMmgp4eLFN3p2WF5w4QCzw6/KftE+sBehlsxbZY/jdHOXtX1r6yzIXKpbq//50+P/QEXvDYAbuIS5q0gBvuM0M1gf9m1TCIgt1bKNX1XDAhkrvy5stFAXyTpFmHnw/h8VGcAnpeLcBsBk5JLS+VyTG/vLyczec9ZIv0NfXwIC3f2+fbFLF9hdXyP24tCvivIt0i0dRjl552/S6XAEaqJUgAtLEVQx1MEf+Q20gCXf50VLfUQSLtUyP82fBBIYJk1J9N3W5Oci/kSI8eZvufX9NlBUMPFdHjmOAfDIixRAdcufhIxC77VFA0zDe+w1wVeLCf7UCJLCDBqlJV9KgyzUGmMzIRyObAzrFqsoIEcjcwOf6Vm9qZUAbHXQRg5/MyAmH8qKDH+FesG3Xs8Np9TgSMBe32ZDgi3NqhwzsfnJP4LCzKJZW0ARn/AZmihiD0WCHfG66gS3CqDN5yDUGHcGpJPYEbKTTJGDc7ce1wAJu9CGF/VkszT5odm/0O64dX/q6Bw6xCPrFYJ5GzFAEUtMY8O1r2Wu9h3e8qEoCIfRh6e0t0DUvG5nQL/jhkX61UdJ0oaMWuZgcHIvypwe8Bh0DT1oefjdt5iZsf23epEwWwRAFAW8QHf3z0rtb3YEqbtdzMRQHQEx6t3rLAZ37L3AdY/s+t3Qnwb+oCUE2L6X9NNkoXefg/q5fNVArDUD6f+G63zcEvSADyNDQta2x3UwKfYr0/qRgRm3agR/VxLgO0a6Ee7foZA9etEAKA/2Rx2HTtnAzgmpYi2B6YcP7U2R7o3emdov78hRODP6YAd7pLmgXDLNAbSeb5dAv+8MFJiIvpmM9Q3eSRgMv/nMsIsF0JGfwVwhxPumIBFAFfMCMAdM1JiU6wAeK1wtIU/4Cf9rzC03RUkyCEsnMybTLx7aTmZ9gVmNAM/hlR97N0v6DQO2LoHE994IsqnmoSmGcBArA05cxC4Y+vA04A95sM99zaIXm6o8gYRDFUK9qgBdBKC/rW2pA1fRPrfsjsABtgf0UAmNEG3nyFBLD46sPBltsdILtp8LFLggngUnV2msI/vbF3Y8AmQZqxOcyb0Ht8LAb5GJg3RklGD0CLq36P84DXulzqBqwuCnMeVpeeMPKLj5ermAA0la7Vbjb+dnt3AtAggHqtxGO7unuWRwAXQTAAw3AwqGAm6dEU4d8H+IPTAIVDbAJUPpoDFPfoTkwEANESWsS6Abjpop0Lqhm6/AdNT0w9+q4tWMO087kPI3mxIBQgtxPs2m7Ki0j6WYTbXYaDNPyxwKh8XbT8BJ2xRLm4q0usWRY+tOvAzYzm9gVdLtIcxuUTEkhgL1bevdiJGP6BAcKgTT2rnS9hP00EY8mgxEQIoLjrU/jDIf59f1g36I3dslHLTNCkqaLjPVLNznYTfHu0KJUwziNVwcoiMv9+bOHzWpzmcAFrrBo1nygIHN9pLAUq8ysRhDssJZw0E/jzNGUeAMNQjeiKSWeO/xY+loQAFssE/Qh+gH+v9cna31se51kHs8YClumNUAAk7ncq1zeNeDdf7HeShKvzH6ckAJEJZDiH+MXVIQ/lpQJ5XPrzd6R5vaVe0FYeFwDC6A/k0FBki+4qLBeU1SX9fXJBLL+vxmtMsHmAZvHeLe4JwEwANf6K5PBJ/8sJhT7p2ZlfJy4D81qdZD2DYEtc67iiMvfTqQ/PBF8jP/qjUNf3p0LvpZ3ZfQJhOEUyA9t1t0FMwWi707shJYBJWgDA0a6XPz4fNbfLdbtHNZgLwUd/hKohv0vCmpxEju5EQAD6eCtQ4sbuTjByLogKD4JgNJxcnPV/soyYAEhSkQHcfIvBFXgldVW2PdR5y4xyAPDnZ/34EtvBIr6nQzIqbYeZF05iyrj+OTH4Cvq46WasleECp8NI8huw8qswMbb+dmuSt9N5PFnAQszRgIz5DPfMH9lxpncp9xqC+GIagHxgoksxATRmB57nJdIZ4d+arxTCO41Zi436Ynpf3ZPWeQTgXV3jPw7tg5SZTl5uGjTwCMIRhItlScrVqTi3h/r7Zg1JIgTQmB2n6zhOHPkYuJvPZlez2Zw08OXKKllEAOQwUm9DjD70kqFjEW5PbsWXJFxX65MUb3bDCaD8m9u6FehXf7lXFH2AGGo2/ygg+jXNcXr1eivh+a2EBSrl8gN4edQ/Eit4/fpHVTUgjK4saGe2FGuYxzE/E5hJFxl17QZIAItwnMF+ks5qpn5zo4e1duYUMU2KZQtnLqTClv3+19fQRWRFYIBFOBIGdorE7lndNG6MmxJ3Xog8gJUSuTR6sKPAKuU3qq7Vv/7hW1PEP4HOgymW5IRlZ0RMhgLwbRBpbAX08gjw79MnJjlILW28C4J1O01ShmlLgnn56jpBA0gI303Lp+lduSAlk42IXpYlbZKa5A01NYEADCN6tjX5E0b6sUyXZg/rbVqxb3OCIu0bRRKuIWlYurH6cJhIZz6Ett43CEQlfdPKwL/38uVSWmy8LcsA8wZutZKjdY5TYVaVYGDHKaugcy26t1DWvUc+SAhAXs25yM8E9Q692Wa9gnX+pepqc9kjbZVW88M8SbK5VixD0eKo2d7NspdzSb3eRoo3s2Qzcq7L/7y9IEBDTRMAaW34Y1/Et4B9zJDw1S+nn4sfy0NS+tWruAQ+v/79XZV8M4rGUGaRN/rDvBp+Ilb8YpKNMH4LBCCHFW5epOOHzMlYgX3v9OKIgPGIZcZTZw/KxeeBm6Gs/g9kaFBAl8BuBBYE+gxdMYN2d8tQ6B7tmqSDm/WzPpc1osYBa2lUN0DksGkSavF/vF3Pa+PaFa5sycjSe3QgglF+QCA04ZG3iMMjdOcuJl11lYWW723ecyHC5pExTiq8NASlwdh+wjDUosx0l42h4LZkMYtmMyUkQxeOI/8T9sIbL7LoOefeq1/2zHSVcyVZlq1rSfb3ne+ce6178GKUJAB5eDBotVttMHaCYb8LFi5FJ8af8ddaByojAFV/z8kr0WPjzTVLZHGTxjvtJD0RQ/17BYLT4Pp39Ols5vZunM1QL4MN1tS6AZDJ/zHRykKo7ktIAKPBAme9+XkQ0O9Y1VZ/Jm6KHSAc7Y1KBGAYhhpMlkXzzTuNeglPY7hnBaz3ZBh3nWYE/RBRszx8a+Pi/RICmBkc/5ThxtTFhiFPF9r1O52PU2QKeRJXJTEqaL5u3k3YgG14y8Hs7sZkVpQwZRgFKzyv12x+0CQgACEAcrl8ZvzwtAz/jRkb6AL/jMwJQCk9YyOAyRKPetTPRM5VlyKa8BsjAYbrpe+EcrKimW8tz3WguG6Fikvzno4Bdi6us/MrJ0sqqcsQJg6EwmAQxvl6hClAk9oqW34rFYHwIGRVU0aKnr3yYgcL5rjeQNFMre/z44zJmiMdvv0cj//z/Mi0dcxwoPEkByztNR3UhfkO67BDkrRDKXS8HdAgJvALwKrAoamPaooA5EA+eg/nZLfsVmRtmBgttFuiJBlwoNM1U/Vc36cd2nw3Rib9b8cSQzD/wa9ctVIGV6yfI4Xejj4aDgOs/V6RCZ4klzew2VE2cvKf3rTFUfFL4fcl1DeP79upGmzbv9bpd1w0b97QVlaYefZOnvUCyhtGwJEmGsTYau9JRwLYLd4T5Mmitdvixn2UE+QiGheTcU6Vx5NOulmxCX7d2DCKNAoSfiqzDKiP169TfXSAADAHOFveXA81TcY4uIe4R9PuLlS3a9z92GwmxAiVqZrBRGj4VRgQfEwEn+EUMttECkdtZOl4XXnORoASvwdRRADqCwd+zhZNwuuHKPISD8K3R8APbUfTSkceQb+Cs1hxq7sJHDDL1BO1UD3ecUZRg2s/TQz+aYADEazY7AjTwQiCENaPsMnCvGEMxFiIkZC3DgJgy/eEKglPsSYVi0UjNDZwlqHviCAoXPjeKo6pWbpmO1qcBsWF8AdZVYQ29P+ffMzEKEfYRyHYvaleWZZlY/mU+Tghq7QpSerbKAEAe9rBkvf69jo62FhHLUnq+6waKvyhDyG6vv5moYLWu2GOOcsNJAGUAfiXq5u2wLeoBAhABZhnr3y2IzsHi6YbIACkAPPaxw14htzg+6ptcwIAMAZzlkiLGzydj3D0r1153ktAn9ts8nGJG+11p2NZHQeUvos3w2OjAsAfPjD6aoEQisbGx/DPO2HHHlIA1ADRW4b/JwVvOkg3aeB3mpGAIKfwKTEiEtnKRwnPMfwe8Hwxscm1jBA0MN1OJTFOUo4JgAf94dnuB/aXfwEB4D1BRSMAmLImnCWb/w+L4E2PsHZu6mbpDJ44NDGj114F8SCbxbM59XKxUu9YQgIgUFkuFnY43in414z23YJr5xKF4fClqYEdew6Y61ToSOgYq4ammdeeGwYzfM07xQbREQ2SPKI2TlgAh6wuKBPP2dEhtDcHHj+i+FWCyEVCiOaNJPJTBECP6ii7PuhbSUMyYIzAMMW3eliQCM71MXYpNtfZq4gw9ggAswdy1FeL/gsh5apEIV4Ics+2/MEQGGTQWiCQPkiVR+WRj6+mII4fFUU7aoldaYE19MdBMNIPbHG0CG5ednSVJIA28NixcwpwLMfxql/nMsQtILZGdwSdNMgnAWInO570Gl2+qRuWxtOkuUAKpAzgqlAEEOs8SBn5+2mxSIQUa8CGM8O3ptRCkxPAXWeBX5AR5oGU3Y2GV6VOc4Y0nr1epuunmCPhiQcW6GLOo9nshYKGE0HjQ1ESN1iSRSPAr5/vnwC/N/ldSHNhDnD0EiFdKdMUWoEKTslNZPhQqfA1fKGex0RbfH9hP3yb9v6YEFROl9BKFRXADUMZ9+KIZe8S9Os4d+JWYsTjHpeT7PHKBNvG9yP0HcZCsHBfmg+m0fdSZANz/bJ+dgYTt0ta1usnKWlD8gYTDHrVdZdw5MkLlZ1U3vgcAfCxDAN5a29wUrOcWs2pOdZnDNBEBFSVMAMgmzc2x5aAP75lNR95fwo+Mpm+T5gl/vBozfKvNVWRrlK6A17pD5bZ9XvfDutgC7+KBGDucLfvIUMR+tHHK0QAOlxkK+b/HctzPPfM4JrYMACunWaj271gBaf9/dvu7YTaCSTJvO3iizRfcOt2P8x74t1iG2xtfFDG2LOwk8rHAxnc8UH8QsORvubz2X/T2YJm8x5DAGx/EFmHRK5O4J8PakLDq8kZ/W6RABq9p5FEJM8aukVKadpbwl1P+SwfKCXLbwc0NH/7bLcD+tvGA4sAYq2Aw1MA1eZmYbPwWduMrWwmNhQq37zQhlppDcGZJoE9EADjnAAAddeF6/R4ukRTHOeAANZRxHPvzaSEe5Y3csFvvJi0QMlxkkT0d0gA57AnGMM/vdutZvUHc8tbgt0wG5AMcBJJBMY5DoYA2ldLJZJzNFrm+ZfQAD99JciuvTqr/sEJzeKFLWgGIrNcB4QQXI21QEYFMPCFew1BZtdj+T/WwppbqXmhgGCPgNMbTdHXbCsReiCOvU81+pKXZxVZWJF/jALAvPEF/3ghSfW/Ukg9aC9C/1+D4pAEcM8VQQC58fRjp3exD7AH4KMdHv5ye9i9ncrUUJgdziOQX1yw9xzu/3Kb2Mo5oPEUZFR1HG8h7Akd3/kxPeIwWrwTMo8YevdmhhoB0jBFV/2k7u6G48ww+I8xnal97MSRz9oqsFsiZYFy5AnAFRio2iZpAgBN053LYsBHcTeQYekfz9UI8NPf/8oEQEwBjOV6hQigkKAAJARiBbayyRZ8pbDJCEPssKapI710zmUDFw+0/GZbdGXBAcJDAlDPhD8PkwZAAMZQDbYQdk4lBmK3Du4jc+wmiWX1hKUYhZ2apZJ8UnHgQx0oZWAiOopXuqKb594XwplIWfBNCStjE4O5GstshFkO91LOp+P+pRQQMiDKgEB+sbN3eXwi4O7E2YATAeCfRJC3N8LmxSH61xoVi2YAmHce6yvMPFB+C1BJ4PeEk4aHdU3RUEFc2TwDIQpL/Qg/zwqSQ1qL+GdBAOERIyE73AzH6dV5AKHt4AHWaMKCpwH0+CiyYhkMiRsM/mwCBjjc734ossSZlJ906dWQIAD++/hGxgdJApjlM4YcLHrjZjPWlB/rHkx9hJLJvl7vzkRemnR6cewzqX67AfjnOI1ui5nLkKzvLglIMvejlMsAACAASURBVPxHTv+aYVowwKAGMR8ark8koQDEPwGGzzcoyE//KfHbAamiwTIjf/09YFVgejP07hH+GdbFatwKxBuVI+xcpGv1SsQfIlY4Y2N08xR7iAal7i5GC8cQaAcHjptw9ZWCW88qox3YVC5EgckPb0/ieQjXvQQCWAf4l8tlQj/hv1D5fkUp6nri08QeEYgrX7DvD4AASjcu1kg1l8PoqLAafFkACAaIKQKA0yizvX5OUiBNApG5MF0G+Uc1yIJnrwnDNdzrKIgJgDwx65FnMW1OCGVzbVtTRgObg9cOF9yNExFgpG9/KhSxvFN9pGt61bNiEp8OzznXGQGYe55TixlEOI5TXlPDPsbjWbPZ3d8XDMARfvGkUF9BCJ+Ltxf7+zEKOIwoILZgDDDBVsDifUgAMQ0fKYKl1ozc91yjHgKdXoOhM8o8NOZjQQAR/gHkUjAD/PNAJCyNuSxxBqY4kMeC+qwZRz8GNxcgeLJCAWR4DnD4bIOC/OrP/yxxBaCG/wVWt/B3jGjm6Oe+fTMiBb4SzhEREFUcYacXVX9bJh4plEVFaOejnCwnfvwEBuP4f7xdv2vjTBpGtmRkKQsfRBAn+4FDdhNCvmKVL6Q8NwkHh7nCRdgqCweXwqApjEmMcGkuyGe2CEbFkWY5rr0t74orDq4JhN2tHP/4JzZFGhcp7v0xMxo5zu1VmZF/xJElxfHzvM/7zKuRkDwheMHnXTwpb6WOAgBQFlMkx982V5zxQGsKXvd3tZYx3AC9AwTQgQOI8ACw4xKKy3Hg+FYLkYvYfZrZRHwUvFU0NDLpEakDa66MQQEMhPqrss2ITrFs/1gA2Kx88GMqq2vQl13gTH+6uvGfQZuQlGS4j+AYeEEBNHMnEx8ie1xX4KozvurbExrmLnGpHRHA5dBMKqgNW6/uRtbnoeQOgi9odNgCehEn5/TknN5hvk0lJcQCB0AAFetcQTwG2uIlPvKYAPwOHGAdDw3v6tRE+1BrlKI9B+zo6E4Iv92/TR9tOeOy5TymeQVA+DdIAZ/SLU3vZ3jV8G9XywxCgw6MioKecuOzl+Z3gVOazQGmiylGer8nCcAyZ8W3rdGjJIB9c+3vs5k8F50HH4kDbG9+1Uv7+W2nIC0o+uP0amoQoPJS84Ft4nVBmQFoFHCGBDBtwNdcgzusPkG/vj1t8KoIX4/JBPc2RCizBaUaoL32l+EjsNpiUSyEYgBfJbvcToQGu1QGr7zVugKohOu61xZCZFoh6VbOVuqhQj903v82EsB2IiEusr1lUJbpTJS9hERB74jY7ey4OFogOSvKccCBu9z8y0d+Q/7zaQX8HK1iYIHpL68HrYTNCyAp1BiKAuAuaRadycR7OzwBfEmAMQnEzaJLFRaUAEgCQBhix0W2k2bZ9w/PT+r8/rp6PJdr1vnxHO/PiRfQnzw/URSQxCfDtx4QwPZJtlFqEfR1JgCn1B7yhuU+4BbFXStgAwAIwP3y8bqvArrE93G//zCzVOEu5ABSHPT5t9SNppRAeluDDZe/f7zqpQtBdqGOoHfd04NwWYIvX597gVMofoHEZH9/P0s/+pCXBNr/l/PRU8WMbddueO19Q5Ck/fuZjnLyywAPMw+3nHM1YN2bYEX6ijQIAPi/82ovNR/Y5t/eqEJg2ygEFmEOtpnwN4FeXXhpd5deE++38IIbeL79mjA4QzoEu4dLLTL3UA8hZBQgLjy3bI+7icQeqXi8fVg9W0vCDMNw975815aGY8w6AAhgDXgMsY/3/JcApwRuzdtJxBJPs2rkN0RXpBpwnyGlG5FmpgvyACOxxBndmQTPEIDLSCf+s/VLS5szLf/+EpUPAj6ijlQg3cz2HugPDyM7x35cGKqDclDKDTLYttVOGPwMbHpIBv7I3zDAey5BX8/hOVZdUgCygHIlh+ue7581hjnsR3CLW9s+kZp/CGvWzzX6iWfEwAkY/qXSXu2rwo6COD7cfs/OZKjdpMavFoG/399Xt/TGKQaF8cPVosbWA4kS9PnSgusc/Hu9hxEogE9fr3tadkgSSCEDKJpzYdpUIEEEoNfuK38C6UgVgAT6y2DPvK8mAcjc5dGiS+AgAwSSACpvXuhMgM3Nv9dGakpwVfxdGHcUARj23nMhX8O/ukswDy9+oblFIQ5VDkRo8AUrgPclZxk4pjtLwCQOfPjU/AtAK0dgAjg8fFitdDIBQA9HFadNCkEPOrz3zrqYAEDDLEAewIYXBDVv7SkBKGsz52ZExALMA5QacJwX74A2K9s07kmSIcsBPhxO8H8e5IFvNDkE8L/xD7fpdKOFuU/E/gX0BFggAg5ITvf88cjpysgO0KwrDoD8BrIpHHVSEsP9iUAdSfgTTuP4wBv5r3PRO1b3QDb1qBXVuatXSdtzFi8zgkMfCOBguBD+obVXeDIVYNnYUACsM+KDkayLKRX20G3v5/F9DARwr+d8LozmPRP2TwSA5oP0cQoE4M+vrtMlrfejJikhfQB5OHvz7TrV4JeHlz4QAfBJ0npGLKzkuL+9ThfJKb0ZWSrMyQyACOD+28fUhD/xxXxPjisUqRAYCeDsDy81H9gfuRAYC7cLnALMgNuaQuQd/rC64PsvgF8Gf8za1108h4y+gN6FMHhDhtau7y5TAOODZQTw1reBNg8SJfNDmQfsrn6Slp7SCruvPFTkglN2ygM+eJ8U+vX+RXfkAjr9y0UCqIZ5TYNPIp0HSOWvUS4aQABnDcGjHtXIGBXtWuUs6+NiGtDrOQIA/DtjnG/HfZYA8B/i+ht1/EsA+rFMAajXk9NXEMCLLVQAMsQSBwBI18ZcxxsoArCdDYzDEtgMU9hUozLy1oYL8j1WFEALcQasyhpASgCWAegi1Itj3zvrJJEBflriLvGXa1eOEj46WD5rmdEYE/qxwnDv/loizWzpzc94QRe+7EuQ5QBZu13CAOnctYKC94gEYNpx2sv7v9rtvevUSmjVLxJM/x4dABr3M8dZy4H7Heji2DiqPtGRUzDgzwSAdcrXyi7Y59FP1BYPe/pCt9oD/OcLDQJs/pkLgRUBIP4L7k/VcCFy/yj8c7gUotuwHTrlEs8nsL2OWIipAJCBR3nvojZ2OksIINwYI4/IcG0MKFY/NYR8RWYAFxXHb5Jlp8uXTr2G4B1H1HH/gFyq7r1IhGndVZ8qgLDNHJAZiJGR6W95Y+fsUpguqbQDL9xyVkuMnysVxUxMAQBfi6Nt33afJYDJZIK04XrvqByLOlBQTDxAKYDne4fxkF03StY5Y2+tSwLQCsD2EecRoZlie0xxfavie++G9aUNBUDcUjJA5w2cCTD8oTXRA6y0E1znFHorkgogvuBBANsbJDq9UA9RawO+IJwBFIoP14vBEwF0Q/MfS5etdpvm4r+602OCSgE8uKWgUFlKAGlPG/rqTjLCIi/cngU1p4RW/eJRkVNn8ZzhWYOEa/IAmzEOio9mjleBlJk/nvXoYjCYlXnAQJoLagDj+15RXWqH5wMEBfCPF/MA/6UIoCzxPyuM13UGsAjy5/GPsbnTsMZlnrQSOKBU9rticYwwDC89kE3uE/y/OhXhk8Kj3V+wpM7feaIAqp8GIj+4uOVNcXfKJkQKOA0GopoP6+GHwEF8jjpC5OuZGP5R/mCzuoaIdqRzftAbvs9ZCAsFYgha951DVZ+kATgUqoCuGACQeSR2G6Xy8xpgQhTgQhYtjBQArUBSBE0LCGBnmLCsp+BPFBC3Dx2aLQjPQZBlRv7lkEN6pE26KP4THL+H8j1a0AAKxRGhH36M6U46DFyqxArgosKVnpGxXWrxrx5PBjBqJnKznyX8z1twhC7PJxmULGsuLYC+aQKkj+QByosH1x7TJQ5ARgHHOkLDp16o3FypKkFVXJimuQE940maEYEqynn0gADcuelMKFaynwoAnJWpBElK7/b4eN+kAKCjcQk/AioACnAiaGwz98uVLnvI+s+cWxStlWDEBOCf/fulCOAvv6FCYCYAxr/l/QpfbBb1+QivtUBo6Ho2+ETYPNgqT205bz2dc1l2mmKRNIAAKnkCYBSMd5bgP+ySZe5vCZGBnUV/4zQrQKZhudF4ioKDkMijdaK6dRpy/FfIhty9Qv8RpytENsBp1DZhPhO2IfwrFaBjf6YA4B3NAABEiiOrlZA252unZCsBgKfE8GkxpAEmlAqUbbeBHLXj288RAMIfCGAyLbUF2h9cyCCFACxNG3Z/NJTavh5rfd0tuLYqAZQEMO0kdcQxwlkm9lH82zJs4HIocWv2GNdrQadGtp72As+1CxDXhw0ggLPtGFc4jUguEGdA25FlAIVWkqeXFuYHxaBEp+MHgVV6fIo0FPMz4+IznANo0GciYD9nB/RvkQBKigC4UNgUAVnZTS/fcwQwd4Ja4Hz52DM1BxkTj7M9y7Lys2FjNXPpDghg/1iNTxwfGwTACsBV3/Hy3t3Xq7xfiP02UARgIQGMIAXwKi81H9jmX+VsIA4NAswIvf7FMgXwbEEworN7uV7yJyV9xTA6GSVAVy7zByVfHCAB5BwwfDq+EDkhzWxwMKVr6R3qcK3H7dr5hEEcVVzXGwiZrrNSiAZP6Gd3dcSn+TW50ikn/42q5mqejbT2kBLgv7xdv2sj2xVmxnOH0YzNmmjAkq0gEMgM2mLlZ1S8LVTE4kFiQthqK20VF4aZwhhkhEqzwnrqEtS8bUxImzLNS/ECKQyCpLKk0T8hFdu4cJHz4947dyRv0vnO6CfSaGY033fP+c655yaDmT/z95o6WyojxqjuGQTgCTWiJmOAQlqLcBvXRaorqDC/4QAQBywKlwm7IHFTJTOhGnoz932/BwSgwS+tdJLYqWCo1gCt676U5xX8AYbjwPeD3p+lzqdW7u8B07heydBDP9nKRSIOqAGFXHy4oy2fX0mygJZc1ed8zK1+X/X/eMOHq/44DFVJaSt82JYAOqPJqmHOP72eTkYvxAE6GwB98O1QAAFQBF+vPEpgYkD8dgP5eQZYeWABtP+tHJOOvo2o4rC9TQCh/wz+QqeTFygnX4UkALADYEFvTzgN0gBPTszUx9HowWrw9K87FqbjPIIFUKq82lCgvwU49i0QgSSA5dJyxIAtgAy3TAC5VLimGgl0OR4etLxgjqXPslmz2QIgAohkkEBuBQlgSwGfFyPdDxvdaTml4lnFl8JteQlvP/AKpZ4av0CRP8Olj9kEAAfdZ2i6TABmbjN+LYLWjejQc2SU8xTQRhj6/qxEWQ6GVURfuCyGrkz+CNHu1xYAyQBpmnrp24FkERfpQCoBWidcSPwLTQCUwRBzPJOJoAf4b3MQ4NyM3PVP51wx1JXDjQuFtHXejw3ss5v+DvAf9O5i411mBsDoVcyLsgKkLZCjgPPz613gkIshEkAXTYCruCs/eblHqocHntu2vNAfCol/sAAqW/o5Qm20NgnACp8nI8MAyDSAjqkJjJ4DIIAQCWAzg2e60SZTlYSHr0baS4D3p2skgPV/bif6B2TfPlott6bDYAugxATQkZ8mE2A0eRI2C10Ef/IAxLKxUmkPZiTzqdGQc8DbRAABeAA/v9ZQoD/+84JZh0cCkAfg7CEY2QUwGKD5qXx4eFg7rJntsNbaSVPRDtlnU2FSVAFC10FZHjcRxYYNgBpAQV/3igDONlKP6e7jW0qa8azr/0MAyThA1XmY0Lfjb+UpNaOaMAnAjPjD/XFxf7+4V8Qps+939/aKRXjdwlavt+ot2fbhM8U9exY8ls6yYGms46U3rqMIgOQ/KQBIEWCRQkfQ08kEHjFAjgBY/xNEA4sUlREUMLNkJpIj3pV832IDu39uynQHc3VlulIEmB/f5XDMDxjDRwI4ZwmPrHgkhrE8YjxQ9aRer+M/fVguH2Mrl8uHtXp9HzO9L24wz5oZQBFGMnDwcEMxP9vyAOATBwvOAkJDYH17O8l36ZgHNK1o/JM0tpp8SwPIvO7O6Mmz4EdL020CeG5X1ut1pYL30HBmkPVqtTbaCtt6/avVqm0Dba++3I5y7AILhSbdTfwrC6AzJeO/o92TyXPgaj9XyUCFwhN7ACdG6jPYFg0VBXAfmQAeL16tHhhWA+Ff5aFAS9e2vFqTCQA5wEDuYFFYYn6jy2ObQ5nTxmlRXG9ZWm1cW9x10ElWG6HNYcfa83kUrAp30+POZTMXc+DHHlfVQIP9hYGJ5jtHQaGwLJ0m/1usbI4J/Nj9XMre25AxmjjZAB6aFxJtC1O3N4bvQj8u5nDWOMhJ6DcljgWOEdcGAJOAsgCg+0+DU5lciVnJoYoPLCQBLIgtpAsgUBmhHCayYTipEff3GAig1b+Lt+T78kJfpHJvg7McAXD7vA8EkJIF0CX4dqUnP/QFpSbSseNukMkCt4KzXHJy65LLkS08MS/510AAXVx5G9R6qZQ9e0AAn8/p9hnRj3sYlz2XygHgCVrd5iQABtHowdnR4Lc4DpD/VGb4n2SW96rgAAFcbBEAYNHDKk8YvCcNX7ogYSUMuTowJ/fauzsNNDjAcX36orp06dXD+tC23BcaHMfsAQhAf1zuGngkS44CyN4fA0FL5VuMcplPKxpjiAdb0ATwr9caCvTjPzQBKAnASj+gzB1JzGoKaN44akZ4ql2yo7Oi1WxCeu5qCgTAeZ4NEulKSIcCluYAy2Rwv8cSGVz0wVmyqTjiepTyoCEh5fZvjkr+fkdgniVthWz9uFmtblgw2MqCvc8wHMjRTqbVcbCwVKHykIO8aui+y4VC6Y6UO0L0TfKCUvKdsLlngCtJSQAyzkouQHCgXRN4MnR9qQ0sFhkLAPI8kQL6FhjGiLWMqbIaolZp5h/d9eO8iB/3r1uhGmkrwwDevLdNAMkPNlY6+e2dNAkwiscAvnFDPlhy4lQj5RLxIzNhMc0DKECUdvHLzABdflqNk7M55rO14Ryj+kgUcM40AKbGdavAIEQCeNIE0MmM+snzkq8rCUzpA4zMwJ/un/X6p7VTgFNceviSH0AMy4NR48koCYS1nzgaQfVT7sN7pgjbe0YCUA6AZKXnxxcJAFr7AewFaNNOR/IAa5LLzNGl6/zRS79+uR1tihmjzpoJAM6sJwkgKP3yauWAfi4ZBMAuQHpKEgC1qkYuXKxLOQ5KSRZyOKQjJxOy7TwHuK4/SKp6O2pbUV04BS8jRrja/fpWkjGZHA2HO53ZODHHI2V5e3JJTgNMr/EPdNi/muE/0k+bN1bISahIKclWgLJX4ASmCoJH14+Dyx8xYTP6HYrocBH16+SFcGhZcM1ZuLKEl7cAoNNMg+O8rjou+pwnxNhH5DMd4OvgiCgmNg6JHn9w/Jn/juCbZetRCs5uyGceI+2yox5sE0B/jCMPg9/cMWgJ/LAAhi9beLAVxyzWSIWNPe5BZSTckQRwSAZAV36fSKAaH895npnd637cZQr4TDQAL+LBLuvDSACP5D3ncvwAP6MneWlx0Q1wSTd9gI6ZFCC/+FByPCKAWx1nV+u0zf86k054TytQABZ/Y/wD9u/x8Z7jDoxoJQDww9Pcdl62ANrIT51NG2D0NZUxHvQEFxhpW6ynL8Q8Tqbttw3ZmUoozmbtV9MA//omYAmApgUDI89eWt6YPAANWwnc5tmyYTpnmbevZ6xUBEBzV8IZLWEHFlUzKsFb853AWWM8rw1npo0gmVuDZKuzBkRS4RAbKGA+TDYUwo2lPicC+JBIcyWSskOkFUh6PPDkv+aKXpJsRTn+sGMxyAEBBSrggr6AKO6lnhwnseT+nwA9bxmhEr3zUd1TPZz2cYRUAfBQa+9zyUbV5PI48IW2AhT2KVoQ1LtNPmemBQCt5/uz+ZglPBmC5+jemP8EZQSgAbALVno3B/8obg6x3llwesedt4J/N4q7R8Ks1CR1BHHUq8EZkVVweJwH1gMtnSXdDP/Y/+Mm4M8AA0A81s775BswP3GuUDx2tQYYQt85yYt5CKJRFgRgArAqpg/Q2coIYhPdBwJ4FOCQj8wYG8nsK93vu+oeawJ+fWorZ41L90kvtjJFAlC9Pz8BPNuFF30AW2QEYPgAkwc/n9cpBIULRhsjG8C2cN82pLEjCSAo/frV5gT4iy8MAkAKgLuBIoCcGVA9XubxzzXR1CydigEyH8C10SmPNrYUVS/3PWYA7hq9OebrRNtRh6hesB0LRQeSCL+VmQQEME4FEkBQTnAr3SiKc7seyQ1/LOoKje1TKU/mEpoPHbi6K5oCcFBf+LjXjd+1yA3G0Wl05XPl1kMOceSW5uVeKIeyEwGEwtMLYHq+/3E7M6q3XwrEdipA4B9eJ7T/sToWtRz7s5l7qTR8hX94Oixk5hdbAEE9JgIAeAI24QZrNT7wsd7hd4lErmzwrDr0+OiVFYA+kPh9fBePjxqOwz2V8oMWpV7S7Rpfxx+oftqlv7UdHKEB0CWBEC0AVgpPuRgASSTQI060W68t7hPOubUsVXdnx33eNgGMVABC3TMSgAiDJ9qkMrTZEHiesfLjkulP/T94APDr8CWb6cCtwNs25x+tJxMNaN1W3hYB0JkGAngyCECFAYB2vvrM+VznW/gXgP8XDAAweJQF4Cpj/OLvP71WEOAXlgD0YOAlXOPFT+ABvN8EbvV9XflmlvVmx3pjqb6mYsPqwM12DPvfBiBgKm4UbWwJOrAwlJYl2se+q/Gfo4Dm0JElyu35h2Sj/EA1N8TgCEefAQHUmppmItMIYDGjeerhjpGXLD4wAZi/2Kz+zrVI5KrwIE6cusBbgLNw1x+cHtX2HA9p4L+8XTtPI0saVbddrX4wGrS0NIZBW5IXoxYT0AxyQEvrBC/a3Qmu0A1u1M42QLKDSbBGDkdY4+sMiWCz/Qub7Ab7AywRG4P/hB2QEDjY71FVXW1zb0g39jB+VD+oc+p8j/pKeepE9IGasI4AP2mfqkCTcQnoj8uzgESlTw4AW5xgeOV4e4YUYE0WBom+Peyau9dVV8MXcvEuiqbbX3vKrf/FhPF6n33lkNl3uRaVHx72ukagMwUkGAQQsycwMBj++hmos9upP1r6nx/VPgZ9vwyO/3g0p4U1tSMkHKT66131/STtc59vRee9Lr/xVfsYQAFckkDSBHA3Mgk0Oog2osI7pkQW6YCFLgdWjgbqEB1C7mU2DzD08GxQNipyhBZGAKhjAw0sJ3eju3tcL3iOK5/A3+xf1LW35gvl1LO3+2XgxlaxVYV/JICgRABaz4zuJssZqTqa3yOi5WQT/xRffD5iAqg43lQoAvjfr29FAP8xBBCruUBOUJfGBWDj9uLIdWzvrKNHGkr7xQVkdBogFaXHp3AvXScAamroiZgDCX5Ua1yZfm4FCwAldZ/gjysH7qW/l4Z8cSTITRU11Hnn6lFqFhis4HBRx4IHG4c8eCpy6DB8G4jZ8IfKf5Cdn/72ea8SCUUA4VC3YJlL6fDRLRRA7NuxDoDM301eVMEBKALy692KCE3F2lDsfBxjLRWF/jIVp8MZdKndbzqs94Usbfrfoe+YiXRMALXzH4hMlOYEf2QAsFOIAOrdbl7a8Kb1m4LFf2AoYPhNYjJC71s+ON79VJ07SgjNvI7Ms9L3czg7VRG4dQ38AgO/2r7kX5EN6oUCeECw6ph+oQAmLVN5Tw84+5PRRvTPdgDA11Ci4w1frGXxkz1ecgPuk/XBGcYw1k9WzwuMEbbgNVwQdav6wk690gYWhrs5/hMBzBdrCkDFAUarVvSo/L9RuLj/fldUPjRJQ2TxaAIIDAG8WTkgrAaiCKCqZgJhEEDKDBRAWQSk4yonZuhnuHw19vMyErGmSNppVRmxgxApN0XeuHFDPMBhw1q4PUwtlSAtl8Nwpspae57fTH6PAI6fOFgXNaVGfl6yOvgCrnUEGv8B0zjVFoI5psx2I5/UCY7zrVYUbl2XA5DJeDee8vxp0e8pA6M4RpJ+IALAyW60qoAhAYyjidOUqyYkyboI6PWuxqeXe82dnZ3G3uVx/yvVZCyuxKYzuStaLfH5h3HgfWE/PjzX44qjlRn7AMJrIADEvqEAVOnvIiEeo528TAAZHqXbb0YYN1M+UD/6dE1UI5ECer3uYNh4qlIUIAgbYG/Z4M/pDkTsA/QHPRIAZP1rC+FqO9AxwPjh5btSAEUSDSiAifdpS8eaeLw5OnoZjTaGzlL2bXs5JwIIQNgXH7pnlsBUAN5i8v3vey0Y/8nhSJGC2wlsq9XqBWchVsTKEMCt3k9WkeMWw77BP5UsWEIT8KE1LwBWL36uhdA1n8LacoV5RxvTmokplp8+qXVGfCKAaBqF/36zmQB/Yh+AXhjUcefOE3bTjGGbFdCVxzi6VGGfvzdFEbgmwj5LXlAA+2olRLUaYjwdYCfOVFtFH06744P69nbjYCxxnNu0NwCL275JvPC3rtLC22ZJbsJc1hBcVGe2I/m084wgk5dalXs4T0ZNRPME+SeTNYEis4MgpNawLE9NHHToUyYAgZ6J8W5AHTy+ek3eHPqOunYmJcsAmJ6n0vhELcLjmOdazUE1ybpQNIZG059c1M8Y3VPw1zE4edV0K1bCOq6+GfV7pM31jnpCDqoRphqKQddGf8YUIK8uvZCcElifrPLh5huyR44MgEmIvV4+bM7ohtc+gqnI36R/iAeS3YgmQbYc9D7mN9y6UgJywD4jIgCTQ1ugHwlgpWxiU3rLdY6W96NXwGMxwC0SAFBuUJt8P2mv7ZiXs2wJ2FkJtJYv93jkW8UAo/YtbRPsG84DtlDGPxDAk+OaUd+rWgTguSGc3G0B/7Y2AkZ3o8kLph29TO4oNlE+fUUU9/tIALwoEBOACP/wdj7ABw4CcDkQ18FZGP4YIZlp+GsWkB99nqVN8H/veO57V5d2UraVp4LQGriuVztNVVNrikJiMjFV+eJunq077dLziHJacfeCeJCWggn2yA2qOybIBsLBA2XQHfX5WxSQ/uzr0R/PbXrek5v4heb6+UFHXgAAIABJREFUHz2sJv4PECfHnR4LGPLCs/cBD3g+Q1X3ThpDybAbmhkYJyMLQMRWxnMsfDX+l65UlvIti1mJmibgAvhycsPG6YGPJZH7P7qF9513OXjHjnNefRt1Oqj0XqKxrSgAxNxMYA5ieJoS8uGnk8MPEid8VnYH5404DKN453CItwDfwO+rjESggH79CQngOMW7TdBX7AHqoimIAKImfLRsYeRdVmFqrgSG7E4KR7v2ARib2BCAW2mtRmsTgtt2oA7shoc5lUDEqTmjdnsdZWDtrxZLGP2BA5aLFTofecxWGgDZ4PYeq4p6bgs0RIF9wv/t6DlwjI/b8/USWryEuljZCsBIkxMqDUZzEajAoO3qMBnGIHhcXGpoyxQEBQKo/fmfb+wDRAXA8J/DCD8gAsg0cDURNAJHuQksZ38RX1WhLzXTW9lJUR0RxG2V9ARzigbPKwbHBS2qphLbYbw2mUmb2x7WyMafx3jAByMSUOdvERhzt1IADWkG8OJC4UemnfHp+fnxcCBT1Rp/v6h9UicCqKfavFEHgt/lxZanp4wLnwvB8JQQ4eHMpA13iBInSfGW/ZlMHyBTB8DzGxDjbl311uAFBDB2KxVrygoQAFhFKdFHphkATYDTEJMNgnCvmzP0OzyMd5IOHUT2ulf9/qCToDeY3iAOIQagsmo/mrjyem2cqpb5CXcY45kAwt2eZAFwY3RADtxJa+SZIAD5zEsGdGETV0xiacV7HtkJACcW+pkKVrM5l0AWYJGz264kK04Ahfco9CeTe8TjCQ/6dEDKGmjfjlYxMnd1eXdXIF9tJ4vAiF4XuFzJZfpTO8EzE4BtBZh4gMlIWvN26pMfrY70WoMeL88xFW9WDYR9gLQQlvDxelAAVJsZg9Z0OcbFL1tVx3Ut6aMCABr6qvyFiO2EaT++kBqTSVlUGNhvWhsIg93InnY9HaavQZ+AOfZ8g7J+kqnezg8DbYCmUzV8ggo97qcGvIm6Wn6WSppkZ2fZmcY/QocHZvlxRiPcJcuDzOYPOQ5Uvil2k6AggDja+w3FoXOkXiW3zBCaOjm8Mz7e9GZeEIAO5snTaqUwATAVKAgP4TpySxXRdRyENPtQbF10Cf20E8qzpMN/dyoJg7/i6x1FAUgeKIawqgpcnriQWXaWw36T3fBthz+HwNQX0cKsrDzjNzQFZPJQUBpREQTQmTYFeMAmXlMAnuOhDdC2w3624AaAv6hK7F7M1r2NRPXfkSoMRi47BL/CrK43Ptmf4431FyAhFPw1BbRvl9Wi68faXlYnV4WTa9+213KB2IZAM6MsDNrlgMHo5QjxjwQQGAJ4s2ogv/63xgQwFQHDf+74h2iAlzbsB/Jn33NUgJ9tfGdfLXuqEt+VkhCxjdzoWJb7cGLAZr1m3jJ27nBqFABaAWA+vwYO4pDLqaksMBuvnbkBdSLZO1c1IkB8SE0j5owQ8WdnZ/x0xr9Z9EWIPX0MaITDHIesfDGJHApOlXMxEdgqC+gL5/pV+fJbmz4tiwM6xE5DQXnWuySwM2W+8yM5CEoKAAigdg4EwFyYaxZIsj2VpPI07DLyDcp551uBjw7cAX4J9QGRIJhn1xF5N3egObpj8NEbfX6nIdg+KkiC2EfiuFG/JJ3Go1EArcXd3ahdhj+O3O81ARRrb3ge2gB26H8N3CcLHyMWaFuEL0gA93aLlm3Oiw/dGmAjRjFiiLN9qNhHHD5/H60LgDatVKLHfOUwM+zkwMlZJkBps4VB2+Yu/QIKHiYABwlgRgTwdtVA/hJqAvDw4pACnj6nSbIJovSvwtWBP9f1TFYVj/vTKIpaETsTYrtkmmgWHTgxpoD1SrJua2AHlb/sBJ5xJMDP9FIWg636Fj/kYMc3ZVdn1xK7YyfTsDXHkWc71VI1Jzd494tMygjLMgv5JfxrNMKHx06VnIDTcW+DyzL5QZgBWPyft6v3aRxN47JjWzYBidNYygAjecUN6FXQiWQQhV1EuoFFMytWo9EWlpDG1V6BNNsyBeUIpOx0kRjpmhO6/oor7u5P4ESdhOQvuKmgoKFIcc/H+2U77HY4CYFgJ7bj3+/5PR/v84albsB++MZWDEr4zJU15YNk8Es1crBEX0P8Eu2rtrDogcO6K0oBqCONFk5QydA50UyW5MtNjlBOVmG7AjhA0QCDWII6LVADyZfhhrtEbv7xEg1xvVmBV/AcFXSezpgCXy7QJdEbfvolSc9QG8CjoJ3MxPFSrAlg4YFjgGXEdK8uywTg0tcW3/crFQClwpv9u0gRe0xiASP3JRaQeFTAZ/BfDyQDYOnutO2gMRvNPncHlWV/FhmbjwRQGvza8O5NEKCkUMrwt3jLEgV3ygOgWcGQAIYLT9cN5EVTDQamBAAukxMggFQRu7m0X/pW7B97CPU4GdYbDnvNUY8T2PRWnt0yaXI+xyg/uih/HWWuVWccNFdsOSwMdwixfWM1Fj1PUr4i8aK0jkB0diaqPk45AWGd6TTuc/kovQmuIICaPMxzD8PTTpUnUyFWQh416mIFuN3zDGf/ep2UI6sW8ZXJraosmJlyPNyVyIEzc+nvgAegkHqWsYuf7wbKBZDa6cY/TeDLTAv7SJJDx6cmdVE0/fIRkF1oEUA2v8AHboJ/pywBPrAI4MjN6sTDROGklegzdibPFaiLJhHAMDjuCPk6ugm0q8kXHJbn0RCLGMfR1+1ld9YAQFRGmoEvKX0ALbHLDDDoqYvOxdr8bgl7iHcj6kumnV9B/M/CtkMEsHB1sT+orjOL2Pw7TgM9gBIBOA3wAbo197+cSHjk31j1sNVeIgZwbyQBPN3EwD//U44EwlmBpAJwQ/CNM62C+aJJ4YtfDU1LdNL7ckIxTFz0Rs0RaQCggOYwtiennKynYg7SK/RicwAse3ZFK43d2RBi/trpeqgn2ImaOwkbpFQymCIyDGHy23maA7yld0kV/fqCznPFAKV9Fdm6j708fb+5mMEFXjocOEvpbswKwLUVgMoDeK+TcszDCj8IKwpRwz7tFhpn0YqoWjWITzofEaRnCLFMWt93bbdhV2gFwXipIAKwNU2WvMWh6TRRTbQKdh0pgO4pYV+fCP6b2JSUQSGjKe/Z3w7Cc0UA6ozDGciXh0gAMSYBBFMDkcAZbX7u4yBDdBixFG9OwQ0lAZZKDgAfjA+w7la9aL3Rla/nRHfi236/awlwvF0by1+x7RwJ7FP1EWnau+uL2mr791Np/2G/YtlA1xTEt4OHvownWBUNJo1g1EEV/sB38RbiHxgAkwBjIAB/4fsnawmumgFgIbA8Gq9du2SI2dNdz5EtEdwg9MHq9wD4Tf5lNBz14DZiIRDaBBCx8k21V1lS2XUaEGitZYLFjGrxnxViDolg1C3wLALYS9I5C17zUaCTlrFkAH/TkhXWjuUIf7zhPcsVi6TiOBWtMR0TuLi74AwrllHP4lQlAVxqBmBN/YO/+9O3MulZdjweX1K1Y1mOz8m28jydT4kojPnlKN8PnjU6m0Mw63ju1bHwIsSrppqpyo12PpLAJ5MvqZOQn7KEKrJU+wAZhQiT1lhOduv+VLtQUnHo+jSCamHzlw7s91dLHwA9tMaSAOKYxsZVTSV6822uA7LGm5FDddvvVhx/pephu1moqvPg52hGsYWB1uDzsa/AjWl+bPfBvQLC24t+faVbT+GflboVBJBty/rzIwCSgh5dug8eJgGRADwigHHTf/5kEwP/+h9DAA5HAJwIbG39ewXfc8vV7mVMPj9Kf7yD5Sfww4IDGUcjvzQ9dfgj+9raHqc2ZLKKr4EBwDdO4FTar4WNU5EZzz7Vfqp47weGAMatxBgki2RAmEbq7WJTDhjudBQOLdsv7zlDRuMf10l2IkquYRn8CjvXFgfA55x4rg4B+NaEX/L5BhmglDb4LezTZ6odI+O7DZfgJTgAbvDsGGk6VwfICmA74utRe07eAsZODJvlTIebRAAYNAu8LZRBbOgN8AvJA/QChw+YB8DH35tQqzGA8LODrH6dnMiWS9ibgf79VZMUvMsqJQF4pPXtxWfpOQ/U0z5CUXoAhgC4cqh31a8rABXGu4+44QenpsldsOD/GPiv6Q7/x+nIybgBAdzXQwCDQU85AI1Fh6vAShLA8SnyWNo9Bf6KE2B5O0QA987WIhNApBTAk00M/N1f//XcxADh6KaNqTNZS0RWN6Liz1yZTcYFCGBECgDVP9xGfOsR/JujYVSan368yUYvrYfYDESVhhYJ2P/AsQiASw3iT8KAQVMJxsTCQE+y543fi7nvn/wwDQz8zVDO9mGnYv4ZLHmunpEBcpQB5MKeT6kODI3581ZH2LkCegislrQIQE77aYIBk3C7lt3jaLshw7RKK2y2RZK88vSMlBugiHDvviqEITiPIt2QiaWa1zxnAlCHhHeR7/qxxD+Q4OoHTGYUheHNAldjJlCyAAMDFAtI9nzZbDAI11MtLjRfij3ZdHXhBAggp537qs9SvhxKAvARaRfKShvEoE9ciQBIAhjO+t3unBA7bXYbBdyQhhLz8b1yAkrJvEc1wPWtxx8Tx+BqfK6vf9VzNAG4HPoKSgQQ9K40AxiGKjkBg3m+y/7+XYMFwCLHAIkAnmokwHd//+OCTQCA/7Yzweou/Da/0Q3vxOxvXBVgdpUCIPCj/B82lQewAE9lHwDO6vAVlcxk87FvXfeI/6Tl2cEfnU04EUZCaIyA0bvR8y9iWGpN8OVYuu5g7zcjy6EwGiDcyDuZCXho+BsvQEUC2fhFssQOCGDhXBGARQPifVQmgMr8B6ABmkdZUqKAEurTyu/6jUEYFRTjJ2BcRpvSsluulMjWAxk116O0QvAUGPvmcMThIndaY6c5PPooxIdMmnsJZ1pRvpTK4CDx896ERn7h1tFaZmSF+iHWxrIf8mknsWOp0j+IdSGw/yDz7dJMqprbeKtRJwDqH9btV6y/Mu7dwV0QqIYl2LcooAF6ygf4nQVER9hgrwkIAJBcX2UW8jwF2Akr8JUEcKw8ZXx7cVFNUSh+4p3cvx50K64BpihftBcbRACuTgI8f7KRAP9AH74pkwBymXxJMnPpf9NedCswBBAOmxzuG5H335QeAJl/fPLjEgNE/nadAfIqD5CR6xxgGN00G4kvVeHejrDMv9lsI1Rta9CmhSu4Vm5dd98IPj81PE0Atg7wwo2DjhX9V7Yyl0/qRLBzsha6umWYPzydFypZ9RQB6JlAqvODNv930GFJVGK02rHJ33OGf9L5shxxR65LeEStJCsY1181AeRbrhEATACLxygU1MIHI95Sz3BPec3hy48UpUktT0FdAIV+kP7PjkJurkcpxr0sNQqAN4EvhF0Af1kkQn2ikiniJNQjAaiTljLQxlj2H+KlKv55E598gFqEnYjjqucq/FPHqvaL2YVKBfyeAuhe3U1lGxsigOs5IYCZBwzB45MXYzOTpl2oAE4AjvapUoDGf//6fta31D/rnsFVLAUAK4sxDgV6spbgP/8XkwBEABJ17enUOU0yCQBCzzfGULrqaAJgASDzfvBg15+xT1xgSQAKuXvhHtXN20BLbfNFF3kisDeG55SjPxKtfmuOY5KJc2x9F0RSBICexZCXArA236CNdUjRrlKAx83yIWXzjAAoUQC9RO5353Td0/NCAQEEBRFleX/y3UB7SXoqIGtacHqMg9dcE6gpoK6K7GPE+sNO1gojNUAWZ5E+V9+SCXSKw4aatZpDtYEbbWSKALRjA37KjVUSDeuGRx/kt1OGs6IARj/syKd1mvYJXRDE2+ssTUtiKc8zcMmwixr4fR2RGdKRCmB7GOjKMZzya2Ci5Eom3zuPEEAQP9QJgCV8Fyx0EKgeQjimvw0rc73v/m9LANj2hbuolAZ8yt08Arh3Gq7qhxnL3HdoKwBkjgcqMuzq0uaBjgAQ/h/ururlQt1ZsCQJIPBVFvD7pxoK9Ou//+LL3H2IEYD21Gl4uwVhqGqh3y2rflBIAE3K+sGmJP17KAIA+n/jMCA81OwU3FYqcLxwM+/wuMB6mI2MP42EyY+mNv7tuh1/bY4PIbKViAiGCSAOoo3CiiiqTKZ4txgHpoA5DvT01LCx3z7pmMsfDvxA3aTZ5DKCZKfhmRo7IIBlUWEkhNanJTUtSmz6gJYVAHX7+NOBGgPFB1XM846Yewj+nZMfJy73Ybykq9z7IpS+1k5K8trTJ04qAFJEedmlycSabxEArOpM/nBMrU2yagyEP4Cz/51sux2p4eC4/J+3q/dpJMniV1XdrW670aKlJcYGySPvYCETwCwiGEvn4Jgd6U47WhGNdAHRbkCw0UkQOERCQtaFJIs06mCz0wYXXL7SBZwILjIz9D9hByQEBFfvo77aPRfSmPUybndVV9f71fuq91NTurZvPW1PuewGpm56qh45CAYzV05/gQDgheXh/fXbuQg2AnhPTS4wY285teft5VMlzHoMhQQTQID57RXswAuaqPv/X+t1eTyUptIpduuqwQc4F6ZACQcBYN0svBqJSSEjRICry1ofqZ2r24fNxW1DoaFHoQEAMaBAF0D7OYMAWAyAAKCgwRuKtFMLuFPMqvcXZeWfAABsffht3xn1/242Nnhwl5KGaTRNKaL3f+7hJGM59iBmxKzio90djaqqQf71w//c2V7KncOsPG4Gk8uSbPXEO8HWAzz8nAQ7GDAZzfQvi14ROJEWDAdKP1kS5H3rnXUzqZxWole4rrHkbY6w/t9TafqemqIBy0YAJEcMDz+YYiKj0P/wxrM7iHH55z3deuLKsIIJkJ8FjkTsSu8w9VK1UANIj3peigPnW7/pxzVvqMh2LqjgAiHShzdOsskxozHydKuStkoX+L3Wvke/DXlvTbrYPhH/JffTPd/TQYOk7QP7RKHuzmW9gv/l1e0iqDdtEQB2mmrznM+iN8v69fphKDyTHL6mhsniCYjAzLafpZUftuncPi0KtWJmNnZ8fn55+TZ03F/qTgnJ/N2S1n+Mdnv7YvTkk/HD1TViwOvXng8QNhtd3XxTlgvkJaNOG96iy7kwGkBBFoAGgOcKAvzh1+9MEGAWYQxAVOr+Vc9k47iN9FCeS+YWAAA1rMk/ZhvAHC30B8xSs/wzAKhEDr7fIwhwofeRpRXvTb5dSxPhAX9IwhD3mxLm/5o6HixghovyyXZN/vV/3hyk3gZGziyIiN8AF+Sdw2OughgmA+LkxyIgIgmT7JP2UcPupB7G4ThVkhOl4gYVoBLRff7qh+09twfIV28YUZiNaXTajSKSCq6Tr99WJw2tb6SuTiuR2H8+7AW7lfG0d2tFGAzRshOl3ek210hzD8jsgQTx70aJLdKB4pAcvKvthYTRWmcRLyZ7vfruxt67FduujB5QWCxFH9H2Xd2M6UZ5snkKTaHNbJ/jixh/idFnPqwXq9Sopor5DZ6Iq/Jb528wO3Vvn+aFKz1YCgg4xY/X51f142ZTcYVShYnAM3KCR/6iAoZPPL+5vjZNOljTDW3mZTk/v65REevzFoLlX8UWAJ4tCPDbVxwEaM/QgAIIuN/v2V07hjNjdDL5YSBy5SY3r/ttVP3J/v84u0NboI2xgXZcRMRQG7GrCRKmNqbbe+GeWJb+k4uBQvGvyb/DgHiroRTQZMdGGwsCADEx9cd7S7UFfeUYeHMKrnyXJNn9yqszZEMa+d55pAfbnuz3ZZIr5VfaSOSn/Z/3agQkuuGNzCgvMW6LoP1RPgKAvwJK0IkkVYPTD25L8tJO4R4VIHq1mmrxz1n6S57fW03kJ31qXZiKLFoPuajVLEFylKXqtvB0oqp7cUyF14zcs2H2c2+yu6XFP3d1uuAV9T/UdnDBX92Unlv+N1vogZaT0eh4e2rbS0T6eH1+biSY34Gdt507CyCA7QLSgT1Wb09A9Qqt6gAgCz0Qxfzplq4dahrwDzePXxUJy39pnU6zx7+fB9eGpfqpYNcL5wHOyAeWJq4EMyZGaDPg4eb8unYBwJk8L8X8v9d1BDi/3dQAoAIAmLV+fx4AePny9xezmIuQcRRQic+ne6Ywxfbxydn0T7vrnYM1JbxnkmDlcvL24YFgMCNIsEds60obANDqk+gfno3IquXi/r297bP9wVqW+VFVad1YXvXlDtNS4fvGxqDT7WwZb571ahd9/HwDTh3Q0RmsJtKfS0QNxJ0jFUVG99HB+ulk5BEFgbIyOV3va2RSVv5NnQNZHGAzGwNzAG1aZ016AICMi2BhBQiQGaMIZO79xsVkxAyFPo05yv7JdHewGmUiD8pj0RCt6BHAA9veIL4u5RVlL9Fbl2x17IHMXvrMo362RHElCQLer09Pti0ZKtAr4+PprGSJcYHBe4nmiMyJMKzbwR86BjmOtX7Y9LdHIrd1cLBaOPqI4SYRctUOrZK7cmAhbBeyaPyKPhJlC1W6BGLdk6FINh+ebkHi7aILCHDz9PBNTpVHaWUHZC2TEqrczRdLrSyMC0CQCwAAQE/1WeYNI2Y3aSHSmHOjQeealnvAmUUxzFf0sbPc+4eHQrEGINi10G5t/vZcPkBMBIZkHiQFwXGr0sne8buz04v1ztbqikoqbSJXwk5A8m/B7Y9bgAGoCmAOUAsVAXi1xzNMEYoT1rLtDIOhrtRBZ+Pb6Zk+Jvpnf9A5UFkR2m9imYQRPA+Gpcdw1QBZjZdwhBac9M8hBCqycDEpYMNyYUCDkoKhd9n9veofrR9C36Zn0+nFUfcgz9JMuIWPQwmkzyBLVkWEWZTvXyS2/wUnWDIYxk4ByEz8DadspcfjaP9ienLsQHHvRDd/OODGc788Jnn5YRyxdazh6pImzH2WrD2BngFnVewU4CSmpHF4URayaqf76nD3dILH2dnu0eBAOT6oUr8oDlFiUrz+YlUJZgzTtpSGVelz+mCRadyEDQ8ic3W0wIWoxFANh9WQj52d4c5wiHaGqMu/Udz0/NTGPZxLZ+NRDdNI1TUATlmDnlRSQ83D4w0fT4/z+dclFuEAl6o0ShV5eIAfjC+/g3VJ9F9DKXLqFGwFSnHNRLu3HWx7i4hiSFRRspg/PmGVwceHxaYCL99Krn+gx4rvlW64qnDxVyYKiADw3TNFAV/+QqxgEMlLrUMz6vZXVdputT7FIGAeF5hVzgvr+UMWI98D0BrjrmAMDrIboDAAYHKpZQS7d9IiIxd0lNQem9EAwmVKStHwjBt0WTMV7IpFCYzovpaA8biZKymsduIkQMosi9ME96pB4d/PkfSvY0OTrM/wnAhbDACgbaMloAQUtug3O9/pK1WlBT3PV7f0WkrKRH9FwFbCRPijj+SxerLKkl3dGJTWx8qQJpHTmm3JSneBPPcuJZeCLIbYEZAlA/4D2uwNdWKJBM6ioJYZikR4ffMP+0nuNxm69PAZG7eaWbpVJYTyL9sAADQz0FRVBmUgN1MIVZ8dUgoz4wAqqkrqh1mWYlNqIfT6Rl7VHH5hZEvM9YFTPPI76U5GHyBufwVrd5bWWIJoBgJ+VBo2EZ9gzHJy9KshA8mQ5wx/hqOVzBhZXvzrmeqBvfz1j5gGANKKJcFpLwDWVUiYKMXNbC84D3otrPituzapQiT8H2cYGWhDLIBQgB2Bbo75YkKmZFD6iaPYxoaVicval4nZjhnSEjmCJowVuFiQa4FdPMYKoPgcwpLXu8Qr8cKrh/TQT7g8aP4oPJRrjO4CAaDNGsCYEQAVgIwh0SgBKCwCVmbkEYihjohRmAL0cV4xJyhsP3pGgpMY6T8+ZnM04yFrCODuybI+KqObWjkgwOPHVqoaAogaANRBwdF9e8O2/H3VDAC0IAiTjye8B4NoUreRDOQzBOCxAssuoCXZ3LQHPw+mif4rdzeOZ9WIMCNrAYC9Gze4U6Sk9nC9h++Yaw3xai7IqTygzPOCS4LPfvrHL8/lA/z6Rdye0QZe6VH8Br6hBt08ZpFv3ZmRmH28Ixyg2T7GNOEZDE9NwuwVFRG/haXf6KG5bsiGOuwe++AyWbvXROleuGLBt0r4LmlaMcQBkigAKMNs5qZqbRLDBaQVliUU8Cjt2QUwblOKFJoBqbMBXBZeE5Couoh4/yJrn1kJzf34qancZme2SSCk1bsMAuzLD8dwPwbiiYsjQkCJFoBgCKgvvipcxo30S+F+vWYChK0jQBKqAJzrz9DolhIlm8Vf+gMlTPzCCB3LNipUpALAK0C+3ACFB7CZUQBotn/KnBHqqVJuEAhSLZTClYaNqhMBwHMSA//4z/EdL1FxMNRfBABeNjgI2HIAYLQAqAsCDoAxbBLUv3GaRFGDCJOcyaVL+58XcSa+gAD/FwB87Pc9Q7R2shMXESDx4xTs0LXqc+Ir0Mb/HnTBk8dgupVcMIXGloIld+gLpIzlyAYfanfkL/KBPHq3ULpxW5JQ94RKdAL6aGvpXB2SySUjy9wT4XDpA1BpQVU5atjSYoXV5yx+hEpRKYXB9roWIBxEheqA4Oi6TzZlynK5r7jMBB+HaiMYwINCr2ou8hBpORpQQwBf/PH0lPR03vzanjECRFFiYqu1B5d/wVZSIlB7hNUsXvznmaKAP/77J/ZR3fkAsDwj7KygMS3o/lukAdwFSQA4JmQAjGMIMKboZouaEED49G9mStrVC3jeBFUdLuoI4Ke7NKgAbl6Z6fo/3q5lRY4cixKRqSAqZGhotKjFLAz+jtGuP2TA+TP1B/YiCVxeDcyiPUzbeMAYBi+Mly25f2fiPnUlRZS9yqiy65FZEXrdc889kq7g9ryPDtoZ13Fs4IRhbsdR9IzDYaita2QRobPZFiQ366PHgDgaF1wvQUIALVikjUvnqkWm0SRc7e8N7YXPlrq0CDAQzcH3NN23lqbQtYS7Uqt0y2b7VmkYKutB/w9M4mRw5dRYNGoVp+Fkn8cgUDEncf5NGEBfYRtZkvjPHDwpQGsxYLBhkkQMY2vgMtyYx2ipV8S28dlw6hjAqQqwaPwGDFdHAAAgAElEQVQkz1vfYbh/R5q7MbvpbPymju/TkViy4cpwKixvFABY4q3ygT38FxcCA2N3uz7VtrYZlzPyWpgE8CnpKqBFVEA0f84WsgUXLkzWxqwRV+N7qqj92VHWlV2Kf0gAlMmyjZz6kPDM855MAggBzN9P9qDzogCyax86CsK4gJ9raasAKdMQWxcAyshxwEYC0PgLAExmibI5V21sxu9YUaQdDlAOa7NHtCpWrGy6J/oF1GSdusVWNQTtRNRr7XVP5NrlH7XAatzxOsgrcoux9f02BG/c4xRc9q7WKTQEeFYfUl+mAafAMug0HgVpJ4FD4TWGtnQhwLMqCpygW6NXbycIcHcuCMBdVBSYumJD9S2X/NkkywvuX9xqK9Dr/zAAsAbYmVQXcRsAoPprCLAQI1iWe4AThwEAa2AoBYbQWbFhzWMr+PJ5qt3unenI/kNbZIv7qyExc4J1nAlVCp/wAKwKAexoE7lJFcBxsIrUaCvC+hQQmc19QqCRcLlYBgawSHSEWiAnMA17j9VMHhX6DiYqmFbiGKNFABr8xKI29j+ak5qHsdIpTUBOYmtomw9IBPAIdY5SBrVxFRNqv78+8ZMEAHvGqPR/qAXBIcCmU7OxVDqg+csG6J0Kc4cAMFgmVBf69AMAuBM/XRjvNsIxQco03U0VAuxrHXVFZfvSKVDQmP3l7zebBPj1nkKAnMIxA6gYNyqxM8391wAg1/3yawTyi0GAZ4UB/Gw4d9xi7CSAlfINc7JBN41F4w89Akz1vj6r5A08vXtqJOHgUJ2g5Y9e1iueex6BMfRQYjX2ZBIgTGMTzqh8OXCYRPtFfIRGkTQJuO1Ck4XvP5eeTEH8MPbNAw9epY7iT4YyAyhZVHo/rnx8NSLA7GYDAaZWNEEumw9EQREIGAe7LrEz9RYDRuQcQ3WbofLcJ6Ptlxl3iKFcqAkK3OMZCxRGACjya0lMf4gAqxZuNUB3qmZXG/vnB8zIH5XysgOd7852cqdhuK28MTT6KD5dFhimyz9vNQnwJnsBgOmAVe/IbuPgMm8BWjxpAAwAhAKXF7/ADKnjGABBINEW8UYPNIyQRUHKN06r6KGhp4En+Po4vZ4DBAbWgFaDL2SX48wZ0HipQs5QtHMTBdC5puNo9DMu4soSm56OYCSBcmwqAkDCZInEAPJVsiVQ6EFpzEOHAHiyoh5eZsYR+OVKpCAbNSR6laUv49RxZjD3E4t62hpUGzSXOWialCcEjpFmUdZDpyomrv2qsqau7ugBoBINh2rVALLtrYfC3kRQu+5PMf5OJnk6GtVMDlKG35EFjzJ9XM2BtgsZxr8IALbB7q8GAWCKB1Y63VU8tJ2zUbHCwjZfs2iAlz9uNQkAp4KxBngYVtfTMJiWwZXNP5wNgCz/mpEA3D++f9xgO/JWQcoctIVyc6B1d218MVQxRjDm7xNMA5zpFJkQwnR8nee73akGNUqTzNh7SWYQeY0O3vrcxMK1iG4n2PZaCH3z9j/ZyQQMIOEUKzYOSyZZaQCtDAzh3DOAqeyBUI+H6aoxC53h9qtJgGGqWKQMS1LIQtbRHOy8cuZSggDRWk3sUA1ggosQjo3fNsNYtBj8sfr98ISCahs80JaTSgUop3MYUbGSqMhFg9py4MC4RaktgJhsFUesqqOqbiEDPeWvxMqOxAAyH4AQYFSAqXYMavynYWimeqk0usPgcrNJgD8unNgru2NZzbygB4B42QHA01yb8YPpY6Ncr3/+6/PHK9g/zoOzwUEwBxjQxdkV9GA6+ZJr3M+DpIKwUcDUrL6C4MvNRcSrBWPsY/bc45ys6ZM07xP7wEZtKItx0MgA+oIK52MoEfuqE1Q65okBOMyZhhRg2UgAbpNMEhaR0dkH0vmqa2AiYDwYNAx4tVEYBy9IFq++ltkHTaLEPbmy4y5umAKAlYZo0A1LgduXox9jonwaBoL/zPOD9GBxnmMRSIQSrTwh0azlqSeCx3FHD1DfSAtOo0kxa+XZofIdyi5Gp5lqeEHV7vPVNYzYr0inxmbyo0cAXAODPm8hcbcIAcAlaXzf1cYzlcedDgImfKgAwJI/32oS4D1pgCnn0Hs3dLlnOZ0zzLPjC0sZefJPwn84TRe+XC5fPjw8vPr3J0AAeE+idAPaJ+7u3BnZSBlVyhOcZ4qO+X6DvTrXjxE8/C0sxacjSgtYlClEPr7Q6dpcXq3EagDR8lDnCikcgJAJTzzRuwe6p/5FUKfNCQE3qhR5qCAG0OYJWBOQ+AgVwZ2plFWL/jfRAqcztz0aaejqWHY3yhmtk7xFDmy1dQoGT+U4Nz4ZBosjC4krWxsn6Z3Z9pwibjWZEMa9b1XDkbuPk/JK4TVTgRL44ngVRQo2mfN0yAQpd6w3F0iuSqyEQUxFa9IxJy+1PqleGYLnLCitiwtpuzIPzpgT9jzcsCOmV8AEDAAcRvb3L261FejVb6IB+hYA9LTP8zQVw2TXrFshSAkR9e9yuVy/vP/w+uXz5y9fv9kQIEnGsCiZw6RTZqS/LIKdTT9griUn+xMQMH7ySqVwjv8qxeodkemLzt7gYUbR654dMoFwZr8ujhbPAOD7640if8jhSOBF8BdBUdJ5DGZ4GgDZES0IWMoxSmXEFNsvlr19hSMFKSSC5Wf0HWisLiZ5fOQC8TdHVyxlrlqkvrg41RGw1AD1n0WqbQxSYSnCwXPLp7mw0YL5BcI4/h7fS1vONshMu/WxfZ/Kd76+EmdlYjA8qyvp7sjFCU80o7gyDnpJ2jE0QOSAOZCfo+yowcG+Evdk51AVUAP8x9tbTQI8Ll40wBoA+NC/rTwyRBx9OlS20KKjCYDA81+//Pn1zavN/OnM0bfvrxLIe2IM4vg8ZyA5buRoKANFEPxRfFVl+kl33nP450Vwt0NbtuZp6FaVprk3rMefeTzacda9kfsv7cCRvrrRuoUWBC26LlhYSJIQnH22umbrnZ2UMUIOVszBjP/DD/R7agEaRFEqy+AWvcuYu7lUNeKD5d5eWZB3JYsRX+5p41NAtL0RucUjl8hx4ZL00s8guiykzll6STrZZSlmdiRDwVZ0qp3vAEDq9z1915tj3JdcOnAke91ddnaaSS9hAMwDKtzBv/i+XxrvKlflyLbwCe52OwF+v/brAJX/AxptNTSGJGcIEnXmCHr7EYz/8dPXdw+b63+u2PXy1dfHRdfDd5c1u6bdo2lq3xtyKYtLe5fXcV6DRtH9ofsUAeLRI7RsODsrQ7vAievf1+KSQgnygIUmjpZIWZRSjqYZnAIP+UkLgFwhXFqFuVZokVXi7+CfvM4/0IZsnIiFEDpjL2x2Q2/kL/zHckePr4hdJP3orSTtoYCOY+2fWDokZVe1nBOoMVb4vX5SAWyOlhRWsstEETerdzKjazrcP3Ul837ntTqpEAmpfHKl+MneOGcFACMC5CYZhsrf4sGMH2NNrB3PNL3gbrcT4H8XxzKeq/KuoPHX05yl88hiwJvDKoDN9T9++fb13euHl8+7g8d//3jvKXeaTyb09vuetzi7qOsH+s77weX3sabuPsVuFClYCvAKHjXVaGHGjLji1xjNU2v8zGodhDiUOQl1wCgOI5cn4ZSJFZW9dSm8uRJdIvo7eHuCE1iouGTAsA1ThNdkDm1A3kAZWzBdQxKT94LmMiZ9Ytbg1H4rkxG3HjG8ionIT4rFWwpk8SGRrDAS3gASmair2JrlmEVpSrzVVDuxdJH8VI2pnLL/0VVVp0B5YVDa39gyOwOqrHjBUeSbz92LO7sxAhlrjqfLZSvQrSYBQAOk8uRZz16Yyfg7TEs9vdos6frx24d3EPTvBi0vX317vI+RKUA+7hC9oqP1g/Sgg9ZskMOL2XL5Eh9SlNWCKEkZxN25wPd1qR6w09V75IItBXuMebmP3gxhjarLYMa4cg6zNKwaf4lC2F4yllIyrEZKsJbLucv4csJPj0exABDTgSyUjS0LVMArkc9sQPuPvhAxBgQ8ygVtDF+kKIGOe3O8jCuS6XIlgWDgLoqYkgm8olhyRP+QMnc3kZSM5U0GbpDGOB+r6GwPZqOXTrM8FFCPyk8TWGx5VHYzQos6v+ueeRjpc5k9yeoVqEcx3tz5/hICaCKMvefUrzAMZLmnltkM4e3tt9oJ8PrjvVTSQQoMo3GUpT2lQkqGqPW2wXP/2+e3D2D7RwV+/vDm03WJkc057wGkje8xJvY4yqTx/BM+3fAzJWmpNG8u30qdcOaS1ix8ebxywX7CYZQnltkDNAMZxshpfT2MDQugbf60gkIElIgWCIZMzpzyK5NKYK9I/5GCEjXojLS0gFale8rO6smyEwICQkIy6Zrobfh3iRO5J1ZmshSBEjogkVAWIV5XHDfFGGD3kV2/sHmj+BBDL+NGyLeneISmhVV/LaRK/jEkRwvkpfOVVGZ6iPR29V5jduW/8rKYnGOYM/GjJ2qR1HeX/W5mwWurAehDbAl8Li/bAtFH8nyyDgQz6FO24Xmrk8Gfv/1lqRSL/7N3Na9tJFk8k3VPpKpdBQYv9CGBhjnNX+C5uG/+DxYhMYaJRWscMBgfcvAhwQ4EDDr4LkEaW5IxWDLYCjMWDsjBscIYHwyZbivz32xVvVdf3S3bm429H/FrWZZa3aVW9Xu/91lVNm4ZCGdpSZX8i+PwqB5cfq1e0OgPQpc1b/bBWHFDf9yPCDGOzjjBVv0aPqliBiM/a+KAuomt/tHhsEUzosYpsLGshEgnD6n03qhjGQLJMCEPAucgGiyy+VKvaEmWe3ypS3hwObQxAFIHMaU46zqcDYCgMCLGBdoEPoNuV8s18g+IfAjJiaTJAeYRSgj/ZXFkYrPAAFwGUsX4VHxAukki6QEeBHS1jzYAoiVaJuiigF2oUjD6dko8MNSvj7KC61BElqRp0aOW26Tyc8jGxNDBKhqd8Ab074ReiJOzXZniD2UvVA2GpSRO2ATiEgiFCtmYZOGAVK5wa8Vlu7e1Mri3T2yZolFS/FO/B0f9MF3BKBz2giuxCiGA4Kg4YpkWdikVri7qkzDceuxq68k8+DJRjVMDk7OIChPAPWg3d/tnw9B1BfplH2qVPMWZdkik+UWFdUyckgZAjjsBMrSPfCrtU1+tpySGDGgbIBR5AywfwGUXfQUKOCd7rKIKOEtrDEkQ1aLNeFS5C77OSMirESgAMQNhTFCVstD+qjB2/EgHOgDq5ESQKjghfXIdBAIXN1bfaGSGs2+mT7Lu33VIRFyJba6LsWoJLWyyvq8iCcnG4GGR63IEiNGLMqKC+GxnyE2fgaQZUppvrC0SV29rUZDgqBrZwdG0+KcwQNwsXvVTDVvDP2rXslUYBJy1WIfFSqaTwGK0TtxweHB03qlSqwezNbrlpRnSb5xHsmCX3b+jRqNerzd/fzv9iF0a1TM8ZJlqquZRh6R0RFnHJGTsUmkZZQNAmk+siD2RZ2aAtuJpbFiRvma5UDKyLznGNwSZyMnY8b9IK0hFb6t9+bFcsIEjrG+Yx74MNEBbVBYrY6CRQsghlooxcnzMM/oyVu7A8CodBVRgQlWqQ1sVeDUYchCugvazY+1zX1PScQwq/BgwyQnJkjwFAZSYtxciFhAB5aAXSZtDG+5J+Xeh4N2tuq60LohlIIz7dn0NqoyQWrpVMFr17S0BgJoMwEbeJABY6jBmvzsMW4eDg9+O+r3GNX0VL6j1Tgct3mFxlqAZrYetwVGz3v7QdS9Jr2ABLzUqBHQYW7GEgfhp9dLaD2pBENTqzTfv3h88DjkISBQgVv5DeRyxlUdSkWgMXpv7jYCJTAUiAOBkQPlJhxrqjMa6spIpfRR+HwcQhL5OHohqCq3zqbkiI/r4ChflO/lxKE0MWM0hgkSALumGU2G1p4ircT/GgCeVjoCoqjGi90ZpmF3HQSO1crTKK8AX4iKSNBqTBKJmxi2mSfDWo1DCcWwEJzlObImiHK6uG4pVAEllQalIlIIzJBWMgTKWA/Bo59eZ7x5z2vh+45EVOFeYoC7AdKiJRJSYWJavdDuqe7eUBTQmA8jy/mWYg8AIttgV6f7h4Oy036s3uPQE149VeIABwxaDTRKnHHrKC4l484dnfdF2+33o0wxLzMTKRGxIMwclCgNiq5NlNJn9H9YDQbVGvbn75sPvBzN+VQBUQvABVESls/86JtSIVUGFjaz40wEkM94ZSQNAjP6T8j/By9EgJyCCksp+p9qQh7ED0hswuB3GoDmhXofVN2IA0rI3d8rp68S8jco+QD3rYzDSj43ABEUL3kqJwmiOjOpLxyxnidB5Noo/YjNmF2MNQ6RiZCo1Q0lGSJ3StNUPo/BSlrW1g9uSBMrT9agdXVomh7Brt0LrfGk0Ev2UJJdUpz++ez/49XB6aur1441JKhiYs5ALEpP0SRN5HxW3pCrzAx4ku9cfbykLWJ9xHTvAFtN0lFPoZS36jRrm/D4jUOnVGr3+GUOBMHQNYo3z1g9E89C6F/SGrRY7jn3yWRTi1so4P2R8zL0Xj5csB7Vao93c/XB+/vGkM/3Qx/tok0v8h4+n5r6vqpusSKIkjoYwP4F9FMvqTAOAF0BPTEzCWFf0201G52WDoeUqqSIG4WHzG+XowD+DCkrDiP/TacZYBwbEik3m4u0Up26VpZmgkXUIFZKGEAGQ2TsRKxf1gU5GdWAErCJcHgh0wJvIrosS8QNuPKtOtLxqq/NCwu9+KJjAoFZya41nkYctZKKwClvVbOhfZSmbhqftervXZ3TE6PT09Ozs4GAwOBwO08den7h9PbylkQBe8xGJpD6NNVhp8Y9D1xb9wPs3L40bAg2GAv3TU95ZjAaDwdlRv9lmep+3r3Gl0evx7u1dQfVe3Sa25xJq8r/9/X1AGo4BAgKYI8Ag4Lw0u7C0tzPHQH1mZmZqamp6bm5rp3uyVFl5Mlsszp50Oe3hhq8terb34sXaz0+XOFU4vdiiVQphwAQAwAgrHO5qxr1UDEvOuGRUE1xJvlWTH6mSJD4kQeQfRPDOz6pXtohiGi6SXg4vhRRzGmN98IgRQBt/JhtzO51ud3t7+xXfXj17vrw5nrY6ne7eyclT6KRFJNFfS5IqlY+c3nHal8TFrXcNljC5ogd8hHTKNkHy2ATrXME+QOz0fa6r0IZkDCSeGDV4YMn6wjT1cMuifYYl/f5tTQe0TyJqheANY0do/Wo4PDzQov+lLos3FQi5Y1Tjcg/CmDxKkfU2qz0vcbDebR4hnBbxZfIbPfkBswJ2OQSUzs+L56ViSVChVCgUHijiLwtsd7E4Pz87+4TTQhY9KRYE8SZ+LJQqO5NuLIQ/DQC86hKGJ0PZnU9VSUNk1+SLtQIcZ2SOWcnhyJXc9bBhLOXGjq5S9Y1UQBjMYqQHCXAQ4Nd2Qaaerb5clfTy5ep2WdByeTlNm+X1YinRsQVFD7DvGByff3izC5oBmITfPLiLivRd9zSDekmuCMx399CA9fRh98TmXc6zoC6ExgC6Z36bfA3tK3YLMnjTvBB1rBeoU9hvvb3ZQFLOlbAEYWTP4Iz5+lI6bwSB7qlu8bL7HO7Ml10MEW69l6BaQ9gAQu75cyGLhPDPMuHncr6ymEUVrshW5ouM5hlQzM8zMFnobBCqcgDWvEZ82GE+d2FUFWsaAeGAnBEfTsb+yRc5GDiXG+VAgHNj5fhq+RfN4pZCADwIkSsBAOxq8p/Ixk+rq+tr65x+Xmcvn6fl/lg9mAVQXpsHeIUHdq7egDgANNsYbJKc4qVY6Coeu4f8ZeiSz+ZX+XwNiVCworjYw+vF3epj3ZZnq60bTwL8JgBAh1EiGekbHoLse94XFr//LvIMXRE02gwAgBsthfSgINUUZ1Kh/UH1ryzyLQMB+N/CLIo/YMCT7gxMiwjjqyfMqYD5cOOckzk8zoSAEar/kdLZhuSrl59NI9m0Jj1yLhKTFqQRgCPQBdnYWRfivya29TUh/qbyPwbFL7fN4+UXHBcN4U8hbeH8QYmZYx922w0cYeb9HzPif4j9GweuY2QnVKTvy3j7/1s44AW19pvzYkkqplImczILAKx/tADgkRD/irACFhefzBeF+AMEzO7NTdKcaQPY80HknIsL/kiL/2ikRXyUElQwBLR3cIkxP9bj5wbAZafn8moNNQEAhg1AmfivraLscxvg2T9A/Lnc2xBwLO2A8vZ6UWp56HBT+ReMvQwAhBq6E9abKQSeIuACgLvfOhycfm2ybyYoGACUhLaXfqjppkpvtVCaR/lfWFzJ1P+4cVqwIKD4dOs+gRUSsiZb/TafkH+NAGDoK+kX0oqCrxDgMu0fXR0ByDAA1OeTYrLEiQwLgKD4S+lf2/77Mop/0gnY5OK/KV6Wf9h+ySyk0o+ygw3fPwG45wIA7mT1hgBg6DhS9g9O+yD6Xy3cchPgvYjki/B+t5NF3e7J/OyCAIBFMAGyQQARYGkFPQFBpVJlZ4Ne6EmproYADQKOsgAsbT2J8w1cY7ak6BIgGG8B4EyrEwoAFAKMCH3d4cb/mrL9fzF9/rLtASxv4jO8LZd/+el5p7PT2UmS0d1v9+t3+v8GXYBhy/9ORPkBZr/ynuZjFs6GrZCv3pf7xMj5dIF1UiJFDWUlzs7SLFoAGeIv1T/IP09qqWgAmAEL3defPvFZaDPnhZvIj5yLlGxK+ZchuhEAge33j80CXOg84OUewCjt/ufyeXPqRQ0A+bxDnOnnq2j8MwhYf6Zc//JxOR0CPNaRQBUL/IusAqCq8gQqACjl6f7hoF+7k/6b43cv6PX2m+Bj3cGsCAUG9SYvVvzmr3/jyzjLlbaB94XpPjmZIxudCoOAlRX2sAGgYsYAKgoCKswMmDeDAVOji/z9+yoLcCUEcARwMOkuLYCRYb7npHWQKf52xd5lMcBs1x+0v5Z/AQAXZHJr2xT/V9z1NwN/5bT6P0YjAPZvvv5Wrt2hmp74c+L+n/wrJvKt4R/99p31f7Mazwv+yd71vLaRpFEkdzdV6hk2i3vAh82y18zdO6fMLf9BMCMikCIGuUFgdPDBhyiyg0FgBl9DDDKSbWGwvWAPZJP1QLxknEPIVVtt/Tdb31c/urq65cksLGM7VbJkkx84EX6v3vu+V185gWVx4tbOwdmnD1ceXAdREjcSmDUvWGxheNRpNEQBsF1YBNAWgD8g2rLSMClguT8OQlIu5adk4/RZLzc+MlEkYIj1JI0EXNPMZ0IBXI/+pBj+kae8fyCCiyrBQFk4PFrdWN/elvDvbz7h2Ef4F3X+32df8Yu/LpYZdEWM91VemgzPq3D/3cXBjsP//7n4/cWr/kJa/HHn7Jf7IfNKuPVn4Y/n+qm/UB5fthtFBQBUAaYCABKwKGD5h6Xm0ZARvOknN4Y6EDIgp9KTFP4KsUQXAoh/3favTcDnTVhmsPmnfT9jg+YILXtXjFt/hD/if7t/+EDCX6I/TwJ/FxpAflobDeapvBnJKCmCsYBPnhf6r88OXPXfrT+uOvKPX59+zzfpsod7lE7j6L3Kr9Cnp4UUkDEAAH7JAJ1mG5zASykDltonA7iMInv3ylRPZaWmDECBb3QA0h2b/Ebv3zyx9zlJgDT0Y8BeLjG1mEWjx+sbuu+/vXr4jcr8qcd7a++3egGjQUnkoqleOljE39qrhb+8OXvlNn+3/tCWwM7ev7kM8CGpS4QCtyiAhOF3p71GL4d+sw+obAAQQBx3sBhQe4kssPRD43TksahULriCMShnZIDc+0naBtS/rIoAybXtv8/d+2XhzyvCP9iAaFJC6y93f279n7UQ/PAhLYDdAXyvRQBWAEaLZT0ZIcoyAHzrsHL/n3tO+7t1A8oBO3sfz33GJYCZyE3lakQrlUcnK43CJJAJfn2+JY5j4QRq4rm03B2XwkS4AKCAqd0WTFQRUDiAxIwCKCUwMwLItAJgn6UA8DuB8y/AvgfdAOoPx5sbCv58ofVfqyoKWNMUYO3+uvY3kvAHxJscgIwKpLp7frHnGv9u3ZCewNbBxWsS+iBNczYAr34Jw/vHnXbvehOgKSDuxPXYcgKdoyFLglJ5RjIAb+RRSQCiI3tJVrQn/1MAaAb8i/APmoAk87LyJ+EP1n9NqX8T/1UjA6hKf6j9R/MeiVLBbxIAaP/KPtf+Dv5u3aCC4NbB2Wu/4otzb0kW/zjiAwril2YksGkEgUQTIFUAoAG4E9AyoKaTAUFJyYB8QJAmUgEkiV2yT4x0wLU1gMlnFP4Skun2ZcQ/ZURW/gQDQOZP7/2WBChuAnDr/zWFd8yoqBJNAJSyyvAXp/3dunlO4NXZu30Y6mEJAGQAbgS8JAzG3SwF5BWAqAIIG8BXsy2NAH9ZWqqtjiIsBtgRYbzrtlRSViBJbPgn1+3/v6P+h3X/YukPL4RFD5/BcV8F/1Vu/bPS32CAql0FEJW/OeX2qYK/qARySohIWPnu1z2X+nHrZhYD3n7a3634EcmviFNAxCXC01NtBLJRwJwG0BRQkxSAbcEY2oJ5CaCv5aYqCmzV+3JtAfg1ZrQAJ78ZAWIy8ecVr8BLGFh/OO0P+K8L+NtL4T8DfnUEaO3PiwGxRgloDxBx+EPXf+tvrint1g2lgK2Dj+dIAb4ciKWTKxRvLiecAro9xQGpBEg9QNNgAOCAuuwJ6GMCveNFTQGBujEdF94oX/bw4I/hAxLf/vidCkAICAYn+osKf5jLCbwrMniwjfBH/K9vrz5uZVCvegDFHIAK4B5NSFRAAMABAYf/m7cu8u/WDS8GvHr7bn/XV5eYJwYDULC2fug/PF3JU4DdCTA4ILYCgg1MBpSMZEBpWoIPSQEBUUcDfCMQPAP+TO38+Q5gkjn9x51/IfQ9zmwBDaPRsw0Nf/6y+bhanbn9p/I/pQAI/RTMEhKDxPj7tvvhE1p/h3+3bvT6UTiBCV4qn2QJAAuC3Mc+0i2BWRIAsC9NAFcB9bgpKODlsk4GXNFySgAIfsgkmxRghVseLkEAABUlSURBVALzFMCk/p/kBntYxkHE/QsJAI4BQHVDaH8N/ycc7q0c+vVXa3YlkFv/7Nsk+v1ywmEU7p7jldLux8utW1EM+PnTh0wxIPOjHeF0jHqvl80CWAJAKYCOoIA6p4AlzQFwTGCIxwQCWQOQJmBOUQAlaTSgCP5MxP+ZkAATJvHPUuTr0mFS6PzlfyjwSDg86r5IB/2tQ9+v2mpdLwAM9V9dG3Hrn4O/pAD+Utl/99ZF/ty6VU7g4OP5/gIjlJDCkiCrQEugnQ0D6TNBohMQawkgKKDT1hRQS48JYP1/quAvGQAqA2VPRhOLFQBTo4CZOAo00aeBjI4B/Pli548M4HEuCxeP17Pw/8aA/79y27+tATj8IfCPLT7b/EP3clIR1t/9VLl1u2TAq7dv9iv+LArg0AnGq5wCsseBmroMaOz/cZ0/gAPU3JCXMHB0aal3MiBXgeoAqP0fJQDSArcCibmdp/A3dn/1tPEv/g6m/YNi+e95SQXafgh/SQH9Zy2O/hbq/9a1AkDVAaDrr5Cfe6/8irT+Dv9u3TIGgLkhe9wJ/KewLSgoIHp40mxbVYBmx8oDKQaoIwWs1FREuMbJoH04KjNPYH5uivj/dioYQNBCWR0WsgsAAvfaA+haIJoASRuJmvCb6/lDUwOzTV1Z+RML+n6tajH881SA8J8jWvcXwf/8o4v8uXV7ncCOaAtSWsgAURRO7h/XeytFfQDpATpaASAJQD2wLeCPa6kWH82zqzKAfm5u+i1ywXRuiqYA4wFleVjIYIDM/p9+YRQEJfqLe/4Uby1l0eDJukJ/hz/WN58I+LeqtgEw64AiDSS0/6BEqEz859+eBLr+Tvu7dduLARfv9hcYNXMBBgV4jA3Hpys9IQCatgcwFIBAP3/26zEkAxQFLIMTSDgFzJWlEpAVQdEbNA4LJdkSgHik2z/TXQFfOv8gp/7Fbg2DOIbjQ3PvF9YfV0u8tAq7AGspEYwWAxp5cAuijX+oOjLQ/q+2nPZ369ZzABQDFkJoC5L0Ah/NAQHkZ0+bXAZ0bAkQGyWAulIAQAH9OiQDOPp/qjX4Y7lxOop8b24OI8GqJogSoCznCcmmQJLN/zAo/zP1hVEDELt/dsKXqvtz3eLfB+1vwF+EfrT+v17+I/y59Qf4F6V+/Ai1v5v04dadcQJ72BaUN2XaMiCgYfjoOFYUUFADSPGfUkCTAx8UQKOGFNA9mr8ifPeHaSHAAPwBGUH4pEeHZChgovt+TPUEVTJAWP/MhF/EP2zWQvvXFfy3Y9X1r2oB0MoLgPcWCQy+gu+Ra/sJ6eFXvj+/cJu/W3doiYzwAtQDxd0daUIA7gIPIh8KaisrxmAg4zxAFvyKAvqdXk0wQKMBZNA8GRAiW4CyEYgSgDPANDAooGASgKwBMPNqr9yJP/XvHB+K4z4xZn5E11+L/1bVSAAVtgEA/iUSafib9wfhJMXwT3DY16HfrbtGAVAMKGgJoKwOPMJKT0+bKzNrAMgA8LjEOgB/dMEJaAoAGbA5Cq48Dvopoh+Qj/BXGoAjmtqDAJlZD/R9I/KTJQBw/iTkNNXnm3/MH9u67Zft8Yutf7YNGC16GfhTI/VHkrDirL9bd9YJQDFgIibc+koHIP7xqBCpTB6ddHo5/F8i8C9BAFymCgApoNvvtGvyAmKUAf2jRUKFE1BLUIAHQ0TLeMnwzIkgM+v+HvUimkDeH5v+MUAftL9x3ses/BWjX1T+5ikJTPhrAsDIXyisvwv8u3UXGSBNBhiFgBQJUZRUYHJQngKsKiCH/mVfUACXAXGvoURAo7G8jOkgKrU/f6pTw54aHBLgeUGWLQbKCX8zF4XNf/WFjvzFGe1ftTSA6QeMXiBYfyJSBBYB4D+jAm0/t/m7dfeLAeKYgG8fEwBaCCvD4zo3AnER/qEReIk6oC9YAJZwAo2GlgGN1TEMDSgZVwhkpwia1QDh+4nnzZjxg60AGkaDx+vPX3D1zz86IvMjEr/Gbt+a3QaA3X80KCckM+M3jf9EfqhO+7nl1t02AlgM4BRA/RwDwExBPCm02myaRUDpAhD99awLABLoduvNNnLAT4IClpvHA4oTBPEygcDT+386QIyIs4JyyEdh3BdXuUzZcNx9AfCH2N8GxH5x1Eeq+LMVv1Y1ZwNaa6N7XkKyO38q/inbPf/o4O/Wl1QM2A3l0AA1AoOqiwUoC6OnJ52mkQNIk4CyCIgWAD1AHRkAigENQwUstTfHX115WPzDAWKeGh0mbjHD38C5W5FXdLMHyv4ILv3w/cGD9ecS/qAANkTkD1a65WcUgEZ/S2v/rwkp8v1iUHFl9/ziwCV+3fqSZMDPanSQT4xjMHKkKE1Cf3CMFJAxAZlO4KXkAeEEgAJ6oAB+0gXB+tE9LAYI/HvqOpGSogDdGwjsm/d0H4CG5OGzjefc+29IBthYP3zQMtHfqlobvmUAWqLrn3H+adufP0M47Ovafm59iU5gwYeeQHrhjZ4pzE36f9m7mtY2siw6llWiSpWhw7gKtAkMzEo/YPAqs+t/kI1RQLIJwmAQWmiRRWRFoqAghGxDAjIyaiGwvHCyiZlFeiMvjJejrlL+zbx773tVr15VMt3T+fDHPY7jJN3gbsI979xzv+LxokkUsEwoYJl0AjWVBKDwJwrY72DwCw54rDKB9ZpMAG1zYIYCEg74VDFm/SoV2y3NghGE/wjjvzMavpr7bRX/ZsavEUKiC9oi9d9wnCLfHwsh7tH0wzlrf8ad9APfvIOyoO1lwl8tFXecOHpw0t/bkyaAzAKWmAMsdRoADdCHj74yA5K64OvB/NiJnI3kmphcHvZpI0MCJUMBYMTG7tZJU2j/wWg4GI46Q/G196hthH/b6PzLVgFF+P+z4pTLhu/v8LAvg/EXPCx2dXHk2rQEn476pATgObBn9wyMgMQF0AqB+KNJHkCYMADKgMfSERRfX7f6s01BARslzQSgSSE5KiQJILvi2xY5SGMowl+8+vA5GI0g9U+xo2kAPQ1IiaDdfnq8RevC89EPFxS44Z/BqcCLXy6xJkACwNL3CNq4CdvbXoR7XWMcCDkgaQiQWUDCAUIGUHPQS1QBj/cWW5G8Ml6SkU8/Fb//4vGversB+v6g/cX7L8Iftb9fEP9p3Lf1UmBbpP5leca7wP2Dqv85P/6MO88ANC0oZIAqzGmnhfAgRmQJGdDtyqVAkgKoH1gpgDT2ET1qEGwldcF0d5CaFZQUoPUJp3V/WPQhtP8AIn/YgZ8Hr+bS90/sv0zwa50/9P5D+Jdsp/Dxh/+vldD+57zjl8EgQ5AyAdWdox0Xw4MYlniQT/e7ugIISQHg+9/skwmgcUCv198fYI8w1QVeYncQNQiqDaIbNCuEnUJK+ldKtmuPG9jzI2IfPkejIe758tvt4gygnTX98M+h4R+nCvKlP+h0kFV/jn4Gg2SAbBBM93HI08J0T8SzV/bD0/09qQDQAlyGUgRIBZCVAIICejgqlPQGvH7cXYztuLJJU4KfKAXICACYS57MeqNRZ9ilmp/I/qnq7xvvv24BJj6A1P47x1t2MlNoNvxaPOvPYBTJALgoUlX3u2MrGRWAs3iCAiLr50W/21U9ACFSAHUCLbMWQCoDQmUGHLZaB62Xjwfz4821o0aGS3JbiFIAQmg8PH0uW34kA7x65u+Y776Kfj0DSMU/Vv29suPk1L8lV3y/44Z/BqOAAnBa0FVrO9IkQKqA2MWaQOoAyl6AsCD28YMyARIAhy3oFHzdap6M17RCcOMTTQtTG4ATQdFRNvx2n1PPT9Lyp8I//ZJTABj9O5j6m+M+Uv7TeZ93vOaPwfgcBdC0oJ11AdS0oBO7lYenza50/zH6l9gJ2A+XWQroqUQg6EFrgMKBSAo6p9vldTkdGQYPIIYFxcPDEaT9w73hc/iU4z6Z8E/lvxn7SvvHThHoHAqn/gzG//ID36AZYGt7gzzaxUWRFMVjkQnsKxewmSkDhEb4oxQIApABh/LjABqF+mQISgooR5Z8/Dto+6P0p+s+hvG3k+8Bkr9F7b8ZF4c/3Pyzqi4M+7Lxz2B82Q98AhRQW9FVLM/ytHFBWseP3UH7qg0QdgJQEWCZFwD0gTJg0GqREjgUFPCyuxg7EXKAE5V2T7v0+Kvwp/Mefs71TxRARgTIlj9nbX8h/Kcf3vFlXwbjd5oBH6dHLq0O8qx0ZBgKA1AWBMGOmUCzsA/A8AIEAiEDuoMWaQBBAQetl6NgNrHKjj0+CWXmj8FPVT8Z/b4pAVL9n5YCUPv/dY1TjWq+WacCTP0v+bIvg/F78UTtEfY8q2hzkBe70XgRUiZAa0GWORswdQIVBZAheCDiHykAZMD2nGb9Omra53nwSAS+77f9ttH6t5NzACn6Qfuv8QRa0X0Px7Gg7MfzPgzGH8oEXlBZ0NPWh2kc4NhxNDnpAQXINoBMCmBKgAB+BCITGB4mDDA4OGx1u4dK9ovoh2G/hu/XfZ8YINP5m9H/2m+fwqIfp+j8Gc36T2Xqz2Aw/mgm8AEHhtUCUTO5jia7832kANoLlCMBsgJIAZAQ6IXdEdgAByPxMRgMRoOhbPobjZ73ntX9er2ODNAmCjCLgLr2h6/H98u2vt5HX/ENLYx82JvB+P8p4MV7/byoEf/limNVthf9/SYVAMIvKgBFAQF0CLYOhAI4FOHfIfWPj/+jOkKPfz+vALQ/eXp8zym87YM9P5D6f+CGfwbjT1HAG3VRpMBjL1fE+7s1EzKAbMClqQFQAvQyEgDsgHDvQFCAEAAdVABo/NVV+FMGoEwAsw1IKQC/Dfc95KSfdtYP+hdiuefr8j2n/gzGn+UAMANwdVBSC8xwgL2GmsB+WPT8J2UAZIAgpYB+dyAYYNTBYZ9XgXj8GwkDfM4E0LJ/n8Z9yvn4hyZG245qtOeLw5/B+ApmANQEVh5xgKkEPLjY8+Ckt9/s9z9TCkwEQCCTgQAMwb2O0AAi+uHxb6TvP4T/QikAP6cAoEEAyn52supDu+pLSz7d2vSK93wxGF+PAyATmLrynK6RDeCoUHUymzebRRaAmQMEVBREDuj2njVk+Dd0AaAsQD8/AozaP7ILpvzlHBN2/LLvz2B8TQagTMC1y0m8JTyAAwMOdgf1m2GhAOif9ZJiIP1EFPAMAl+Jf00BmB5Aov5B+zuR9s1V/MvXP65OP15y2Y/B+AYU8Pb86qcj3CNs67fF1BcHevqNTMBwAWUC0DuTacBcRb/pAJgJgMTT8b3YSr5j+vjLNQZC+/OOXwbj22UCcE5AXhQpaLqzIxczgTDvAWgUEKQkMK9nJQDG/8Kvt+tGJ+AOhX8lsoo7fuA/p3r0M1/3YjC+KQVAJqBfFMkSgMgEIm97oWUCygMIEg8QWwID/OzPdf2vdQHU27k2gJPjrTiK7SJYNm364PM+DMb3MQOOViLm4qLWey92q5PZWWoIghF4pnGAePq1FMAIfmKAVAGk2r+UPP4F39at/u3qnKf9GIzvwACyQdC1kAMsww4QMsBawXKvsJnOAwPO5KcUASAB0ANoGBQgwt/wAMTjb2P4Z0+XJKiu5G0/jn8G4zvJgMuLo5pMvm3bTAesqGqNRSbQ18qAug+A0X+WVwBoAGiNQFT1u6c4Jo4NCoD74nLUn/9WGIzvnQnUVumZPWMMz6r+9uCk14S9gD2DAgJ0AJUCqH9GAUD0Y8cfZf6WHv/U8Ysbvi+uuOjPYPwADnjy9v3VtJacE8h4criEr4rdQaFWB9QcABAAgUYA/kKNAlIdEJYCwFnvWB4uSwSARQeM4Bu6csM3/2UwGD8AcGX8Ij0nkMnPUROs3NLuaRgaGkA5AGfZFMBXSQB2Atah6geT/mm5X0W+/G41Pu7FYPxoDqBMICEAszqIZcGeoICgl64GIAGgKYCF4QDU6zvH96GqmOn1VaG/4p4fBuP6ZAJ4W1ApgNg0BGO49RcgBUg/QKQAIhGAz7leAJS/hF/NxhM7OeppmwRg4V3v96z9GYxroQJgWrBWJZvOyjGA46zdyczIBKgZKPUA/AW1ACwaDX8mtL9XyQ/7yBTArXHqz2BcLzMAbgvWIlzGYRmmIPQGrOHMeBCqHAA1QJDxAMTDLxKARqN9vCW0fyU5R+IYLb+o/bnnh8G4VokAXRmvVem0qJUbFhAywHowm4chlAGSccC5vghAhH/96XhTRH+l7BUQAGr/2j+435/BuJYUgHtDcH0Y3RjNZgKekAEbu6f9sE+DAJlWYPH418Xjf78stH8FTxF6+XV/UXXK2p/BuM6ZwK8fZWuAbeU4AO4J2GMwBIPgDOsA88T4o8ffVtEvGSCtKTpOhNqfw5/BuPYyoGp58sZwlgQ8mCKcYCYQJPsAFn6j3oYdf56Q/o4W/6n093DHJ5/3YDCuPwfIRcKqXycnA2y38nCBV0NJATTqO+OJ+AcVtWDMeP9pv/+vvOOTwbghqQCeFPmtoB5g2xjhkfVgdio4YA62/2wsMn+v7GWQpP+e4x79m40/BuMmMUDSGgACINscJNeIWqXtk/m8vnM8sS1PXR9XAiD1/yxe8sdg3MRUgDKBFe0PTHWAivIKuAG70O6vlfzSDMDDZCFyacsXhz+DceMoAM+Mi0wgs0JUj/K1G9merbf84eFRxwNSEJn/v2DRB0c/g3FjKUDWBNIxYYx//aHHZYI6QWD0w2W/K170wWDccDdA1gQ0AiDFr4LfXO/nWdL4u2Tjj8G4HZmAkAFwZpyWBHiOV3zUl2oG4t+rHX3klh8G47ZQAN0TqFKTsF1w1EtuEMHNYtbRTzzpz2DcMhmAy8TxrJD3GQKAhj+66s2PP4NxCyngA2QCeFTcHPSl8F/xVW8G49YmArhCcGp5lYr5/kP444ZfePw5/BmM2yoD3uKN4bTVN1beH3b8sfRnMG65DHgLZ4VWMPoj13wJBhCPPxl/TAAMxm1XAdgaIGSA3BqyRuOPfX8G485wAC4Td3HHHzz+vOOPwbhrZsDVxVSAq34Mxt3MBH45/8/5e571YzDuJAP8/ckTEfwc/QwGg8FgMBj/bQ8OCQAAAAAE/X/tChsAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADALzmk1IcMZpJfAAAAAElFTkSuQmCC"

    $reportPath = Join-Path $OutputPath "CIS-M365-Compliance-Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"

    # Capture tenant and user context
    $mgContext = Get-MgContext
    $currentTenantId = if ($mgContext.TenantId) { $mgContext.TenantId } else { "Unknown" }
    $currentUserAccount = if ($mgContext.Account) { $mgContext.Account } else { "Unknown User" }
    $reportDate = Get-Date -Format "MMMM dd, yyyy HH:mm:ss"

    # HTML-encode all dynamic values to prevent XSS
    $safeTenantDomain = Get-HtmlEncoded $TenantDomain
    $safeTenantId = Get-HtmlEncoded $currentTenantId
    $safeUserAccount = Get-HtmlEncoded $currentUserAccount
    $safeReportDate = Get-HtmlEncoded $reportDate

    $passRate = if ($Script:TotalControls -gt 0 -and ($Script:TotalControls - $Script:ManualControls) -gt 0) {
        [math]::Round(($Script:PassedControls / ($Script:TotalControls - $Script:ManualControls)) * 100, 2)
    } else { 0 }

    # Calculate L1 compliance rate
    $l1PassRate = if ($Script:L1TotalControls -gt 0 -and ($Script:L1TotalControls - $Script:L1ManualControls) -gt 0) {
        [math]::Round(($Script:L1PassedControls / ($Script:L1TotalControls - $Script:L1ManualControls)) * 100, 2)
    } else { 0 }

    # Calculate L2 compliance rate
    $l2PassRate = if ($Script:L2TotalControls -gt 0 -and ($Script:L2TotalControls - $Script:L2ManualControls) -gt 0) {
        [math]::Round(($Script:L2PassedControls / ($Script:L2TotalControls - $Script:L2ManualControls)) * 100, 2)
    } else { 0 }

    $html = @"
<!DOCTYPE html>
<html data-theme="dark">
<head>
    <title>CIS Microsoft 365 Compliance Report</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        /* =========================================================
           CSS VARIABLES - THEME DEFINITIONS
           ========================================================= */
        :root {
            /* Status Colors (shared across themes) */
            --color-pass: #4ade80;
            --color-fail: #f87171;
            --color-warning: #fbbf24;
            --color-info: #93c5fd;
            --color-l2: #c4b5fd;
            --color-progress: #22c55e;

            /* Font */
            --font-sans: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;

            /* Transitions */
            --transition-speed: 0.3s;
        }

        /* LIGHT THEME */
        [data-theme="light"] {
            --bg-primary: #f8fafc;
            --bg-secondary: #ffffff;
            --bg-tertiary: #f1f5f9;
            --bg-header: linear-gradient(135deg, #0f172a 0%, #1e3a5f 50%, #1e40af 100%);
            --text-primary: #0f172a;
            --text-secondary: #475569;
            --text-muted: #64748b;
            --text-header: #ffffff;
            --accent: #2563eb;
            --accent-light: #3b82f6;
            --border-color: #e2e8f0;
            --border-subtle: #f1f5f9;
            --shadow-sm: 0 1px 2px rgba(0,0,0,0.04);
            --shadow-md: 0 2px 8px rgba(0,0,0,0.06);
            --shadow-lg: 0 8px 30px rgba(0,0,0,0.08);
            --hover-bg: #f1f5f9;
            --input-bg: #ffffff;
            --input-border: #d1d5db;
            --detail-bg: #f8fafc;
            --detail-border: #e2e8f0;
            --summary-box-bg: #ffffff;
            --summary-box-border: #e2e8f0;
            --tooltip-bg: #0f172a;
            --tooltip-text: #f1f5f9;
            --tooltip-border: #334155;
        }

        /* DARK THEME */
        [data-theme="dark"] {
            --bg-primary: #0a0a0c;
            --bg-secondary: #18181b;
            --bg-tertiary: #27272a;
            --bg-header: #18181b;
            --text-primary: #e4e4e7;
            --text-secondary: #a1a1aa;
            --text-muted: #71717a;
            --text-header: #ffffff;
            --accent: #60a5fa;
            --accent-light: #93c5fd;
            --border-color: #27272a;
            --border-subtle: #2d3548;
            --shadow-sm: 0 1px 2px rgba(0,0,0,0.2);
            --shadow-md: 0 2px 8px rgba(0,0,0,0.3);
            --shadow-lg: 0 4px 12px rgba(0,0,0,0.4);
            --hover-bg: #27272a;
            --input-bg: #27272a;
            --input-border: #3f3f46;
            --detail-bg: #1a1d2e;
            --detail-border: #2d3548;
            --summary-box-bg: #000000;
            --summary-box-border: #ffffff;
            --tooltip-bg: #18181b;
            --tooltip-text: #e4e4e7;
            --tooltip-border: #3f3f46;
        }

        /* =========================================================
           BASE STYLES
           ========================================================= */
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: var(--font-sans);
            background-color: var(--bg-primary);
            color: var(--text-primary);
            padding-top: 0;
            transition: background-color var(--transition-speed) ease, color var(--transition-speed) ease;
        }
        .container { max-width: 1400px; margin: 0 auto; }

        /* Sticky Header */
        .header {
            background: var(--bg-header);
            border-bottom: 3px solid var(--accent);
            position: sticky;
            top: 0;
            z-index: 1000;
            box-shadow: var(--shadow-md);
            transition: background var(--transition-speed) ease, box-shadow var(--transition-speed) ease;
        }
        .header-container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 12px 40px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .header h1 {
            font-size: 1.8em;
            font-weight: 700;
            letter-spacing: -1px;
            margin: 0;
            color: var(--text-header);
        }
        .subtitle {
            font-size: 0.9em;
            opacity: 0.9;
            margin-top: 4px;
            color: var(--text-header);
        }
        .header-right {
            display: flex;
            align-items: center;
            justify-content: flex-end;
            gap: 12px;
            color: var(--text-header);
            position: relative;
        }

        .tenant-info {
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 10px;
            padding: 8px 14px;
            border-radius: 8px;
            border: 1px solid rgba(255, 255, 255, 0.15);
            background: rgba(255, 255, 255, 0.06);
            transition: all 0.25s ease;
        }
        .tenant-info:hover {
            background: rgba(255, 255, 255, 0.12);
            border-color: rgba(255, 255, 255, 0.25);
        }
        .expand-icon {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 20px;
            height: 20px;
            border-radius: 4px;
            background: rgba(255, 255, 255, 0.1);
            font-size: 0.55em;
            transition: all 0.3s ease;
        }
        .expand-icon.expanded {
            transform: rotate(180deg);
            background: rgba(255, 255, 255, 0.2);
        }
        .header-details-box {
            display: none;
            position: absolute;
            top: calc(100% + 10px);
            right: 0;
            width: 320px;
            background: var(--detail-bg);
            border: 1px solid var(--detail-border);
            border-radius: 6px;
            padding: 8px 12px;
            animation: slideDown 0.3s ease;
            box-shadow: var(--shadow-lg);
            z-index: 1001;
            transition: background var(--transition-speed) ease, border-color var(--transition-speed) ease;
        }
        .header-details-box.expanded {
            display: block;
        }
        @keyframes slideDown {
            from {
                opacity: 0;
                transform: translateY(-10px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        .detail-item {
            margin-bottom: 6px;
            padding-bottom: 6px;
            border-bottom: 1px solid var(--detail-border);
        }
        .detail-item:last-child {
            margin-bottom: 0;
            padding-bottom: 0;
            border-bottom: none;
        }
        .detail-label {
            font-size: 0.8em;
            color: var(--text-header);
            font-weight: 600;
            margin-bottom: 2px;
        }
        .detail-value {
            font-size: 0.75em;
            color: var(--text-secondary);
        }
        [data-theme="dark"] .detail-value { color: #9ca3af; }

        /* Theme Toggle */
        .theme-toggle {
            position: relative;
            width: 56px;
            height: 30px;
            background: rgba(255,255,255,0.12);
            border: 1px solid rgba(255,255,255,0.18);
            border-radius: 15px;
            cursor: pointer;
            transition: all 0.3s ease;
            outline: none;
            padding: 0;
            flex-shrink: 0;
        }
        .theme-toggle:hover {
            background: rgba(255,255,255,0.18);
        }
        .theme-toggle .toggle-thumb {
            position: absolute;
            top: 3px;
            left: 3px;
            width: 22px;
            height: 22px;
            border-radius: 50%;
            background: #ffffff;
            transition: all 0.3s cubic-bezier(0.68, -0.55, 0.265, 1.55);
            display: flex;
            align-items: center;
            justify-content: center;
        }
        [data-theme="dark"] .theme-toggle .toggle-thumb {
            left: 29px;
            background: #334155;
        }
        .toggle-thumb::before {
            content: '';
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: #f59e0b;
            transition: all 0.3s ease;
        }
        [data-theme="dark"] .toggle-thumb::before {
            width: 10px;
            height: 10px;
            background: transparent;
            border-radius: 50%;
            box-shadow: inset -4px -2px 0 0 #fbbf24;
        }
        .toggle-thumb::after {
            content: '';
            position: absolute;
            width: 18px;
            height: 18px;
            border-radius: 50%;
            border: 2px dashed rgba(245,158,11,0.4);
            transition: all 0.3s ease;
        }
        [data-theme="dark"] .toggle-thumb::after {
            border-color: transparent;
            width: 0;
            height: 0;
        }

        /* Content */
        .content {
            padding: 10px 40px 20px 40px;
            transition: background-color var(--transition-speed) ease;
        }
        h2 { color: var(--text-primary); margin-top: 30px; margin-bottom: 15px; transition: color var(--transition-speed) ease; }
        h2:first-child { margin-top: 0; margin-bottom: 10px; }

        .summary {
            background: var(--bg-secondary);
            padding: 12px 15px;
            border-radius: 8px;
            margin-bottom: 25px;
            border: 1px solid var(--border-color);
            transition: background var(--transition-speed) ease, border-color var(--transition-speed) ease;
        }

        .summary-box {
            display: inline-block;
            margin: 8px 15px 8px 0;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            transition: all 0.3s ease;
            background-color: var(--summary-box-bg);
            border: 2px solid var(--summary-box-border);
        }
        .summary-box:hover {
            transform: translateY(-2px);
            box-shadow: 0 0 8px rgba(96, 165, 250, 0.5);
        }
        .summary-box.active {
            box-shadow: 0 0 12px rgba(96, 165, 250, 0.8);
            border: 2px solid var(--accent) !important;
        }
        .pass { color: var(--color-pass); }
        .fail { color: var(--color-fail); }
        .manual { color: var(--color-warning); }
        .error { color: var(--color-fail); }
        .level-l1 { color: var(--color-info); }
        .level-l2 { color: var(--color-l2); }

        .progress-bar {
            width: 100%; height: 30px;
            background-color: var(--bg-tertiary);
            border-radius: 5px; overflow: hidden; margin: 15px 0;
            transition: background-color var(--transition-speed) ease;
        }
        .progress-fill { height: 100%; background-color: var(--color-progress); text-align: center; line-height: 30px; color: white; font-weight: bold; }

        /* Search Box */
        .search-container {
            position: relative;
            margin: 20px 0;
            max-width: 100%;
        }
        #searchBox {
            width: 100%;
            padding: 15px 50px 15px 20px;
            font-size: 16px;
            background-color: var(--input-bg);
            border: 2px solid var(--input-border);
            border-radius: 8px;
            color: var(--text-primary);
            transition: all 0.3s ease;
            outline: none;
        }
        #searchBox:focus {
            border-color: var(--accent);
            box-shadow: 0 0 10px rgba(96, 165, 250, 0.3);
        }
        #searchBox::placeholder {
            color: var(--text-muted);
        }
        .search-icon {
            position: absolute;
            right: 20px;
            top: 50%;
            transform: translateY(-50%);
            font-size: 20px;
            pointer-events: none;
            color: var(--text-muted);
        }
        .search-results {
            display: block;
            margin-top: 8px;
            font-size: 14px;
            color: var(--text-secondary);
        }

        table {
            width: 100%; border-collapse: collapse;
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            margin-top: 20px;
            transition: background var(--transition-speed) ease, border-color var(--transition-speed) ease;
        }
        th {
            background-color: var(--bg-secondary);
            color: var(--text-primary);
            padding: 12px; text-align: left; font-weight: 600;
            border-bottom: 2px solid var(--accent);
            transition: background-color var(--transition-speed) ease, color var(--transition-speed) ease;
        }
        td {
            padding: 12px;
            border-bottom: 1px solid var(--border-color);
            transition: border-color var(--transition-speed) ease;
        }
        tr:hover { background-color: var(--hover-bg); }
        .status-pass { color: var(--color-pass); font-weight: bold; }
        .status-fail { color: var(--color-fail); font-weight: bold; }
        .status-manual { color: var(--color-warning); font-weight: bold; }
        .status-error { color: var(--color-fail); font-weight: bold; }
        .details { font-size: 0.9em; color: var(--text-secondary); }
        .remediation { font-size: 0.85em; color: var(--accent); font-style: italic; margin-top: 5px; }

        /* Floating Action Buttons (Right Side) */
        .floating-actions {
            position: fixed;
            right: 20px;
            top: 50%;
            transform: translateY(-50%);
            display: flex;
            flex-direction: column;
            gap: 12px;
            z-index: 1000;
        }
        .action-btn {
            width: 56px;
            height: 56px;
            border-radius: 50%;
            background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%);
            border: 2px solid var(--accent);
            display: flex;
            align-items: center;
            justify-content: center;
            text-decoration: none;
            font-size: 20px;
            font-weight: bold;
            color: white;
            transition: all 0.3s ease;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
            position: relative;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        }
        .action-btn:hover {
            transform: scale(1.1);
            box-shadow: 0 8px 20px rgba(96, 165, 250, 0.4);
            border-color: var(--accent-light);
        }
        .action-btn::before {
            content: attr(data-tooltip);
            position: absolute;
            right: 70px;
            background: var(--tooltip-bg);
            color: var(--tooltip-text);
            padding: 8px 12px;
            border-radius: 6px;
            font-size: 14px;
            white-space: nowrap;
            opacity: 0;
            pointer-events: none;
            transition: opacity 0.3s ease;
            border: 1px solid var(--tooltip-border);
            box-shadow: var(--shadow-lg);
        }
        .action-btn:hover::before {
            opacity: 1;
        }

        /* Footer */
        .footer {
            background: var(--bg-secondary);
            color: var(--text-secondary);
            padding: 10px 40px;
            text-align: center;
            border-top: 1px solid var(--border-color);
            margin-top: 40px;
            font-size: 0.9em;
            transition: background var(--transition-speed) ease, color var(--transition-speed) ease, border-color var(--transition-speed) ease;
        }
        .footer p { margin: 0; }
        .footer a { color: var(--accent); text-decoration: none; }
        .footer a:hover { text-decoration: underline; }

        /* Hidden class for filtering */
        .hidden { display: none !important; }

        /* Print styles - force light theme */
        @media print {
            * { transition: none !important; animation: none !important; }
            html, body { background: #ffffff !important; color: #0f172a !important; }
            [data-theme="dark"] {
                --bg-primary: #ffffff; --bg-secondary: #ffffff; --bg-tertiary: #f8fafc;
                --text-primary: #0f172a; --text-secondary: #475569; --text-muted: #64748b;
                --border-color: #e2e8f0; --detail-bg: #f8fafc; --detail-border: #e2e8f0;
                --input-bg: #ffffff; --hover-bg: #f1f5f9;
            }
            .theme-toggle, .floating-actions { display: none !important; }
        }
    </style>
</head>
<body>
    <!-- Header -->
    <div class="header">
        <div class="header-container">
            <div class="header-left" style="display:flex;align-items:center;">
                <img src="data:image/png;base64,$logoBase64" alt="PowerShellNerd" style="height:40px;margin-right:12px;">
                <h1>CIS MICROSOFT 365 FOUNDATIONS BENCHMARK v6.0.0</h1>
            </div>
            <div class="header-right">
                <button class="theme-toggle" id="themeToggle" title="Toggle dark/light mode" aria-label="Toggle theme">
                    <span class="toggle-thumb"></span>
                </button>
                <div class="tenant-info" id="tenantInfo" onclick="toggleHeaderDetails()">
                    <span class="subtitle">$safeTenantDomain</span>
                    <span class="expand-icon" id="expandIcon"><svg width="10" height="10" viewBox="0 0 10 10" fill="none"><path d="M2 3.5L5 6.5L8 3.5" stroke="white" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg></span>
                </div>
                <div class="header-details-box" id="headerDetailsBox">
                    <div class="detail-item">
                        <div class="detail-label">Tenant</div>
                        <div class="detail-value">$safeTenantDomain</div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">Tenant ID</div>
                        <div class="detail-value">$safeTenantId</div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">Assessment generated by</div>
                        <div class="detail-value">$safeUserAccount</div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">Assessment run on</div>
                        <div class="detail-value">$safeReportDate</div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">Version</div>
                        <div class="detail-value">CIS Benchmark v6.0.0</div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">Compliance Rate</div>
                        <div class="detail-value">$passRate%</div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="container">

        <!-- Content -->
        <div class="content">

    <div class="summary">
        <h2>Executive Summary</h2>
        <div class="progress-bar">
            <div class="progress-fill" style="width: $passRate%">$passRate% Compliant</div>
        </div>
        <br/>
        <div class="summary-box pass" data-filter="pass" onclick="filterResults(this)">
            <strong>Passed:</strong> $Script:PassedControls
        </div>
        <div class="summary-box fail" data-filter="fail" onclick="filterResults(this)">
            <strong>Failed:</strong> $Script:FailedControls
        </div>
        <div class="summary-box manual" data-filter="manual" onclick="filterResults(this)">
            <strong>Manual:</strong> $Script:ManualControls
        </div>
        <div class="summary-box error" data-filter="error" onclick="filterResults(this)">
            <strong>Errors:</strong> $Script:ErrorControls
        </div>
        <div class="summary-box" data-filter="all" onclick="filterResults(this)">
            <strong>Total Controls:</strong> $Script:TotalControls
        </div>
        <div class="summary-box level-l1" data-filter="L1" onclick="filterResults(this)">
            <strong>L1 Checks:</strong> $Script:L1PassedControls / $Script:L1TotalControls ($l1PassRate%)
        </div>
        <div class="summary-box level-l2" data-filter="L2" onclick="filterResults(this)">
            <strong>L2 Checks:</strong> $Script:L2PassedControls / $Script:L2TotalControls ($l2PassRate%)
        </div>
    </div>

    <!-- Search Box -->
    <div class="search-container">
        <input type="text" id="searchBox" placeholder="Search by control number, title, level (L1/L2), or status (Pass/Fail/Manual)..." onkeyup="searchTable()">
        <span class="search-icon">&#128269;</span>
        <span id="searchResults" class="search-results"></span>
    </div>

    <h2>Detailed Results</h2>

    <table id="resultsTable">
        <thead>
            <tr>
                <th>Control</th>
                <th>Title</th>
                <th>Level</th>
                <th>Result</th>
                <th>Details</th>
            </tr>
        </thead>
        <tbody>
"@

    foreach ($result in $Script:Results | Sort-Object { ($_.ControlNumber -split '\.' | ForEach-Object { $_.PadLeft(4, '0') }) -join '.' }) {
        $statusClass = "status-" + $result.Result.ToLower()
        $resultLower = $result.Result.ToLower()
        $levelValue = $result.ProfileLevel
        $safeControlNumber = Get-HtmlEncoded $result.ControlNumber
        $safeControlTitle = Get-HtmlEncoded $result.ControlTitle
        $safeDetails = Get-HtmlEncoded $result.Details
        $safeRemediation = Get-HtmlEncoded $result.Remediation
        $safeResult = Get-HtmlEncoded $result.Result
        $safeLevel = Get-HtmlEncoded $result.ProfileLevel
        $html += @"
            <tr data-result="$resultLower" data-level="$levelValue">
                <td><strong>$safeControlNumber</strong></td>
                <td>$safeControlTitle</td>
                <td>$safeLevel</td>
                <td class="$statusClass">$safeResult</td>
                <td>
                    <div class="details">$safeDetails</div>
"@
        if ($result.Remediation -and $result.Result -eq "Fail") {
            $html += "                    <div class='remediation'>Remediation: $safeRemediation</div>`n"
        }
        $html += "                </td>`n            </tr>`n"
    }

    $html += @"
        </tbody>
    </table>
        </div>

        <!-- Floating Action Buttons -->
        <div class="floating-actions">
            <a href="https://powershellnerd.com" target="_blank" class="action-btn" data-tooltip="PowerShellNerd">
                <img src="data:image/png;base64,$logoBase64" alt="PowerShellNerd" style="width:32px;height:32px;border-radius:50%;object-fit:cover;">
            </a>
            <a href="https://github.com/mohammedsiddiqui6872/CIS-Microsoft-365-Foundations-Benchmark" target="_blank" class="action-btn" data-tooltip="View on GitHub">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="white"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
            </a>
            <a href="https://www.linkedin.com/in/mohammedsiddiqui6872/" target="_blank" class="action-btn" data-tooltip="Let's Chat!">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="white"><path d="M19 0h-14c-2.761 0-5 2.239-5 5v14c0 2.761 2.239 5 5 5h14c2.762 0 5-2.239 5-5v-14c0-2.761-2.238-5-5-5zm-11 19h-3v-11h3v11zm-1.5-12.268c-.966 0-1.75-.79-1.75-1.764s.784-1.764 1.75-1.764 1.75.79 1.75 1.764-.783 1.764-1.75 1.764zm13.5 12.268h-3v-5.604c0-3.368-4-3.113-4 0v5.604h-3v-11h3v1.765c1.396-2.586 7-2.777 7 2.476v6.759z"/></svg>
            </a>
        </div>

        <!-- Footer -->
        <div class="footer">
            <p><strong>CIS Microsoft 365 Foundations Benchmark v6.0.0</strong> | Generated $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") | $Script:TotalControls controls | Run by: $safeUserAccount</p>
        </div>
    </div>

    <script>
        /* ===========================================================
           THEME TOGGLE
           =========================================================== */
        var themeToggle = document.getElementById('themeToggle');
        var savedTheme = null;
        try { savedTheme = localStorage.getItem('cis-report-theme'); } catch(e) {}
        if (savedTheme) {
            document.documentElement.setAttribute('data-theme', savedTheme);
        }

        themeToggle.addEventListener('click', function() {
            var current = document.documentElement.getAttribute('data-theme');
            var next = current === 'dark' ? 'light' : 'dark';
            document.documentElement.setAttribute('data-theme', next);
            try { localStorage.setItem('cis-report-theme', next); } catch(e) {}
        });

        /* ===========================================================
           HEADER & FILTERING
           =========================================================== */
        let activeFilter = null;

        function toggleHeaderDetails() {
            const detailsBox = document.getElementById('headerDetailsBox');
            const icon = document.getElementById('expandIcon');
            if (detailsBox && icon) {
                detailsBox.classList.toggle('expanded');
                icon.classList.toggle('expanded');
            }
        }

        function filterResults(box) {
            if (!box) return;

            const filterValue = box.getAttribute('data-filter');
            if (!filterValue) return;

            const allRows = document.querySelectorAll('tbody tr');
            const allBoxes = document.querySelectorAll('.summary-box');

            // Clear search box when using filter buttons
            document.getElementById('searchBox').value = '';
            document.getElementById('searchResults').textContent = '';

            // Toggle filter - if same box clicked, clear filter
            if (activeFilter === filterValue) {
                // Clear filter - show all
                allRows.forEach(row => row.classList.remove('hidden'));
                allBoxes.forEach(b => b.classList.remove('active'));
                activeFilter = null;
            } else {
                // Apply new filter
                activeFilter = filterValue;
                allBoxes.forEach(b => b.classList.remove('active'));
                box.classList.add('active');

                if (filterValue === 'all') {
                    // Show all rows
                    allRows.forEach(row => row.classList.remove('hidden'));
                } else {
                    // Filter by result type or level
                    allRows.forEach(row => {
                        const rowResult = row.getAttribute('data-result');
                        const rowLevel = row.getAttribute('data-level');
                        if (rowResult === filterValue || rowLevel === filterValue) {
                            row.classList.remove('hidden');
                        } else {
                            row.classList.add('hidden');
                        }
                    });
                }
            }
        }

        function searchTable() {
            // Clear any active filter when searching
            const allBoxes = document.querySelectorAll('.summary-box');
            allBoxes.forEach(b => b.classList.remove('active'));
            activeFilter = null;

            const searchInput = document.getElementById('searchBox');
            const filter = searchInput.value.toLowerCase().trim();
            const table = document.getElementById('resultsTable');
            const tbody = table.getElementsByTagName('tbody')[0];
            const rows = tbody.getElementsByTagName('tr');
            let visibleCount = 0;
            let totalCount = rows.length;

            // If search is empty, show all rows
            if (filter === '') {
                for (let i = 0; i < rows.length; i++) {
                    rows[i].classList.remove('hidden');
                }
                document.getElementById('searchResults').textContent = '';
                return;
            }

            // Search through all rows
            for (let i = 0; i < rows.length; i++) {
                const row = rows[i];
                const cells = row.getElementsByTagName('td');

                if (cells.length > 0) {
                    const controlNumber = cells[0].textContent.toLowerCase();
                    const title = cells[1].textContent.toLowerCase();
                    const level = cells[2].textContent.toLowerCase();
                    const result = cells[3].textContent.toLowerCase();
                    const details = cells[4].textContent.toLowerCase();

                    // Check if any cell contains the search term
                    if (controlNumber.includes(filter) ||
                        title.includes(filter) ||
                        level.includes(filter) ||
                        result.includes(filter) ||
                        details.includes(filter)) {
                        row.classList.remove('hidden');
                        visibleCount++;
                    } else {
                        row.classList.add('hidden');
                    }
                }
            }

            // Update search results counter
            const resultsText = visibleCount === 1
                ? 'Found 1 result out of ' + totalCount + ' controls'
                : 'Found ' + visibleCount + ' results out of ' + totalCount + ' controls';
            document.getElementById('searchResults').textContent = resultsText;
        }
    </script>
</body>
</html>
"@

    $html | Out-File -FilePath $reportPath -Encoding UTF8
    Write-Log "HTML report saved to: $reportPath" -Level Success
    return $reportPath
}

function Export-CsvReport {
    param([string]$OutputPath)

    $csvPath = Join-Path $OutputPath "CIS-M365-Compliance-Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $Script:Results | Sort-Object { ($_.ControlNumber -split '\.' | ForEach-Object { $_.PadLeft(4, '0') }) -join '.' } | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Log "CSV report saved to: $csvPath" -Level Success
    return $csvPath
}

#endregion

#region Main Execution

function Start-ComplianceCheck {
    # Reset all script-scope variables to prevent state leaking from previous runs
    $Script:Results = [System.Collections.Generic.List[PSCustomObject]]::new()
    $Script:TotalControls = 0
    $Script:PassedControls = 0
    $Script:FailedControls = 0
    $Script:ManualControls = 0
    $Script:ErrorControls = 0
    $Script:L1TotalControls = 0
    $Script:L1PassedControls = 0
    $Script:L1FailedControls = 0
    $Script:L1ManualControls = 0
    $Script:L1ErrorControls = 0
    $Script:L2TotalControls = 0
    $Script:L2PassedControls = 0
    $Script:L2FailedControls = 0
    $Script:L2ManualControls = 0
    $Script:L2ErrorControls = 0

    # Initialize file-based audit log
    $logTimestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $Script:LogFilePath = Join-Path -Path $OutputPath -ChildPath "CIS-M365-Audit_$logTimestamp.log"
    try {
        $null = New-Item -Path $Script:LogFilePath -ItemType File -Force
    }
    catch {
        Write-Warning "Could not create log file at $($Script:LogFilePath). File logging disabled."
        $Script:LogFilePath = $null
    }

    Write-Host "`n"
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "  CIS Microsoft 365 Foundations Benchmark v6.0.0" -ForegroundColor Cyan
    Write-Host "  Compliance Checker" -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "`n"

    # Check required modules
    Write-Log "Checking required PowerShell modules..." -Level Info
    $requiredModules = @(
        "Microsoft.Graph",
        "ExchangeOnlineManagement",
        "Microsoft.Online.SharePoint.PowerShell",
        "MicrosoftTeams"
    )

    $missingModules = @()
    foreach ($module in $requiredModules) {
        if (-not (Test-ModuleInstalled $module)) {
            $missingModules += $module
            Write-Log "Missing module: $module" -Level Warning
        }
    }

    if ($missingModules.Count -gt 0) {
        Write-Log "The following modules are missing:" -Level Error
        $missingModules | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
        Write-Host "`nPlease install missing modules using:" -ForegroundColor Yellow
        Write-Host "Install-Module <ModuleName> -Scope CurrentUser" -ForegroundColor Yellow
        return
    }

    Write-Log "All required modules are installed" -Level Success

    # Connect to services
    if (-not (Connect-M365Services)) {
        Write-Log "Failed to connect to Microsoft 365 services. Exiting." -Level Error
        return
    }

    Write-Host "`n"
    Write-Log "Starting CIS compliance checks..." -Level Info
    Write-Host "`n"

    # Run all checks with progress tracking
    $sections = @(
        @{ Key = "AdminCenter"; Name = "Microsoft 365 Admin Center"; Function = { Test-M365AdminCenter } }
        @{ Key = "Defender";    Name = "Microsoft 365 Defender";     Function = { Test-M365Defender } }
        @{ Key = "Purview";     Name = "Microsoft Purview";          Function = { Test-Purview } }
        @{ Key = "Intune";      Name = "Microsoft Intune";           Function = { Test-Intune } }
        @{ Key = "EntraID";     Name = "Microsoft Entra ID";         Function = { Test-EntraID } }
        @{ Key = "Exchange";    Name = "Exchange Online";            Function = { Test-ExchangeOnline } }
        @{ Key = "SharePoint";  Name = "SharePoint Online";          Function = { Test-SharePointOnline } }
        @{ Key = "Teams";       Name = "Microsoft Teams";            Function = { Test-MicrosoftTeams } }
        @{ Key = "PowerBI";     Name = "Power BI";                   Function = { Test-PowerBI } }
    )

    # Filter out excluded sections
    if ($ExcludeSections.Count -gt 0) {
        $excludedNames = ($sections | Where-Object { $_.Key -in $ExcludeSections } | ForEach-Object { $_.Name }) -join ', '
        Write-Log "Excluding sections: $excludedNames" -Level Warning
        $sections = @($sections | Where-Object { $_.Key -notin $ExcludeSections })
    }

    $totalSections = $sections.Count
    $currentSection = 0

    foreach ($section in $sections) {
        $currentSection++
        $percentComplete = [math]::Round(($currentSection / $totalSections) * 100, 1)

        Write-Progress -Activity "Running CIS Benchmark Compliance Checks" `
            -Status "Processing Section $currentSection of $totalSections - $($section.Name) - $percentComplete% complete" `
            -PercentComplete $percentComplete

        & $section.Function
    }

    Write-Progress -Activity "Running CIS Benchmark Compliance Checks" -Completed

    # Generate reports
    Write-Host "`n"
    Write-Log "Generating reports..." -Level Info
    $htmlReport = Export-HtmlReport -OutputPath $OutputPath
    $csvReport = Export-CsvReport -OutputPath $OutputPath

    # Summary
    Write-Host "`n"
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "  Compliance Check Complete" -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "`n"
    Write-Host "Total Controls Checked: " -NoNewline
    Write-Host $Script:TotalControls -ForegroundColor White
    Write-Host "Passed: " -NoNewline -ForegroundColor Green
    Write-Host $Script:PassedControls -ForegroundColor Green
    Write-Host "Failed: " -NoNewline -ForegroundColor Red
    Write-Host $Script:FailedControls -ForegroundColor Red
    Write-Host "Manual Review Required: " -NoNewline -ForegroundColor Yellow
    Write-Host $Script:ManualControls -ForegroundColor Yellow
    Write-Host "Errors: " -NoNewline -ForegroundColor Red
    Write-Host $Script:ErrorControls -ForegroundColor Red

    if ($Script:TotalControls -gt $Script:ManualControls) {
        $complianceRate = [math]::Round(($Script:PassedControls / ($Script:TotalControls - $Script:ManualControls)) * 100, 2)
        Write-Host "`nAutomated Compliance Rate: " -NoNewline
        Write-Host "$complianceRate%" -ForegroundColor Cyan
    }

    # Display L1 and L2 statistics
    Write-Host "`n--- Profile Level Statistics ---" -ForegroundColor Cyan
    if ($Script:L1TotalControls -gt 0) {
        $l1Rate = if (($Script:L1TotalControls - $Script:L1ManualControls) -gt 0) {
            [math]::Round(($Script:L1PassedControls / ($Script:L1TotalControls - $Script:L1ManualControls)) * 100, 2)
        } else { 0 }
        Write-Host "L1 Controls: " -NoNewline -ForegroundColor Blue
        Write-Host "$Script:L1PassedControls passed / $Script:L1TotalControls total ($l1Rate%)" -ForegroundColor White
    }
    if ($Script:L2TotalControls -gt 0) {
        $l2Rate = if (($Script:L2TotalControls - $Script:L2ManualControls) -gt 0) {
            [math]::Round(($Script:L2PassedControls / ($Script:L2TotalControls - $Script:L2ManualControls)) * 100, 2)
        } else { 0 }
        Write-Host "L2 Controls: " -NoNewline -ForegroundColor Magenta
        Write-Host "$Script:L2PassedControls passed / $Script:L2TotalControls total ($l2Rate%)" -ForegroundColor White
    }

    # Log final summary to audit log
    Write-Log "Compliance check complete - Total: $($Script:TotalControls), Pass: $($Script:PassedControls), Fail: $($Script:FailedControls), Manual: $($Script:ManualControls), Error: $($Script:ErrorControls)" -Level Info

    Write-Host "`n"
    Write-Host "Reports saved to:" -ForegroundColor Cyan
    Write-Host "  HTML: $htmlReport" -ForegroundColor White
    Write-Host "  CSV:  $csvReport" -ForegroundColor White
    if ($Script:LogFilePath) {
        Write-Host "  Log:  $($Script:LogFilePath)" -ForegroundColor White
    }
    Write-Host "`n"

    # Disconnect and clean up environment state
    Write-Log "Disconnecting from services..." -Level Info
    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
        Disconnect-SPOService -ErrorAction SilentlyContinue | Out-Null
        Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue | Out-Null
    }
    catch {
        # Ignore disconnect errors
    }
    finally {
        # Clean up environment variables to prevent state leaking across sessions
        if ($env:CIS_USE_DEVICE_CODE) { Remove-Item Env:\CIS_USE_DEVICE_CODE -ErrorAction SilentlyContinue }
        if ($env:AZURE_IDENTITY_DISABLE_MULTITENANTAUTH) { Remove-Item Env:\AZURE_IDENTITY_DISABLE_MULTITENANTAUTH -ErrorAction SilentlyContinue }
    }

    Write-Log "Done!" -Level Success
}

# Only run the compliance check if script is executed directly (not dot-sourced by module)
if ($MyInvocation.InvocationName -ne '.' -and $MyInvocation.InvocationName -notlike '*psm1') {
    # Script was called directly, not imported as a module
    Start-ComplianceCheck
}

#endregion
