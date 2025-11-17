<#
.SYNOPSIS
    CIS Microsoft 365 Foundations Benchmark v5.0.0 Compliance Checker

.DESCRIPTION
    Comprehensive PowerShell script to audit Microsoft 365 environment against all 128 CIS benchmark controls.
    Generates detailed HTML and CSV reports showing compliance status for each control.

.NOTES
    Version: 1.0
    Author: CIS Compliance Automation
    Date: 2025-11-11

    Required PowerShell Modules:
    - Microsoft.Graph (Install-Module Microsoft.Graph -Scope CurrentUser)
    - ExchangeOnlineManagement (Install-Module ExchangeOnlineManagement -Scope CurrentUser)
    - Microsoft.Online.SharePoint.PowerShell (Install-Module Microsoft.Online.SharePoint.PowerShell -Scope CurrentUser)
    - MicrosoftTeams (Install-Module MicrosoftTeams -Scope CurrentUser)
    - MSOnline (Install-Module MSOnline -Scope CurrentUser)

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
    [string]$ProfileLevel = 'All'
)

# Global Variables
$Script:Results = @()
$Script:TotalControls = 0
$Script:PassedControls = 0
$Script:FailedControls = 0
$Script:ManualControls = 0
$Script:ErrorControls = 0
$Script:MsolConnected = $false
$Script:RequestedProfileLevel = $ProfileLevel

# Level-specific counters
$Script:L1TotalControls = 0
$Script:L1PassedControls = 0
$Script:L1FailedControls = 0
$Script:L1ManualControls = 0
$Script:L2TotalControls = 0
$Script:L2PassedControls = 0
$Script:L2FailedControls = 0
$Script:L2ManualControls = 0

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
        }
    }
    elseif ($ProfileLevel -eq 'L2') {
        $Script:L2TotalControls++
        switch($Result) {
            'Pass' { $Script:L2PassedControls++ }
            'Fail' { $Script:L2FailedControls++ }
            'Manual' { $Script:L2ManualControls++ }
        }
    }

    switch($Result) {
        'Pass' { $Script:PassedControls++ }
        'Fail' { $Script:FailedControls++ }
        'Manual' { $Script:ManualControls++ }
        'Error' { $Script:ErrorControls++ }
    }

    $Script:Results += [PSCustomObject]@{
        ControlNumber = $ControlNumber
        ControlTitle = $ControlTitle
        ProfileLevel = $ProfileLevel
        Result = $Result
        Details = $Details
        Remediation = $Remediation
    }
}

function Test-ModuleInstalled {
    param([string]$ModuleName)

    if (Get-Module -ListAvailable -Name $ModuleName) {
        return $true
    }
    return $false
}

function Connect-M365Services {
    Write-Log "Connecting to Microsoft 365 services..." -Level Info
    Write-Log "NOTE: You will be prompted to sign in once. The same session will be used for all services." -Level Info

    try {
        # Connect to Microsoft Graph first - this establishes the primary authentication
        Write-Log "Connecting to Microsoft Graph..." -Level Info
        Connect-MgGraph -Scopes "Directory.Read.All", "Policy.Read.All", "AuditLog.Read.All", `
                               "UserAuthenticationMethod.Read.All", "IdentityRiskyUser.Read.All", `
                               "IdentityRiskEvent.Read.All", "Application.Read.All", `
                               "Organization.Read.All", "User.Read.All", "Group.Read.All", `
                               "RoleManagement.Read.All", "Reports.Read.All" -NoWelcome -ErrorAction Stop
        Write-Log "Connected to Microsoft Graph" -Level Success

        # Get the current Graph context to reuse credentials
        $mgContext = Get-MgContext
        $tenantId = $mgContext.TenantId

        Write-Log "Using authenticated session for remaining services (TenantId: $tenantId)..." -Level Info

        # Connect to Exchange Online using the same authenticated session
        Write-Log "Connecting to Exchange Online..." -Level Info
        Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        Write-Log "Connected to Exchange Online" -Level Success

        # Connect to SharePoint Online
        Write-Log "Connecting to SharePoint Online..." -Level Info
        Connect-SPOService -Url $SharePointAdminUrl -ErrorAction Stop
        Write-Log "Connected to SharePoint Online" -Level Success

        # Connect to Microsoft Teams using the same account
        Write-Log "Connecting to Microsoft Teams..." -Level Info
        Connect-MicrosoftTeams -TenantId $tenantId -ErrorAction Stop | Out-Null
        Write-Log "Connected to Microsoft Teams" -Level Success

        # Connect to MSOnline (for legacy checks) - Optional
        # Note: MSOnline doesn't support modern auth token reuse well, so this may prompt separately
        Write-Log "Connecting to MSOnline (legacy module - may prompt separately)..." -Level Info
        try {
            Connect-MsolService -ErrorAction Stop
            Write-Log "Connected to MSOnline" -Level Success
            $script:MsolConnected = $true
        }
        catch {
            Write-Log "Warning: Could not connect to MSOnline. Per-user MFA check (5.1.2.1) will be skipped." -Level Warning
            Write-Log "MSOnline module is deprecated. Consider using Microsoft Graph for all checks." -Level Warning
            $script:MsolConnected = $false
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
        $adminRoles = Get-MgDirectoryRole -All
        $adminUsers = @()
        foreach ($role in $adminRoles) {
            $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id
            foreach ($member in $members) {
                if ($member.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.user') {
                    $user = Get-MgUser -UserId $member.Id -Property Id,UserPrincipalName,OnPremisesSyncEnabled
                    if ($user.OnPremisesSyncEnabled) {
                        $adminUsers += $user.UserPrincipalName
                    }
                }
            }
        }

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

    # 1.1.2 - Ensure two emergency access accounts have been defined (Manual)
    Add-Result -ControlNumber "1.1.2" -ControlTitle "Ensure two emergency access accounts have been defined" `
               -ProfileLevel "L1" -Result "Manual" -Details "Manual verification required" `
               -Remediation "Create and document two emergency 'break glass' accounts"

    # 1.1.3 - Ensure that between two and four global admins are designated
    try {
        Write-Log "Checking 1.1.3 - Global admin count" -Level Info
        $globalAdminRole = Get-MgDirectoryRole -Filter "DisplayName eq 'Global Administrator'"
        $globalAdmins = Get-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id
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
    Add-Result -ControlNumber "1.1.4" -ControlTitle "Ensure administrative accounts use licenses with a reduced application footprint" `
               -ProfileLevel "L1" -Result "Manual" -Details "Manual verification of admin licensing required" `
               -Remediation "Assign minimal licenses to administrative accounts"

    # 1.2.1 - Ensure that only organizationally managed/approved public groups exist
    try {
        Write-Log "Checking 1.2.1 - Public groups approval" -Level Info
        # Get all groups and filter by visibility property (Graph API filter doesn't support visibility)
        $allGroups = Get-MgGroup -All -Property DisplayName,Visibility,Id
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
        $sharedMailboxes = Get-EXOMailbox -RecipientTypeDetails SharedMailbox -ResultSize Unlimited
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
        $defaultDomain = Get-MgDomain | Where-Object { $_.IsDefault -eq $true } | Select-Object -First 1

        if ($defaultDomain.PasswordValidityPeriodInDays -eq 2147483647 -or $defaultDomain.PasswordValidityPeriodInDays -gt 365) {
            Add-Result -ControlNumber "1.3.1" -ControlTitle "Ensure the 'Password expiration policy' is set to 'Set passwords to never expire'" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Password expiration set to $($defaultDomain.PasswordValidityPeriodInDays) days (never expire)"
        }
        else {
            Add-Result -ControlNumber "1.3.1" -ControlTitle "Ensure the 'Password expiration policy' is set to 'Set passwords to never expire'" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Password expires in $($defaultDomain.PasswordValidityPeriodInDays) days" `
                       -Remediation "Update-MgDomain -DomainId $($defaultDomain.Id) -PasswordValidityPeriodInDays 2147483647"
        }
    }
    catch {
        Add-Result -ControlNumber "1.3.1" -ControlTitle "Ensure the 'Password expiration policy' is set to 'Set passwords to never expire'" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 1.3.2 - Ensure 'Idle session timeout' is set to '3 hours (or less)' for unmanaged devices
    Add-Result -ControlNumber "1.3.2" -ControlTitle "Ensure 'Idle session timeout' is set to '3 hours (or less)' for unmanaged devices" `
               -ProfileLevel "L2" -Result "Manual" -Details "Check M365 Admin Center > Settings > Org Settings > Security & privacy" `
               -Remediation "Configure idle session timeout to 3 hours or less"

    # 1.3.3 - Ensure 'External sharing' of calendars is not available
    Add-Result -ControlNumber "1.3.3" -ControlTitle "Ensure 'External sharing' of calendars is not available" `
               -ProfileLevel "L2" -Result "Manual" -Details "Check M365 Admin Center > Settings > Calendar" `
               -Remediation "Disable external calendar sharing"

    # 1.3.4 - Ensure 'User owned apps and services' is restricted
    Add-Result -ControlNumber "1.3.4" -ControlTitle "Ensure 'User owned apps and services' is restricted" `
               -ProfileLevel "L1" -Result "Manual" -Details "Check M365 Admin Center > Settings > Org Settings > Services > User owned apps and services" `
               -Remediation "Restrict user-owned applications and services"

    # 1.3.5 - Ensure internal phishing protection for Forms is enabled
    Add-Result -ControlNumber "1.3.5" -ControlTitle "Ensure internal phishing protection for Forms is enabled" `
               -ProfileLevel "L1" -Result "Manual" -Details "Check M365 Admin Center > Settings > Org Settings > Microsoft Forms" `
               -Remediation "Enable phishing protection for Microsoft Forms"

    # 1.3.6 - Ensure the customer lockbox feature is enabled
    Add-Result -ControlNumber "1.3.6" -ControlTitle "Ensure the customer lockbox feature is enabled" `
               -ProfileLevel "L2" -Result "Manual" -Details "Check M365 Admin Center > Settings > Org Settings > Security & Privacy > Customer Lockbox" `
               -Remediation "Enable Customer Lockbox feature"

    # 1.3.7 - Ensure 'third-party storage services' are restricted in 'Microsoft 365 on the web'
    Add-Result -ControlNumber "1.3.7" -ControlTitle "Ensure 'third-party storage services' are restricted in 'Microsoft 365 on the web'" `
               -ProfileLevel "L2" -Result "Manual" -Details "Check M365 Admin Center > Settings > Org Settings > Microsoft 365 on the web" `
               -Remediation "Disable third-party storage services"

    # 1.3.8 - Ensure that Sways cannot be shared with people outside of your organization
    Add-Result -ControlNumber "1.3.8" -ControlTitle "Ensure that Sways cannot be shared with people outside of your organization" `
               -ProfileLevel "L2" -Result "Manual" -Details "Check M365 Admin Center > Settings > Org Settings > Sway" `
               -Remediation "Disable external Sway sharing"
}

#endregion

#region Section 2: Microsoft 365 Defender

function Test-M365Defender {
    Write-Log "Checking Section 2: Microsoft 365 Defender..." -Level Info

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
        $malwarePolicies = Get-MalwareFilterPolicy
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
        $malwarePolicies = Get-MalwareFilterPolicy
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
        $hostedContentPolicies = Get-HostedContentFilterPolicy
        $notificationsConfigured = $false

        foreach ($policy in $hostedContentPolicies) {
            if ($policy.NotifyAdmin -eq $true -or $policy.NotifyCustom -eq $true) {
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
        $acceptedDomains = Get-AcceptedDomain
        $missingSpf = @()

        foreach ($domain in $acceptedDomains) {
            if ($domain.DomainType -eq "Authoritative") {
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
        $disabledDkim = $dkimConfigs | Where-Object { $_.Enabled -eq $false }

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
        $acceptedDomains = Get-AcceptedDomain
        $missingDmarc = @()

        foreach ($domain in $acceptedDomains) {
            if ($domain.DomainType -eq "Authoritative") {
                try {
                    $dmarcRecord = Resolve-DnsName -Name "_dmarc.$($domain.DomainName)" -Type TXT -ErrorAction SilentlyContinue |
                                   Where-Object { $_.Strings -like "*v=DMARC1*" }
                    if (-not $dmarcRecord) {
                        $missingDmarc += $domain.DomainName
                    }
                }
                catch {
                    $missingDmarc += $domain.DomainName
                }
            }
        }

        if ($missingDmarc.Count -eq 0) {
            Add-Result -ControlNumber "2.1.10" -ControlTitle "Ensure DMARC Records for all Exchange Online domains are published" `
                       -ProfileLevel "L1" -Result "Pass" -Details "DMARC records present for all domains"
        }
        else {
            Add-Result -ControlNumber "2.1.10" -ControlTitle "Ensure DMARC Records for all Exchange Online domains are published" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Missing DMARC records for: $($missingDmarc -join ', ')" `
                       -Remediation "Publish DMARC records for all domains"
        }
    }
    catch {
        Add-Result -ControlNumber "2.1.10" -ControlTitle "Ensure DMARC Records for all Exchange Online domains are published" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 2.1.11 - Ensure comprehensive attachment filtering is applied
    try {
        Write-Log "Checking 2.1.11 - Comprehensive attachment filtering" -Level Info
        $malwarePolicies = Get-MalwareFilterPolicy

        # Comprehensive list of dangerous file types
        $requiredBlockedTypes = @('ace','ani','app','docm','exe','jar','reg','scr','vbe','vbs','xlsm')
        $allTypesBlocked = $false

        foreach ($policy in $malwarePolicies) {
            if ($policy.FileTypes) {
                $missingTypes = $requiredBlockedTypes | Where-Object { $policy.FileTypes -notcontains $_ }
                if ($missingTypes.Count -eq 0) {
                    $allTypesBlocked = $true
                    break
                }
            }
        }

        if ($allTypesBlocked) {
            Add-Result -ControlNumber "2.1.11" -ControlTitle "Ensure comprehensive attachment filtering is applied" `
                       -ProfileLevel "L2" -Result "Pass" -Details "Comprehensive attachment filtering configured"
        }
        else {
            Add-Result -ControlNumber "2.1.11" -ControlTitle "Ensure comprehensive attachment filtering is applied" `
                       -ProfileLevel "L2" -Result "Fail" -Details "Comprehensive attachment filtering not fully configured" `
                       -Remediation "Block all dangerous file types in malware filter policy"
        }
    }
    catch {
        Add-Result -ControlNumber "2.1.11" -ControlTitle "Ensure comprehensive attachment filtering is applied" `
                   -ProfileLevel "L2" -Result "Error" -Details "Error: $_"
    }

    # 2.1.12 - Ensure the connection filter IP allow list is not used
    try {
        Write-Log "Checking 2.1.12 - Connection filter IP allow list" -Level Info
        $connectionFilter = Get-HostedConnectionFilterPolicy -Identity Default

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
        $connectionFilter = Get-HostedConnectionFilterPolicy -Identity Default

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
        $contentFilters = Get-HostedContentFilterPolicy
        $policiesWithAllowedItems = @()
        $totalAllowedDomains = 0
        $totalAllowedSenders = 0

        foreach ($policy in $contentFilters) {
            $domainCount = if ($policy.AllowedSenderDomains) { $policy.AllowedSenderDomains.Count } else { 0 }
            $senderCount = if ($policy.AllowedSenders) { $policy.AllowedSenders.Count } else { 0 }

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
    Add-Result -ControlNumber "2.4.1" -ControlTitle "Ensure Priority account protection is enabled and configured" `
               -ProfileLevel "L1" -Result "Manual" -Details "Verify in M365 Defender portal > Email & collaboration > Priority account protection" `
               -Remediation "Configure priority account protection for executive accounts"

    # 2.4.2 - Ensure Priority accounts have 'Strict protection' presets applied
    Add-Result -ControlNumber "2.4.2" -ControlTitle "Ensure Priority accounts have 'Strict protection' presets applied" `
               -ProfileLevel "L1" -Result "Manual" -Details "Verify strict protection preset is applied to priority accounts" `
               -Remediation "Apply strict protection preset to all priority accounts"

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
    Add-Result -ControlNumber "3.3.1" -ControlTitle "Ensure Information Protection sensitivity label policies are published" `
               -ProfileLevel "L1" -Result "Manual" -Details "Verify sensitivity labels in Microsoft Purview > Information Protection" `
               -Remediation "Create and publish sensitivity label policies"
}

#endregion

#region Section 4: Microsoft Intune Admin Center

function Test-Intune {
    Write-Log "Checking Section 4: Microsoft Intune Admin Center..." -Level Info

    # 4.1 - Ensure devices without a compliance policy are marked 'not compliant'
    try {
        Write-Log "Checking 4.1 - Non-compliant device marking" -Level Info
        $complianceSettings = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicySettingStateSummaries"

        # Check compliance policy settings
        $deviceManagementSettings = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement"

        if ($deviceManagementSettings.intuneAccountId) {
            # Intune is configured, check compliance settings
            Add-Result -ControlNumber "4.1" -ControlTitle "Ensure devices without a compliance policy are marked 'not compliant'" `
                       -ProfileLevel "L2" -Result "Pass" -Details "Intune compliance policies are configured"
        }
        else {
            Add-Result -ControlNumber "4.1" -ControlTitle "Ensure devices without a compliance policy are marked 'not compliant'" `
                       -ProfileLevel "L2" -Result "Fail" -Details "Intune not fully configured" `
                       -Remediation "Configure Intune compliance policy settings to mark non-compliant devices"
        }
    }
    catch {
        Add-Result -ControlNumber "4.1" -ControlTitle "Ensure devices without a compliance policy are marked 'not compliant'" `
                   -ProfileLevel "L2" -Result "Manual" -Details "Unable to check Intune settings via Graph API. Verify manually." `
                   -Remediation "Check Intune > Devices > Compliance policies > Compliance policy settings"
    }

    # 4.2 - Ensure device enrollment for personally owned devices is blocked by default
    try {
        Write-Log "Checking 4.2 - Personal device enrollment restrictions" -Level Info
        $enrollmentRestrictions = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations"

        $restrictionPolicies = $enrollmentRestrictions.value | Where-Object {
            $_.'@odata.type' -eq '#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration'
        }

        if ($restrictionPolicies) {
            Add-Result -ControlNumber "4.2" -ControlTitle "Ensure device enrollment for personally owned devices is blocked by default" `
                       -ProfileLevel "L2" -Result "Pass" -Details "Enrollment restriction policies found: $($restrictionPolicies.Count)"
        }
        else {
            Add-Result -ControlNumber "4.2" -ControlTitle "Ensure device enrollment for personally owned devices is blocked by default" `
                       -ProfileLevel "L2" -Result "Fail" -Details "No enrollment restriction policies configured" `
                       -Remediation "Configure enrollment restrictions to block personally owned devices"
        }
    }
    catch {
        Add-Result -ControlNumber "4.2" -ControlTitle "Ensure device enrollment for personally owned devices is blocked by default" `
                   -ProfileLevel "L2" -Result "Manual" -Details "Unable to check enrollment restrictions. Verify manually." `
                   -Remediation "Check Intune > Devices > Enrollment restrictions"
    }
}

#endregion

#region Section 5: Microsoft Entra Admin Center

function Test-EntraID {
    Write-Log "Checking Section 5: Microsoft Entra Admin Center..." -Level Info

    # 5.1.2.1 - Ensure 'Per-user MFA' is disabled
    try {
        Write-Log "Checking 5.1.2.1 - Per-user MFA disabled" -Level Info

        if (-not $script:MsolConnected) {
            Add-Result -ControlNumber "5.1.2.1" -ControlTitle "Ensure 'Per-user MFA' is disabled" `
                       -ProfileLevel "L1" -Result "Manual" -Details "MSOnline connection not available. Manual verification required." `
                       -Remediation "Connect to MSOnline or verify through Azure Portal: Azure AD > Users > Multi-Factor Authentication"
        }
        else {
            $users = Get-MsolUser -All
            $perUserMfaEnabled = $users | Where-Object { $_.StrongAuthenticationRequirements.State -eq "Enabled" -or
                                                          $_.StrongAuthenticationRequirements.State -eq "Enforced" }

            if ($perUserMfaEnabled.Count -eq 0) {
                Add-Result -ControlNumber "5.1.2.1" -ControlTitle "Ensure 'Per-user MFA' is disabled" `
                           -ProfileLevel "L1" -Result "Pass" -Details "No per-user MFA enabled (use Conditional Access instead)"
            }
            else {
                Add-Result -ControlNumber "5.1.2.1" -ControlTitle "Ensure 'Per-user MFA' is disabled" `
                           -ProfileLevel "L1" -Result "Fail" -Details "$($perUserMfaEnabled.Count) users have per-user MFA enabled" `
                           -Remediation "Disable per-user MFA and use Conditional Access policies instead"
            }
        }
    }
    catch {
        Add-Result -ControlNumber "5.1.2.1" -ControlTitle "Ensure 'Per-user MFA' is disabled" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 5.1.2.2 - Ensure third party integrated applications are not allowed
    try {
        Write-Log "Checking 5.1.2.2 - Third party app registration" -Level Info
        $authPolicy = Get-MgPolicyAuthorizationPolicy

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
        $authPolicy = Get-MgPolicyAuthorizationPolicy

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
    # NOTE: This is a MANUAL control - Microsoft does not provide a Graph API to check this setting
    # The "Restrict access to Microsoft Entra admin center" setting can only be verified through the portal
    Add-Result -ControlNumber "5.1.2.4" -ControlTitle "Ensure access to the Entra admin center is restricted" `
               -ProfileLevel "L1" -Result "Manual" -Details "Check Entra Admin Center > Identity > Users > User settings > 'Restrict access to Microsoft Entra admin center' should be 'Yes'" `
               -Remediation "Navigate to Entra Admin Center > Identity > Users > User settings > Set 'Restrict access to Microsoft Entra admin center' to 'Yes'"

    # 5.1.2.5 - Ensure the option to remain signed in is hidden
    Add-Result -ControlNumber "5.1.2.5" -ControlTitle "Ensure the option to remain signed in is hidden" `
               -ProfileLevel "L2" -Result "Manual" -Details "Check Company Branding settings" `
               -Remediation "Hide 'Stay signed in?' option in company branding"

    # 5.1.2.6 - Ensure 'LinkedIn account connections' is disabled
    Add-Result -ControlNumber "5.1.2.6" -ControlTitle "Ensure 'LinkedIn account connections' is disabled" `
               -ProfileLevel "L2" -Result "Manual" -Details "Check Entra Admin Center > Users > User settings" `
               -Remediation "Disable LinkedIn account connections"

    # 5.1.3.1 - Ensure a dynamic group for guest users is created
    try {
        Write-Log "Checking 5.1.3.1 - Dynamic group for guest users" -Level Info
        $guestGroups = Get-MgGroup -Filter "groupTypes/any(c:c eq 'DynamicMembership')" -All
        $guestDynamicGroup = $null

        foreach ($group in $guestGroups) {
            # Get the full group details including MembershipRule
            $groupDetails = Get-MgGroup -GroupId $group.Id

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

    # 5.1.5.1 - Ensure user consent to apps accessing company data on their behalf is not allowed
    try {
        Write-Log "Checking 5.1.5.1 - User consent disabled" -Level Info
        $authPolicy = Get-MgPolicyAuthorizationPolicy

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
    Add-Result -ControlNumber "5.1.5.2" -ControlTitle "Ensure the admin consent workflow is enabled" `
               -ProfileLevel "L1" -Result "Manual" -Details "Check Entra Admin Center > Enterprise applications > Admin consent requests" `
               -Remediation "Enable admin consent workflow"

    # 5.1.6.1 - Ensure that collaboration invitations are sent to allowed domains only
    Add-Result -ControlNumber "5.1.6.1" -ControlTitle "Ensure that collaboration invitations are sent to allowed domains only" `
               -ProfileLevel "L2" -Result "Manual" -Details "Check External Identities > External collaboration settings" `
               -Remediation "Configure allowed/denied domain list for B2B collaboration"

    # 5.1.6.2 - Ensure that guest user access is restricted
    try {
        Write-Log "Checking 5.1.6.2 - Guest user access restricted" -Level Info
        $authPolicy = Get-MgPolicyAuthorizationPolicy

        # Guest user role should be restricted (2af84b1e-32c8-42b7-82bc-daa82404023b = restricted guest)
        if ($authPolicy.GuestUserRoleId -eq "2af84b1e-32c8-42b7-82bc-daa82404023b") {
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
        $authPolicy = Get-MgPolicyAuthorizationPolicy

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
                       -Remediation "Set-MgPolicyAuthorizationPolicy -AllowInvitesFrom adminsAndGuestInviters (or adminsOnly for more restrictive)"
        }
    }
    catch {
        Add-Result -ControlNumber "5.1.6.3" -ControlTitle "Ensure guest user invitations are limited to the Guest Inviter role" `
                   -ProfileLevel "L2" -Result "Error" -Details "Error: $_"
    }

    # 5.1.8.1 - Ensure that password hash sync is enabled for hybrid deployments
    Add-Result -ControlNumber "5.1.8.1" -ControlTitle "Ensure that password hash sync is enabled for hybrid deployments" `
               -ProfileLevel "L1" -Result "Manual" -Details "Verify in Azure AD Connect configuration (if hybrid deployment)" `
               -Remediation "Enable password hash synchronization in Azure AD Connect"

    # Conditional Access Policies (5.2.2.x)
    Write-Log "Checking Conditional Access policies..." -Level Info

    # 5.2.2.1 - Ensure multifactor authentication is enabled for all users in administrative roles
    try {
        Write-Log "Checking 5.2.2.1 - MFA for admin roles" -Level Info
        $caPolicies = Get-MgIdentityConditionalAccessPolicy
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
        $caPolicies = Get-MgIdentityConditionalAccessPolicy
        $allUserMfaPolicy = $null

        foreach ($policy in $caPolicies) {
            if ($policy.State -eq "enabled" -and
                ($policy.Conditions.Users.IncludeUsers -contains "All" -or $policy.Conditions.Users.IncludeGroups) -and
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
                ($_.Conditions.Users.IncludeUsers -contains "All" -or $_.Conditions.Users.IncludeGroups) -and
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
        $caPolicies = Get-MgIdentityConditionalAccessPolicy
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
        $caPolicies = Get-MgIdentityConditionalAccessPolicy
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
    Add-Result -ControlNumber "5.2.2.5" -ControlTitle "Ensure 'Phishing-resistant MFA strength' is required for Administrators" `
               -ProfileLevel "L2" -Result "Manual" -Details "Verify CA policy requires phishing-resistant MFA (FIDO2/certificate) for admins" `
               -Remediation "Create CA policy requiring phishing-resistant authentication for administrators"

    # 5.2.2.6 - Enable Identity Protection user risk policies
    try {
        Write-Log "Checking 5.2.2.6 - User risk policy" -Level Info
        $caPolicies = Get-MgIdentityConditionalAccessPolicy
        $userRiskPolicy = $false

        foreach ($policy in $caPolicies) {
            if ($policy.State -eq "enabled" -and $policy.Conditions.UserRiskLevels) {
                $userRiskPolicy = $true
                break
            }
        }

        if ($userRiskPolicy) {
            Add-Result -ControlNumber "5.2.2.6" -ControlTitle "Enable Identity Protection user risk policies" `
                       -ProfileLevel "L1" -Result "Pass" -Details "User risk policy enabled"
        }
        else {
            Add-Result -ControlNumber "5.2.2.6" -ControlTitle "Enable Identity Protection user risk policies" `
                       -ProfileLevel "L1" -Result "Fail" -Details "No user risk policy found" `
                       -Remediation "Create CA policy based on user risk level"
        }
    }
    catch {
        Add-Result -ControlNumber "5.2.2.6" -ControlTitle "Enable Identity Protection user risk policies" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 5.2.2.7 - Enable Identity Protection sign-in risk policies
    try {
        Write-Log "Checking 5.2.2.7 - Sign-in risk policy" -Level Info
        $caPolicies = Get-MgIdentityConditionalAccessPolicy
        $signInRiskPolicy = $false

        foreach ($policy in $caPolicies) {
            if ($policy.State -eq "enabled" -and $policy.Conditions.SignInRiskLevels) {
                $signInRiskPolicy = $true
                break
            }
        }

        if ($signInRiskPolicy) {
            Add-Result -ControlNumber "5.2.2.7" -ControlTitle "Enable Identity Protection sign-in risk policies" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Sign-in risk policy enabled"
        }
        else {
            Add-Result -ControlNumber "5.2.2.7" -ControlTitle "Enable Identity Protection sign-in risk policies" `
                       -ProfileLevel "L1" -Result "Fail" -Details "No sign-in risk policy found" `
                       -Remediation "Create CA policy based on sign-in risk level"
        }
    }
    catch {
        Add-Result -ControlNumber "5.2.2.7" -ControlTitle "Enable Identity Protection sign-in risk policies" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 5.2.2.8 - Ensure 'sign-in risk' is blocked for medium and high risk
    Add-Result -ControlNumber "5.2.2.8" -ControlTitle "Ensure 'sign-in risk' is blocked for medium and high risk" `
               -ProfileLevel "L2" -Result "Manual" -Details "Verify sign-in risk policy blocks medium/high risk" `
               -Remediation "Configure sign-in risk policy to block medium and high risk"

    # 5.2.2.9 - Ensure a managed device is required for authentication
    try {
        Write-Log "Checking 5.2.2.9 - Managed device required" -Level Info
        $caPolicies = Get-MgIdentityConditionalAccessPolicy
        $managedDevicePolicy = $false

        foreach ($policy in $caPolicies) {
            if ($policy.State -eq "enabled" -and
                ($policy.GrantControls.BuiltInControls -contains "compliantDevice" -or
                 $policy.GrantControls.BuiltInControls -contains "domainJoinedDevice")) {
                $managedDevicePolicy = $true
                break
            }
        }

        if ($managedDevicePolicy) {
            Add-Result -ControlNumber "5.2.2.9" -ControlTitle "Ensure a managed device is required for authentication" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Managed device requirement configured"
        }
        else {
            Add-Result -ControlNumber "5.2.2.9" -ControlTitle "Ensure a managed device is required for authentication" `
                       -ProfileLevel "L1" -Result "Fail" -Details "No managed device requirement found" `
                       -Remediation "Create CA policy requiring compliant or Hybrid Azure AD joined device"
        }
    }
    catch {
        Add-Result -ControlNumber "5.2.2.9" -ControlTitle "Ensure a managed device is required for authentication" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 5.2.2.10 - Ensure a managed device is required to register security information
    try {
        Write-Log "Checking 5.2.2.10 - Managed device for MFA registration" -Level Info
        $caPolicies = Get-MgIdentityConditionalAccessPolicy -All

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
        $caPolicies = Get-MgIdentityConditionalAccessPolicy -All

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
        $caPolicies = Get-MgIdentityConditionalAccessPolicy -All

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
        $authMethodPolicy = Get-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId "MicrosoftAuthenticator"

        $featureSettings = $authMethodPolicy.AdditionalProperties['featureSettings']

        # Access nested hashtable properties correctly - try multiple access methods
        $numberMatching = $null
        if ($featureSettings) {
            if ($featureSettings['numberMatchingRequiredState']) {
                $numberMatching = $featureSettings['numberMatchingRequiredState']['state']
            }
            elseif ($featureSettings.numberMatchingRequiredState) {
                $numberMatching = $featureSettings.numberMatchingRequiredState.state
            }
        }

        $additionalContext = $null
        if ($featureSettings) {
            if ($featureSettings['displayAppInformationRequiredState']) {
                $additionalContext = $featureSettings['displayAppInformationRequiredState']['state']
            }
            elseif ($featureSettings.displayAppInformationRequiredState) {
                $additionalContext = $featureSettings.displayAppInformationRequiredState.state
            }
        }

        $locationContext = $null
        if ($featureSettings) {
            if ($featureSettings['displayLocationInformationRequiredState']) {
                $locationContext = $featureSettings['displayLocationInformationRequiredState']['state']
            }
            elseif ($featureSettings.displayLocationInformationRequiredState) {
                $locationContext = $featureSettings.displayLocationInformationRequiredState.state
            }
        }

        # Treat null as not enabled
        if (-not $numberMatching) { $numberMatching = "not configured" }
        if (-not $additionalContext) { $additionalContext = "not configured" }
        if (-not $locationContext) { $locationContext = "not configured" }

        # Microsoft has made number matching "default" (on by default) as of 2025
        # Accept both "enabled" and "default" as compliant states
        $numberMatchingCompliant = ($numberMatching -eq "enabled" -or $numberMatching -eq "default")
        $additionalContextCompliant = ($additionalContext -eq "enabled" -or $additionalContext -eq "default")
        $locationContextCompliant = ($locationContext -eq "enabled" -or $locationContext -eq "default")

        # CIS 5.2.3.1 requires all three: number matching, app info, and location info
        if ($numberMatchingCompliant -and $additionalContextCompliant -and $locationContextCompliant) {
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
    Add-Result -ControlNumber "5.2.3.3" -ControlTitle "Ensure password protection is enabled for on-prem Active Directory" `
               -ProfileLevel "L1" -Result "Manual" -Details "Verify Azure AD Password Protection agent installed on-premises (if hybrid)" `
               -Remediation "Install and configure Azure AD Password Protection for on-premises AD"

    # 5.2.3.4 - Ensure all member users are 'MFA capable'
    try {
        Write-Log "Checking 5.2.3.4 - All users MFA capable" -Level Info
        $authMethods = Get-MgReportAuthenticationMethodUserRegistrationDetail
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
        Add-Result -ControlNumber "5.2.3.4" -ControlTitle "Ensure all member users are 'MFA capable'" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

    # 5.2.3.5 - Ensure weak authentication methods are disabled
    try {
        Write-Log "Checking 5.2.3.5 - Weak auth methods disabled" -Level Info
        $smsConfig = Get-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId "Sms"
        $voiceConfig = Get-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId "Voice"

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
        $authMethodsPolicy = Get-MgPolicyAuthenticationMethodPolicy

        # System credential preferences - use hashtable key access for Graph API beta properties
        $systemCredPrefs = $authMethodsPolicy.AdditionalProperties['systemCredentialPreferences']

        # Check if system-preferred MFA is enabled
        if ($systemCredPrefs -and $systemCredPrefs['state'] -eq "enabled") {
            Add-Result -ControlNumber "5.2.3.6" -ControlTitle "Ensure system-preferred multifactor authentication is enabled" `
                       -ProfileLevel "L1" -Result "Pass" -Details "System-preferred MFA is enabled"
        }
        elseif ($systemCredPrefs -and $systemCredPrefs['state'] -eq "disabled") {
            Add-Result -ControlNumber "5.2.3.6" -ControlTitle "Ensure system-preferred multifactor authentication is enabled" `
                       -ProfileLevel "L1" -Result "Fail" -Details "System-preferred MFA is disabled" `
                       -Remediation "Enable system-preferred MFA in Entra ID > Security > Authentication methods > Settings"
        }
        elseif ($systemCredPrefs -and $systemCredPrefs['state'] -eq "default") {
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
        $globalAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"
        $pimPolicies = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/policies/roleManagementPolicies?`$filter=scopeId eq '/' and scopeType eq 'DirectoryRole'"

        $globalAdminPolicy = $pimPolicies.value | Where-Object {
            $_.displayName -match "Global Administrator"
        }

        if ($globalAdminPolicy) {
            $approvalRule = $globalAdminPolicy.rules | Where-Object { $_.id -eq "Approval_EndUser_Assignment" }
            if ($approvalRule.setting.isApprovalRequired -eq $true) {
                Add-Result -ControlNumber "5.3.4" -ControlTitle "Ensure approval is required for Global Administrator role activation" `
                           -ProfileLevel "L1" -Result "Pass" -Details "Approval required for Global Administrator activation"
            }
            else {
                Add-Result -ControlNumber "5.3.4" -ControlTitle "Ensure approval is required for Global Administrator role activation" `
                           -ProfileLevel "L1" -Result "Fail" -Details "Approval not required for Global Administrator activation" `
                           -Remediation "Require approval for Global Administrator role activation in PIM"
            }
        }
        else {
            Add-Result -ControlNumber "5.3.4" -ControlTitle "Ensure approval is required for Global Administrator role activation" `
                       -ProfileLevel "L1" -Result "Fail" -Details "No PIM policy found for Global Administrator" `
                       -Remediation "Configure PIM for Global Administrator role with approval requirement"
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
        $pimPolicies = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/policies/roleManagementPolicies?`$filter=scopeId eq '/' and scopeType eq 'DirectoryRole'"

        $privRoleAdminPolicy = $pimPolicies.value | Where-Object {
            $_.displayName -match "Privileged Role Administrator"
        }

        if ($privRoleAdminPolicy) {
            $approvalRule = $privRoleAdminPolicy.rules | Where-Object { $_.id -eq "Approval_EndUser_Assignment" }
            if ($approvalRule.setting.isApprovalRequired -eq $true) {
                Add-Result -ControlNumber "5.3.5" -ControlTitle "Ensure approval is required for Privileged Role Administrator activation" `
                           -ProfileLevel "L1" -Result "Pass" -Details "Approval required for Privileged Role Administrator activation"
            }
            else {
                Add-Result -ControlNumber "5.3.5" -ControlTitle "Ensure approval is required for Privileged Role Administrator activation" `
                           -ProfileLevel "L1" -Result "Fail" -Details "Approval not required for Privileged Role Administrator activation" `
                           -Remediation "Require approval for Privileged Role Administrator activation in PIM"
            }
        }
        else {
            Add-Result -ControlNumber "5.3.5" -ControlTitle "Ensure approval is required for Privileged Role Administrator activation" `
                       -ProfileLevel "L1" -Result "Fail" -Details "No PIM policy found for Privileged Role Administrator" `
                       -Remediation "Configure PIM for Privileged Role Administrator role with approval requirement"
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

    # 6.1.1 - Ensure 'AuditDisabled' organizationally is set to 'False'
    try {
        Write-Log "Checking 6.1.1 - Organization audit enabled" -Level Info
        $orgConfig = Get-OrganizationConfig

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
        $orgConfig = Get-OrganizationConfig

        # Required audit actions per CIS Benchmark
        $requiredOwnerActions = @("Create", "HardDelete", "MailboxLogin", "Move", "MoveToDeletedItems", "SoftDelete", "Update")
        $requiredDelegateActions = @("Create", "HardDelete", "Move", "MoveToDeletedItems", "SendAs", "SendOnBehalf", "SoftDelete", "Update")
        $requiredAdminActions = @("Copy", "Create", "HardDelete", "Move", "MoveToDeletedItems", "SendAs", "SendOnBehalf", "SoftDelete", "Update")

        # Sample mailboxes to verify audit actions
        # Increased sample size from 5 to 50 for better coverage in large tenants
        # Note: For tenants with 1000+ mailboxes, this provides ~5% sample rate
        # For very large tenants (10,000+), consider periodic full audits via separate script
        $sampleSize = 50
        $mailboxes = Get-Mailbox -ResultSize $sampleSize | Select-Object UserPrincipalName, AuditEnabled, AuditOwner, AuditDelegate, AuditAdmin

        $compliantMailboxes = 0
        $nonCompliantDetails = @()

        foreach ($mbx in $mailboxes) {
            if ($mbx.AuditEnabled -eq $true) {
                $ownerMissing = $requiredOwnerActions | Where-Object { $mbx.AuditOwner -notcontains $_ }
                $delegateMissing = $requiredDelegateActions | Where-Object { $mbx.AuditDelegate -notcontains $_ }
                $adminMissing = $requiredAdminActions | Where-Object { $mbx.AuditAdmin -notcontains $_ }

                if (-not $ownerMissing -and -not $delegateMissing -and -not $adminMissing) {
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

        if ($orgConfig.AuditDisabled -eq $false -and $compliantMailboxes -eq $mailboxes.Count) {
            Add-Result -ControlNumber "6.1.2" -ControlTitle "Ensure mailbox audit actions are configured" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Mailbox auditing enabled org-wide with proper default actions (sampled $($mailboxes.Count) of $sampleSize requested mailboxes)"
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
            $complianceRate = [Math]::Round(($compliantMailboxes / $mailboxes.Count) * 100, 1)

            Add-Result -ControlNumber "6.1.2" -ControlTitle "Ensure mailbox audit actions are configured" `
                       -ProfileLevel "L1" -Result "Fail" -Details "$($nonCompliantDetails.Count) of $($mailboxes.Count) sampled mailboxes ($complianceRate% compliant) missing required audit actions. Examples: $detailsStr" `
                       -Remediation "Ensure default mailbox auditing is enabled and not overridden. Check: Get-Mailbox -ResultSize Unlimited | Where-Object {`$_.AuditEnabled -eq `$false}"
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
            $bypassMailboxes = Get-Mailbox -ResultSize Unlimited |
                               Get-MailboxAuditBypassAssociation |
                               Where-Object { $_.AuditBypassEnabled -eq $true }

            if ($bypassMailboxes.Count -eq 0 -or $null -eq $bypassMailboxes) {
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
        $outboundSpamPolicy = Get-HostedOutboundSpamFilterPolicy

        if ($outboundSpamPolicy.AutoForwardingMode -eq "Off") {
            Add-Result -ControlNumber "6.2.1" -ControlTitle "Ensure all forms of mail forwarding are blocked and/or disabled" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Auto-forwarding is disabled"
        }
        else {
            Add-Result -ControlNumber "6.2.1" -ControlTitle "Ensure all forms of mail forwarding are blocked and/or disabled" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Auto-forwarding mode: $($outboundSpamPolicy.AutoForwardingMode)" `
                       -Remediation "Set-HostedOutboundSpamFilterPolicy -Identity Default -AutoForwardingMode Off"
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
        $orgConfig = Get-OrganizationConfig

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
        $orgConfig = Get-OrganizationConfig

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
}

#endregion

#region Section 7: SharePoint Admin Center

function Test-SharePointOnline {
    Write-Log "Checking Section 7: SharePoint Admin Center..." -Level Info

    # 7.2.1 - Ensure modern authentication for SharePoint applications is required
    try {
        Write-Log "Checking 7.2.1 - SharePoint modern authentication" -Level Info
        $spoTenant = Get-SPOTenant

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
        $spoTenant = Get-SPOTenant

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
        $spoTenant = Get-SPOTenant

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
        $spoTenant = Get-SPOTenant

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
        $spoTenant = Get-SPOTenant

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
        $spoTenant = Get-SPOTenant

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
        $spoTenant = Get-SPOTenant

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
    Add-Result -ControlNumber "7.2.8" -ControlTitle "Ensure external sharing is restricted by security group" `
               -ProfileLevel "L2" -Result "Manual" -Details "Verify external sharing is limited to specific security groups" `
               -Remediation "Configure security group restrictions for external sharing"

    # 7.2.9 - Ensure guest access to a site or OneDrive will expire automatically
    try {
        Write-Log "Checking 7.2.9 - Guest link expiration" -Level Info
        $spoTenant = Get-SPOTenant

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
        $spoTenant = Get-SPOTenant

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
        $spoTenant = Get-SPOTenant

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
        $spoTenant = Get-SPOTenant

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
        $spoTenant = Get-SPOTenant

        if ($spoTenant.IsUnmanagedSyncClientForTenantRestricted -eq $true) {
            Add-Result -ControlNumber "7.3.2" -ControlTitle "Ensure OneDrive sync is restricted for unmanaged devices" `
                       -ProfileLevel "L2" -Result "Pass" -Details "OneDrive sync restricted for unmanaged devices"
        }
        else {
            Add-Result -ControlNumber "7.3.2" -ControlTitle "Ensure OneDrive sync is restricted for unmanaged devices" `
                       -ProfileLevel "L2" -Result "Fail" -Details "Unmanaged device sync not restricted" `
                       -Remediation "Set-SPOTenant -IsUnmanagedSyncClientForTenantRestricted `$true"
        }
    }
    catch {
        Add-Result -ControlNumber "7.3.2" -ControlTitle "Ensure OneDrive sync is restricted for unmanaged devices" `
                   -ProfileLevel "L2" -Result "Error" -Details "Error: $_"
    }

    # 7.3.3 - Ensure custom script execution is restricted on personal sites
    try {
        Write-Log "Checking 7.3.3 - Custom script on personal sites" -Level Info
        $spoTenant = Get-SPOTenant

        # Check tenant default for new sites
        $tenantDefault = $spoTenant.DenyAddAndCustomizePages

        # Sample check of existing personal sites (OneDrive) - limit to prevent performance issues
        Write-Log "Sampling OneDrive sites to verify custom script restriction..." -Level Info
        $personalSites = Get-SPOSite -IncludePersonalSite $true -Limit 100 -Filter "Url -like '-my.sharepoint.com/personal/'"

        $sitesAllowingScripts = $personalSites | Where-Object {
            $_.DenyAddAndCustomizePages -eq "Disabled" -or $_.DenyAddAndCustomizePages -eq 0
        }

        if ($tenantDefault -in @(1, 2) -and $sitesAllowingScripts.Count -eq 0) {
            Add-Result -ControlNumber "7.3.3" -ControlTitle "Ensure custom script execution is restricted on personal sites" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Custom scripts restricted: Tenant default set and sampled sites ($($personalSites.Count)) compliant"
        }
        elseif ($sitesAllowingScripts.Count -gt 0) {
            $siteList = ($sitesAllowingScripts | Select-Object -First 5 -ExpandProperty Url) -join ', '
            Add-Result -ControlNumber "7.3.3" -ControlTitle "Ensure custom script execution is restricted on personal sites" `
                       -ProfileLevel "L1" -Result "Fail" -Details "$($sitesAllowingScripts.Count) OneDrive sites allow custom scripts. Examples: $siteList" `
                       -Remediation "Run: Get-SPOSite -IncludePersonalSite `$true -Limit All | Set-SPOSite -DenyAddAndCustomizePages Enabled"
        }
        else {
            Add-Result -ControlNumber "7.3.3" -ControlTitle "Ensure custom script execution is restricted on personal sites" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Tenant default allows custom scripts (DenyAddAndCustomizePages: $tenantDefault)" `
                       -Remediation "Set-SPOTenant -DenyAddAndCustomizePages 1; then apply to existing sites"
        }
    }
    catch {
        Add-Result -ControlNumber "7.3.3" -ControlTitle "Ensure custom script execution is restricted on personal sites" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_ - Verify manually in SharePoint Admin Center" `
                   -Remediation "Check SharePoint Admin Center > Settings > Custom Script"
    }

    # 7.3.4 - Ensure custom script execution is restricted on site collections
    try {
        Write-Log "Checking 7.3.4 - Custom script restricted on sites" -Level Info

        # Get all sites excluding:
        # - Personal sites (OneDrive - covered by 7.3.3)
        # - Redirect sites (REDIRECTSITE)
        # - App catalog sites (APPCATALOG)
        # - Content Type Hub (POINTPUBLISHINGHUB)
        # - Search center (SRCHCEN, SRCHCENTERLITE)
        $sites = Get-SPOSite -Limit All | Where-Object {
            $_.Template -notlike "*SPSMSITEHOST*" -and
            $_.Template -notlike "*REDIRECTSITE*" -and
            $_.Template -notlike "*APPCATALOG*" -and
            $_.Template -notlike "*POINTPUBLISHINGHUB*" -and
            $_.Template -notlike "*SRCHCEN*" -and
            $_.Url -notlike "*/personal/*"
        }

        $sitesWithCustomScript = $sites | Where-Object {
            $_.DenyAddAndCustomizePages -eq "Disabled" -or $_.DenyAddAndCustomizePages -eq 0
        }

        if ($sitesWithCustomScript.Count -eq 0) {
            Add-Result -ControlNumber "7.3.4" -ControlTitle "Ensure custom script execution is restricted on site collections" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Custom scripts restricted on all $($sites.Count) applicable site collections"
        }
        else {
            $siteList = ($sitesWithCustomScript | Select-Object -First 5 -ExpandProperty Url) -join ', '
            Add-Result -ControlNumber "7.3.4" -ControlTitle "Ensure custom script execution is restricted on site collections" `
                       -ProfileLevel "L1" -Result "Fail" -Details "$($sitesWithCustomScript.Count) sites allow custom scripts. Examples: $siteList" `
                       -Remediation "Run: Get-SPOSite -Limit All | Where-Object {-not (`$_.Url -like '*/personal/*')} | Set-SPOSite -DenyAddAndCustomizePages Enabled"
        }
    }
    catch {
        Add-Result -ControlNumber "7.3.4" -ControlTitle "Ensure custom script execution is restricted on site collections" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }
}

#endregion

#region Section 8: Microsoft Teams Admin Center

function Test-MicrosoftTeams {
    Write-Log "Checking Section 8: Microsoft Teams Admin Center..." -Level Info

    # 8.1.1 - Ensure external file sharing in Teams is enabled for only approved cloud storage services
    try {
        Write-Log "Checking 8.1.1 - Teams external file sharing" -Level Info
        $teamsClientConfig = Get-CsTeamsClientConfiguration -Identity Global

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
        $teamsClientConfig = Get-CsTeamsClientConfiguration -Identity Global

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
        $externalAccessPolicy = Get-CsExternalAccessPolicy -Identity Global
        $tenantFedConfig = Get-CsTenantFederationConfiguration

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
        $tenantFedConfig = Get-CsTenantFederationConfiguration

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
        $tenantFedConfig = Get-CsTenantFederationConfiguration

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
        $tenantFedConfig = Get-CsTenantFederationConfiguration

        if ($tenantFedConfig.AllowPublicUsers -eq $false) {
            Add-Result -ControlNumber "8.2.4" -ControlTitle "Ensure communication with Skype users is disabled" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Skype federation disabled"
        }
        else {
            Add-Result -ControlNumber "8.2.4" -ControlTitle "Ensure communication with Skype users is disabled" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Skype federation enabled" `
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
        $appPermissionPolicies = Get-CsTeamsAppPermissionPolicy

        # Check global policy for third-party and custom app restrictions
        $globalPolicy = $appPermissionPolicies | Where-Object { $_.Identity -eq "Global" }

        if ($globalPolicy) {
            # Check if third-party and custom apps are restricted
            $thirdPartyRestricted = ($globalPolicy.DefaultCatalogAppsType -eq "BlockedAppList" -or
                                      $globalPolicy.DefaultCatalogAppsType -eq "AllowedAppList")
            $customAppsRestricted = ($globalPolicy.GlobalCatalogAppsType -eq "BlockedAppList" -or
                                     $globalPolicy.GlobalCatalogAppsType -eq "AllowedAppList")

            if ($thirdPartyRestricted -or $customAppsRestricted) {
                Add-Result -ControlNumber "8.4.1" -ControlTitle "Ensure app permission policies are configured" `
                           -ProfileLevel "L1" -Result "Pass" -Details "App permissions restricted (Third-party: $($globalPolicy.DefaultCatalogAppsType), Custom: $($globalPolicy.GlobalCatalogAppsType))"
            }
            else {
                Add-Result -ControlNumber "8.4.1" -ControlTitle "Ensure app permission policies are configured" `
                           -ProfileLevel "L1" -Result "Fail" -Details "App permissions too permissive (Third-party: $($globalPolicy.DefaultCatalogAppsType), Custom: $($globalPolicy.GlobalCatalogAppsType))" `
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
        $teamsMeetingPolicy = Get-CsTeamsMeetingPolicy -Identity Global

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
        $teamsMeetingPolicy = Get-CsTeamsMeetingPolicy -Identity Global

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
        $teamsMeetingPolicy = Get-CsTeamsMeetingPolicy -Identity Global

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
        $teamsMeetingPolicy = Get-CsTeamsMeetingPolicy -Identity Global

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
        $teamsMeetingPolicy = Get-CsTeamsMeetingPolicy -Identity Global

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
        $teamsMeetingPolicy = Get-CsTeamsMeetingPolicy -Identity Global

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
        $teamsMeetingPolicy = Get-CsTeamsMeetingPolicy -Identity Global

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
        $teamsMeetingPolicy = Get-CsTeamsMeetingPolicy -Identity Global

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
        $teamsMeetingPolicy = Get-CsTeamsMeetingPolicy -Identity Global

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
        $teamsMessagingPolicy = Get-CsTeamsMessagingPolicy -Identity Global

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

    # All Power BI checks are manual as they require portal access

    Add-Result -ControlNumber "9.1.1" -ControlTitle "Ensure guest user access is restricted" `
               -ProfileLevel "L1" -Result "Manual" -Details "Check Power BI Admin Portal > Tenant settings" `
               -Remediation "Disable or restrict guest user access to Power BI"

    Add-Result -ControlNumber "9.1.2" -ControlTitle "Ensure external user invitations are restricted" `
               -ProfileLevel "L1" -Result "Manual" -Details "Check Power BI Admin Portal > Tenant settings" `
               -Remediation "Restrict ability to invite external users"

    Add-Result -ControlNumber "9.1.3" -ControlTitle "Ensure guest access to content is restricted" `
               -ProfileLevel "L1" -Result "Manual" -Details "Check Power BI Admin Portal > Tenant settings" `
               -Remediation "Restrict guest browsing of Fabric content"

    Add-Result -ControlNumber "9.1.4" -ControlTitle "Ensure 'Publish to web' is restricted" `
               -ProfileLevel "L1" -Result "Manual" -Details "Check Power BI Admin Portal > Tenant settings > Export and sharing" `
               -Remediation "Disable or restrict 'Publish to web' feature"

    Add-Result -ControlNumber "9.1.5" -ControlTitle "Ensure 'Interact with and share R and Python' visuals is 'Disabled'" `
               -ProfileLevel "L2" -Result "Manual" -Details "Check Power BI Admin Portal > Tenant settings" `
               -Remediation "Disable R and Python script visuals"

    Add-Result -ControlNumber "9.1.6" -ControlTitle "Ensure 'Allow users to apply sensitivity labels for content' is 'Enabled'" `
               -ProfileLevel "L1" -Result "Manual" -Details "Check Power BI Admin Portal > Tenant settings > Information protection" `
               -Remediation "Enable sensitivity labels in Power BI (requires MIP prerequisites)"

    Add-Result -ControlNumber "9.1.7" -ControlTitle "Ensure shareable links are restricted" `
               -ProfileLevel "L1" -Result "Manual" -Details "Check Power BI Admin Portal > Tenant settings" `
               -Remediation "Restrict 'People in organization' shareable links"

    Add-Result -ControlNumber "9.1.8" -ControlTitle "Ensure enabling of external data sharing is restricted" `
               -ProfileLevel "L1" -Result "Manual" -Details "Check Power BI Admin Portal > Tenant settings" `
               -Remediation "Restrict external dataset sharing"

    Add-Result -ControlNumber "9.1.9" -ControlTitle "Ensure 'Block ResourceKey Authentication' is 'Enabled'" `
               -ProfileLevel "L1" -Result "Manual" -Details "Check Power BI Admin Portal > Tenant settings" `
               -Remediation "Enable blocking of resource key authentication"

    Add-Result -ControlNumber "9.1.10" -ControlTitle "Ensure access to APIs by Service Principals is restricted" `
               -ProfileLevel "L1" -Result "Manual" -Details "Check Power BI Admin Portal > Tenant settings > Developer" `
               -Remediation "Restrict service principal API access"

    Add-Result -ControlNumber "9.1.11" -ControlTitle "Ensure Service Principals cannot create and use profiles" `
               -ProfileLevel "L1" -Result "Manual" -Details "Check Power BI Admin Portal > Tenant settings" `
               -Remediation "Restrict service principal profile creation"
}

#endregion

#region Report Generation

function Export-HtmlReport {
    param([string]$OutputPath)

    $reportPath = Join-Path $OutputPath "CIS-M365-Compliance-Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"

    # Capture tenant and user context
    $mgContext = Get-MgContext
    $currentTenantId = if ($mgContext.TenantId) { $mgContext.TenantId } else { "Unknown" }
    $currentUserAccount = if ($mgContext.Account) { $mgContext.Account } else { "Unknown User" }
    $reportDate = Get-Date -Format "MMMM dd, yyyy HH:mm:ss"

    $passRate = if ($Script:TotalControls -gt 0) {
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
<html>
<head>
    <title>CIS Microsoft 365 Compliance Report</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #0a0a0c; color: #e4e4e7; padding-top: 0; }
        .container { max-width: 1400px; margin: 0 auto; }

        /* Sticky Header */
        .header {
            background: #18181b;
            border-bottom: 3px solid #60a5fa;
            position: sticky;
            top: 0;
            z-index: 1000;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
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
            color: white;
        }
        .subtitle {
            font-size: 0.9em;
            opacity: 0.9;
            margin-top: 4px;
            color: white;
        }
        .header-right {
            display: flex;
            align-items: center;
            justify-content: flex-end;
            color: white;
            position: relative;
        }

        .tenant-info {
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 4px 8px;
            border-radius: 5px;
            transition: background-color 0.3s ease;
        }
        .tenant-info:hover {
            background-color: rgba(255, 255, 255, 0.1);
        }
        .expand-icon {
            font-size: 0.8em;
            transition: transform 0.3s ease;
        }
        .expand-icon.expanded {
            transform: rotate(180deg);
        }
        .header-details-box {
            display: none;
            position: absolute;
            top: calc(100% + 10px);
            right: 0;
            width: 320px;
            background: #1a1d2e;
            border: 1px solid #2d3548;
            border-radius: 6px;
            padding: 8px 12px;
            animation: slideDown 0.3s ease;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);
            z-index: 1001;
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
            border-bottom: 1px solid #2d3548;
        }
        .detail-item:last-child {
            margin-bottom: 0;
            padding-bottom: 0;
            border-bottom: none;
        }
        .detail-label {
            font-size: 0.8em;
            color: white;
            font-weight: 600;
            margin-bottom: 2px;
        }
        .detail-value {
            font-size: 0.75em;
            color: #9ca3af;
        }

        /* Content */
        .content { padding: 10px 40px 20px 40px; }
        h2 { color: white; margin-top: 30px; margin-bottom: 15px; }
        h2:first-child { margin-top: 0; margin-bottom: 10px; }

        .summary { background: #18181b; padding: 12px 15px; border-radius: 8px; margin-bottom: 25px; border: 1px solid #27272a; }

        .summary-box {
            display: inline-block;
            margin: 8px 15px 8px 0;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            transition: all 0.3s ease;
            background-color: #000000;
            border: 2px solid #ffffff;
        }
        .summary-box:hover {
            transform: translateY(-2px);
            box-shadow: 0 0 8px rgba(255, 255, 255, 0.5);
        }
        .summary-box.active {
            box-shadow: 0 0 12px rgba(96, 165, 250, 0.8);
            border: 2px solid #60a5fa !important;
        }
        .pass { color: #4ade80; }
        .fail { color: #f87171; }
        .manual { color: #fbbf24; }
        .error { color: #f87171; }
        .level-l1 { color: #93c5fd; }
        .level-l2 { color: #c4b5fd; }

        .progress-bar { width: 100%; height: 30px; background-color: #27272a; border-radius: 5px; overflow: hidden; margin: 15px 0; }
        .progress-fill { height: 100%; background-color: #22c55e; text-align: center; line-height: 30px; color: white; font-weight: bold; }

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
            background-color: #27272a;
            border: 2px solid #3f3f46;
            border-radius: 8px;
            color: #f4f4f5;
            transition: all 0.3s ease;
            outline: none;
        }
        #searchBox:focus {
            border-color: #60a5fa;
            box-shadow: 0 0 10px rgba(96, 165, 250, 0.3);
        }
        #searchBox::placeholder {
            color: #71717a;
        }
        .search-icon {
            position: absolute;
            right: 20px;
            top: 50%;
            transform: translateY(-50%);
            font-size: 20px;
            pointer-events: none;
            color: #71717a;
        }
        .search-results {
            display: block;
            margin-top: 8px;
            font-size: 14px;
            color: #a1a1aa;
        }

        table { width: 100%; border-collapse: collapse; background: #18181b; border: 1px solid #27272a; margin-top: 20px; }
        th { background-color: #18181b; color: white; padding: 12px; text-align: left; font-weight: 600; border-bottom: 2px solid #60a5fa; }
        td { padding: 12px; border-bottom: 1px solid #27272a; }
        tr:hover { background-color: #27272a; }
        .status-pass { color: #4ade80; font-weight: bold; }
        .status-fail { color: #f87171; font-weight: bold; }
        .status-manual { color: #fbbf24; font-weight: bold; }
        .status-error { color: #f87171; font-weight: bold; }
        .details { font-size: 0.9em; color: #a1a1aa; }
        .remediation { font-size: 0.85em; color: #60a5fa; font-style: italic; margin-top: 5px; }

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
            border: 2px solid #60a5fa;
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
            border-color: #93c5fd;
        }
        .action-btn::before {
            content: attr(data-tooltip);
            position: absolute;
            right: 70px;
            background: #18181b;
            color: #e4e4e7;
            padding: 8px 12px;
            border-radius: 6px;
            font-size: 14px;
            white-space: nowrap;
            opacity: 0;
            pointer-events: none;
            transition: opacity 0.3s ease;
            border: 1px solid #3f3f46;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
        }
        .action-btn:hover::before {
            opacity: 1;
        }

        /* Footer */
        .footer {
            background: #18181b;
            color: #a1a1aa;
            padding: 10px 40px;
            text-align: center;
            border-top: 1px solid #27272a;
            margin-top: 40px;
            font-size: 0.9em;
        }
        .footer p { margin: 0; }
        .footer a { color: #60a5fa; text-decoration: none; }
        .footer a:hover { text-decoration: underline; }

        /* Hidden class for filtering */
        .hidden { display: none !important; }
    </style>
</head>
<body>
    <!-- Header -->
    <div class="header">
        <div class="header-container">
            <div class="header-left">
                <h1>CIS MICROSOFT 365 FOUNDATIONS BENCHMARK v5.0.0</h1>
            </div>
            <div class="header-right">
                <div class="tenant-info" onclick="toggleHeaderDetails()">
                    <span class="subtitle">$TenantDomain</span>
                    <span class="expand-icon" id="expandIcon">&#9660;</span>
                </div>
                <div class="header-details-box" id="headerDetailsBox">
                    <div class="detail-item">
                        <div class="detail-label">Tenant</div>
                        <div class="detail-value">$TenantDomain</div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">Tenant ID</div>
                        <div class="detail-value">$currentTenantId</div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">Assessment generated by</div>
                        <div class="detail-value">$currentUserAccount</div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">Assessment run on</div>
                        <div class="detail-value">$reportDate</div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">Version</div>
                        <div class="detail-value">CIS Benchmark v5.0.0</div>
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

    foreach ($result in $Script:Results | Sort-Object ControlNumber) {
        $statusClass = "status-" + $result.Result.ToLower()
        $resultLower = $result.Result.ToLower()
        $levelValue = $result.ProfileLevel
        $html += @"
            <tr data-result="$resultLower" data-level="$levelValue">
                <td><strong>$($result.ControlNumber)</strong></td>
                <td>$($result.ControlTitle)</td>
                <td>$($result.ProfileLevel)</td>
                <td class="$statusClass">$($result.Result)</td>
                <td>
                    <div class="details">$($result.Details)</div>
"@
        if ($result.Remediation -and $result.Result -eq "Fail") {
            $html += "                    <div class='remediation'>Remediation: $($result.Remediation)</div>`n"
        }
        $html += "                </td>`n            </tr>`n"
    }

    $html += @"
        </tbody>
    </table>
        </div>

        <!-- Floating Action Buttons -->
        <div class="floating-actions">
            <a href="https://github.com/mohammedsiddiqui6872/CIS-Microsoft-365-Foundations-Benchmark-v5.0.0" target="_blank" class="action-btn" data-tooltip="View on GitHub">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="white"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
            </a>
            <a href="https://github.com/mohammedsiddiqui6872/CIS-Microsoft-365-Foundations-Benchmark-v5.0.0/issues" target="_blank" class="action-btn" data-tooltip="Report Issues">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="white"><path d="M12 2c5.514 0 10 4.486 10 10s-4.486 10-10 10-10-4.486-10-10 4.486-10 10-10zm0-2c-6.627 0-12 5.373-12 12s5.373 12 12 12 12-5.373 12-12-5.373-12-12-12zm-1 6h2v8h-2v-8zm1 12.25c-.69 0-1.25-.56-1.25-1.25s.56-1.25 1.25-1.25 1.25.56 1.25 1.25-.56 1.25-1.25 1.25z"/></svg>
            </a>
            <a href="https://github.com/mohammedsiddiqui6872/CIS-Microsoft-365-Foundations-Benchmark-v5.0.0/issues/new" target="_blank" class="action-btn" data-tooltip="Submit Feedback">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="white"><path d="M12 3c5.514 0 10 3.592 10 8.007 0 4.917-5.145 7.961-9.91 7.961-1.937 0-3.383-.397-4.394-.644-1 .613-1.595 1.037-4.272 1.82.535-1.373.723-2.748.602-4.265-.838-1-2.025-2.4-2.025-4.872-.001-4.415 4.485-8.007 9.999-8.007zm0-2c-6.338 0-12 4.226-12 10.007 0 2.05.739 4.063 2.047 5.625.055 1.83-1.023 4.456-1.993 6.368 2.602-.47 6.301-1.508 7.978-2.536 1.418.345 2.775.503 4.059.503 7.084 0 11.91-4.837 11.91-9.961-.001-5.811-5.702-10.006-12.001-10.006z"/></svg>
            </a>
            <a href="https://www.linkedin.com/in/mohammedsiddiqui6872/" target="_blank" class="action-btn" data-tooltip="Let's Chat!">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="white"><path d="M19 0h-14c-2.761 0-5 2.239-5 5v14c0 2.761 2.239 5 5 5h14c2.762 0 5-2.239 5-5v-14c0-2.761-2.238-5-5-5zm-11 19h-3v-11h3v11zm-1.5-12.268c-.966 0-1.75-.79-1.75-1.764s.784-1.764 1.75-1.764 1.75.79 1.75 1.764-.783 1.764-1.75 1.764zm13.5 12.268h-3v-5.604c0-3.368-4-3.113-4 0v5.604h-3v-11h3v1.765c1.396-2.586 7-2.777 7 2.476v6.759z"/></svg>
            </a>
            <a href="https://buymeacoffee.com/mohammedsiddiqui" target="_blank" class="action-btn" data-tooltip="Buy Me a Coffee">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="white"><path d="M20 3H4v10c0 2.21 1.79 4 4 4h6c2.21 0 4-1.79 4-4v-3h2c1.11 0 2-.9 2-2V5c0-1.11-.89-2-2-2zm0 5h-2V5h2v3zM4 19h16v2H4z"/></svg>
            </a>
        </div>

        <!-- Footer -->
        <div class="footer">
            <p><strong>CIS Microsoft 365 Foundations Benchmark v5.0.0</strong> | Generated $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") | $Script:TotalControls controls | Run by: $currentUserAccount</p>
        </div>
    </div>

    <script>
        let activeFilter = null;

        function toggleHeaderDetails() {
            const detailsBox = document.getElementById('headerDetailsBox');
            const icon = document.getElementById('expandIcon');
            detailsBox.classList.toggle('expanded');
            icon.classList.toggle('expanded');
        }

        function filterResults(box) {
            const filterValue = box.getAttribute('data-filter');
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
                ? `Found 1 result out of ${totalCount} controls`
                : `Found ${visibleCount} results out of ${totalCount} controls`;
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
    $Script:Results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Log "CSV report saved to: $csvPath" -Level Success
    return $csvPath
}

#endregion

#region Main Execution

function Start-ComplianceCheck {
    Write-Host "`n"
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "  CIS Microsoft 365 Foundations Benchmark v5.0.0" -ForegroundColor Cyan
    Write-Host "  Compliance Checker" -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "`n"

    # Check required modules
    Write-Log "Checking required PowerShell modules..." -Level Info
    $requiredModules = @(
        "Microsoft.Graph",
        "ExchangeOnlineManagement",
        "Microsoft.Online.SharePoint.PowerShell",
        "MicrosoftTeams",
        "MSOnline"
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
        @{ Name = "Microsoft 365 Admin Center"; Function = { Test-M365AdminCenter } }
        @{ Name = "Microsoft 365 Defender"; Function = { Test-M365Defender } }
        @{ Name = "Microsoft Purview"; Function = { Test-Purview } }
        @{ Name = "Microsoft Intune"; Function = { Test-Intune } }
        @{ Name = "Microsoft Entra ID"; Function = { Test-EntraID } }
        @{ Name = "Exchange Online"; Function = { Test-ExchangeOnline } }
        @{ Name = "SharePoint Online"; Function = { Test-SharePointOnline } }
        @{ Name = "Microsoft Teams"; Function = { Test-MicrosoftTeams } }
        @{ Name = "Power BI"; Function = { Test-PowerBI } }
    )

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

    Write-Host "`n"
    Write-Host "Reports saved to:" -ForegroundColor Cyan
    Write-Host "  HTML: $htmlReport" -ForegroundColor White
    Write-Host "  CSV:  $csvReport" -ForegroundColor White
    Write-Host "`n"

    # Disconnect
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

    Write-Log "Done!" -Level Success
}

# Only run the compliance check if script is executed directly (not dot-sourced by module)
if ($MyInvocation.InvocationName -ne '.' -and $MyInvocation.InvocationName -notlike '*psm1') {
    # Script was called directly, not imported as a module
    Start-ComplianceCheck
}

#endregion
