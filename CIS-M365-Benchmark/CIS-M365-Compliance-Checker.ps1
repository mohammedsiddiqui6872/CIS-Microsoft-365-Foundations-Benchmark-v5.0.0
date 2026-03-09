#Requires -Version 5.1


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

$Script:Results = [System.Collections.Generic.List[PSCustomObject]]::new()
$Script:TotalControls = 0
$Script:PassedControls = 0
$Script:FailedControls = 0
$Script:ManualControls = 0
$Script:ErrorControls = 0

$Script:RequestedProfileLevel = $ProfileLevel
$Script:LogFilePath = $null

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

$Script:ControlRegistry = @{
    "1.1.1" = @{ Title = "Ensure Administrative accounts are cloud-only"; Level = "L1" }
    "1.1.2" = @{ Title = "Ensure two emergency access accounts have been defined"; Level = "L1" }
    "1.1.3" = @{ Title = "Ensure that between two and four global admins are designated"; Level = "L1" }
    "1.1.4" = @{ Title = "Ensure administrative accounts use licenses with a reduced application footprint"; Level = "L1" }
    "1.2.1" = @{ Title = "Ensure that only organizationally managed/approved public groups exist"; Level = "L2" }
    "1.2.2" = @{ Title = "Ensure sign-in to shared mailboxes is blocked"; Level = "L1" }
    "1.3.1" = @{ Title = "Ensure the 'Password expiration policy' is set to 'Set passwords to never expire'"; Level = "L1" }
    "1.3.2" = @{ Title = "Ensure 'Idle session timeout' is set to '3 hours (or less)' for unmanaged devices"; Level = "L2" }
    "1.3.3" = @{ Title = "Ensure 'External sharing' of calendars is not available"; Level = "L2" }
    "1.3.4" = @{ Title = "Ensure 'User owned apps and services' is restricted"; Level = "L1" }
    "1.3.5" = @{ Title = "Ensure internal phishing protection for Forms is enabled"; Level = "L1" }
    "1.3.6" = @{ Title = "Ensure the customer lockbox feature is enabled"; Level = "L2" }
    "1.3.7" = @{ Title = "Ensure 'third-party storage services' are restricted in 'Microsoft 365 on the web'"; Level = "L2" }
    "1.3.8" = @{ Title = "Ensure that Sways cannot be shared with people outside of your organization"; Level = "L2" }
    "1.3.9" = @{ Title = "Ensure shared bookings pages are restricted to select users"; Level = "L1" }
    "2.1.1" = @{ Title = "Ensure Safe Links for Office Applications is Enabled"; Level = "L2" }
    "2.1.2" = @{ Title = "Ensure the Common Attachment Types Filter is enabled"; Level = "L1" }
    "2.1.3" = @{ Title = "Ensure notifications for internal users sending malware is Enabled"; Level = "L1" }
    "2.1.4" = @{ Title = "Ensure Safe Attachments policy is enabled"; Level = "L2" }
    "2.1.5" = @{ Title = "Ensure Safe Attachments for SharePoint, OneDrive, and Microsoft Teams is Enabled"; Level = "L2" }
    "2.1.6" = @{ Title = "Ensure Exchange Online Spam Policies are set to notify administrators"; Level = "L1" }
    "2.1.7" = @{ Title = "Ensure that an anti-phishing policy has been created"; Level = "L2" }
    "2.1.8" = @{ Title = "Ensure that SPF records are published for all Exchange Domains"; Level = "L1" }
    "2.1.9" = @{ Title = "Ensure that DKIM is enabled for all Exchange Online Domains"; Level = "L1" }
    "2.1.10" = @{ Title = "Ensure DMARC Records for all Exchange Online domains are published"; Level = "L1" }
    "2.1.11" = @{ Title = "Ensure comprehensive attachment filtering is applied"; Level = "L2" }
    "2.1.12" = @{ Title = "Ensure the connection filter IP allow list is not used"; Level = "L1" }
    "2.1.13" = @{ Title = "Ensure the connection filter safe list is off"; Level = "L1" }
    "2.1.14" = @{ Title = "Ensure inbound anti-spam policies do not contain allowed domains"; Level = "L1" }
    "2.1.15" = @{ Title = "Ensure outbound anti-spam message limits are in place"; Level = "L1" }
    "2.2.1" = @{ Title = "Ensure emergency access account activity is monitored"; Level = "L1" }
    "2.4.1" = @{ Title = "Ensure Priority account protection is enabled and configured"; Level = "L1" }
    "2.4.2" = @{ Title = "Ensure Priority accounts have 'Strict protection' presets applied"; Level = "L1" }
    "2.4.3" = @{ Title = "Ensure Microsoft Defender for Cloud Apps is enabled and configured"; Level = "L2" }
    "2.4.4" = @{ Title = "Ensure Zero-hour auto purge for Microsoft Teams is on"; Level = "L1" }
    "3.1.1" = @{ Title = "Ensure Microsoft 365 audit log search is Enabled"; Level = "L1" }
    "3.2.1" = @{ Title = "Ensure DLP policies are enabled"; Level = "L1" }
    "3.2.2" = @{ Title = "Ensure DLP policies are enabled for Microsoft Teams"; Level = "L1" }
    "3.3.1" = @{ Title = "Ensure Information Protection sensitivity label policies are published"; Level = "L1" }
    "4.1" = @{ Title = "Ensure devices without a compliance policy are marked 'not compliant'"; Level = "L2" }
    "4.2" = @{ Title = "Ensure device enrollment for personally owned devices is blocked by default"; Level = "L2" }
    "5.1.2.1" = @{ Title = "Ensure 'Per-user MFA' is disabled"; Level = "L1" }
    "5.1.2.2" = @{ Title = "Ensure third party integrated applications are not allowed"; Level = "L2" }
    "5.1.2.3" = @{ Title = "Ensure 'Restrict non-admin users from creating tenants' is set to 'Yes'"; Level = "L1" }
    "5.1.2.4" = @{ Title = "Ensure access to the Entra admin center is restricted"; Level = "L1" }
    "5.1.2.5" = @{ Title = "Ensure the option to remain signed in is hidden"; Level = "L2" }
    "5.1.2.6" = @{ Title = "Ensure 'LinkedIn account connections' is disabled"; Level = "L2" }
    "5.1.3.1" = @{ Title = "Ensure a dynamic group for guest users is created"; Level = "L1" }
    "5.1.3.2" = @{ Title = "Ensure users cannot create security groups"; Level = "L1" }
    "5.1.4.1" = @{ Title = "Ensure the ability to join devices to Entra is restricted"; Level = "L2" }
    "5.1.4.2" = @{ Title = "Ensure the maximum number of devices per user is limited"; Level = "L1" }
    "5.1.4.3" = @{ Title = "Ensure the GA role is not added as a local administrator during Entra join"; Level = "L1" }
    "5.1.4.4" = @{ Title = "Ensure local administrator assignment is limited during Entra join"; Level = "L1" }
    "5.1.4.5" = @{ Title = "Ensure Local Administrator Password Solution is enabled"; Level = "L1" }
    "5.1.4.6" = @{ Title = "Ensure users are restricted from recovering BitLocker keys"; Level = "L2" }
    "5.1.5.1" = @{ Title = "Ensure user consent to apps accessing company data on their behalf is not allowed"; Level = "L2" }
    "5.1.5.2" = @{ Title = "Ensure the admin consent workflow is enabled"; Level = "L1" }
    "5.1.6.1" = @{ Title = "Ensure that collaboration invitations are sent to allowed domains only"; Level = "L2" }
    "5.1.6.2" = @{ Title = "Ensure that guest user access is restricted"; Level = "L1" }
    "5.1.6.3" = @{ Title = "Ensure guest user invitations are limited to the Guest Inviter role"; Level = "L2" }
    "5.1.8.1" = @{ Title = "Ensure that password hash sync is enabled for hybrid deployments"; Level = "L1" }
    "5.2.2.1" = @{ Title = "Ensure multifactor authentication is enabled for all users in administrative roles"; Level = "L1" }
    "5.2.2.2" = @{ Title = "Ensure multifactor authentication is enabled for all users"; Level = "L1" }
    "5.2.2.3" = @{ Title = "Enable Conditional Access policies to block legacy authentication"; Level = "L1" }
    "5.2.2.4" = @{ Title = "Ensure Sign-in frequency is enabled and browser sessions are not persistent for Administrative users"; Level = "L1" }
    "5.2.2.5" = @{ Title = "Ensure 'Phishing-resistant MFA strength' is required for Administrators"; Level = "L2" }
    "5.2.2.6" = @{ Title = "Enable Identity Protection user risk policies"; Level = "L1" }
    "5.2.2.7" = @{ Title = "Enable Identity Protection sign-in risk policies"; Level = "L1" }
    "5.2.2.8" = @{ Title = "Ensure 'sign-in risk' is blocked for medium and high risk"; Level = "L2" }
    "5.2.2.9" = @{ Title = "Ensure a managed device is required for authentication"; Level = "L1" }
    "5.2.2.10" = @{ Title = "Ensure a managed device is required to register security information"; Level = "L1" }
    "5.2.2.11" = @{ Title = "Ensure sign-in frequency for Intune Enrollment is set to 'Every time'"; Level = "L1" }
    "5.2.2.12" = @{ Title = "Ensure the device code sign-in flow is blocked"; Level = "L1" }
    "5.2.3.1" = @{ Title = "Ensure Microsoft Authenticator is configured to protect against MFA fatigue"; Level = "L1" }
    "5.2.3.2" = @{ Title = "Ensure custom banned passwords lists are used"; Level = "L1" }
    "5.2.3.3" = @{ Title = "Ensure password protection is enabled for on-prem Active Directory"; Level = "L1" }
    "5.2.3.4" = @{ Title = "Ensure all member users are 'MFA capable'"; Level = "L1" }
    "5.2.3.5" = @{ Title = "Ensure weak authentication methods are disabled"; Level = "L1" }
    "5.2.3.6" = @{ Title = "Ensure system-preferred multifactor authentication is enabled"; Level = "L1" }
    "5.2.3.7" = @{ Title = "Ensure the email OTP authentication method is disabled"; Level = "L2" }
    "5.2.4.1" = @{ Title = "Ensure 'Self service password reset enabled' is set to 'All'"; Level = "L1" }
    "5.3.1" = @{ Title = "Ensure 'Privileged Identity Management' is used to manage roles"; Level = "L2" }
    "5.3.2" = @{ Title = "Ensure 'Access reviews' for Guest Users are configured"; Level = "L1" }
    "5.3.3" = @{ Title = "Ensure 'Access reviews' for privileged roles are configured"; Level = "L1" }
    "5.3.4" = @{ Title = "Ensure approval is required for Global Administrator role activation"; Level = "L1" }
    "5.3.5" = @{ Title = "Ensure approval is required for Privileged Role Administrator activation"; Level = "L1" }
    "6.1.1" = @{ Title = "Ensure 'AuditDisabled' organizationally is set to 'False'"; Level = "L1" }
    "6.1.2" = @{ Title = "Ensure mailbox audit actions are configured"; Level = "L1" }
    "6.1.3" = @{ Title = "Ensure 'AuditBypassEnabled' is not enabled on mailboxes"; Level = "L1" }
    "6.2.1" = @{ Title = "Ensure all forms of mail forwarding are blocked and/or disabled"; Level = "L1" }
    "6.2.2" = @{ Title = "Ensure mail transport rules do not whitelist specific domains"; Level = "L1" }
    "6.2.3" = @{ Title = "Ensure email from external senders is identified"; Level = "L1" }
    "6.3.1" = @{ Title = "Ensure users installing Outlook add-ins is not allowed"; Level = "L2" }
    "6.5.1" = @{ Title = "Ensure modern authentication for Exchange Online is enabled"; Level = "L1" }
    "6.5.2" = @{ Title = "Ensure MailTips are enabled for end users"; Level = "L1" }
    "6.5.3" = @{ Title = "Ensure additional storage providers are restricted in Outlook on the web"; Level = "L2" }
    "6.5.4" = @{ Title = "Ensure SMTP AUTH is disabled"; Level = "L1" }
    "6.5.5" = @{ Title = "Ensure Direct Send submissions are rejected"; Level = "L2" }
    "7.2.1" = @{ Title = "Ensure modern authentication for SharePoint applications is required"; Level = "L1" }
    "7.2.2" = @{ Title = "Ensure SharePoint and OneDrive integration with Azure AD B2B is enabled"; Level = "L1" }
    "7.2.3" = @{ Title = "Ensure external content sharing is restricted"; Level = "L1" }
    "7.2.4" = @{ Title = "Ensure OneDrive content sharing is restricted"; Level = "L2" }
    "7.2.5" = @{ Title = "Ensure that SharePoint guest users cannot share items they don't own"; Level = "L2" }
    "7.2.6" = @{ Title = "Ensure SharePoint external sharing is managed through domain whitelist/blacklists"; Level = "L2" }
    "7.2.7" = @{ Title = "Ensure link sharing is restricted in SharePoint and OneDrive"; Level = "L1" }
    "7.2.8" = @{ Title = "Ensure external sharing is restricted by security group"; Level = "L2" }
    "7.2.9" = @{ Title = "Ensure guest access to a site or OneDrive will expire automatically"; Level = "L1" }
    "7.2.10" = @{ Title = "Ensure reauthentication with verification code is restricted"; Level = "L1" }
    "7.2.11" = @{ Title = "Ensure the SharePoint default sharing link permission is set"; Level = "L1" }
    "7.3.1" = @{ Title = "Ensure Office 365 SharePoint infected files are disallowed for download"; Level = "L2" }
    "7.3.2" = @{ Title = "Ensure OneDrive sync is restricted for unmanaged devices"; Level = "L2" }
    "8.1.1" = @{ Title = "Ensure external file sharing in Teams is enabled for only approved cloud storage services"; Level = "L2" }
    "8.1.2" = @{ Title = "Ensure users can't send emails to a channel email address"; Level = "L1" }
    "8.2.1" = @{ Title = "Ensure external domains are restricted in the Teams admin center"; Level = "L2" }
    "8.2.2" = @{ Title = "Ensure communication with unmanaged Teams users is disabled"; Level = "L1" }
    "8.2.3" = @{ Title = "Ensure external Teams users cannot initiate conversations"; Level = "L1" }
    "8.2.4" = @{ Title = "Ensure communication with Skype users is disabled"; Level = "L1" }
    "8.4.1" = @{ Title = "Ensure app permission policies are configured"; Level = "L1" }
    "8.5.1" = @{ Title = "Ensure anonymous users can't join a meeting"; Level = "L2" }
    "8.5.2" = @{ Title = "Ensure anonymous users and dial-in callers can't start a meeting"; Level = "L1" }
    "8.5.3" = @{ Title = "Ensure only people in my org can bypass the lobby"; Level = "L1" }
    "8.5.4" = @{ Title = "Ensure users dialing in can't bypass the lobby"; Level = "L1" }
    "8.5.5" = @{ Title = "Ensure meeting chat does not allow anonymous users"; Level = "L2" }
    "8.5.6" = @{ Title = "Ensure only organizers and co-organizers can present"; Level = "L2" }
    "8.5.7" = @{ Title = "Ensure external participants can't give or request control"; Level = "L1" }
    "8.5.8" = @{ Title = "Ensure external meeting chat is off"; Level = "L2" }
    "8.5.9" = @{ Title = "Ensure meeting recording is off by default"; Level = "L2" }
    "8.6.1" = @{ Title = "Ensure users can report security concerns in Teams"; Level = "L1" }
    "9.1.1" = @{ Title = "Ensure guest user access is restricted"; Level = "L1" }
    "9.1.2" = @{ Title = "Ensure external user invitations are restricted"; Level = "L1" }
    "9.1.3" = @{ Title = "Ensure guest access to content is restricted"; Level = "L1" }
    "9.1.4" = @{ Title = "Ensure 'Publish to web' is restricted"; Level = "L1" }
    "9.1.5" = @{ Title = "Ensure 'Interact with and share R and Python' visuals is 'Disabled'"; Level = "L2" }
    "9.1.6" = @{ Title = "Ensure 'Allow users to apply sensitivity labels for content' is 'Enabled'"; Level = "L1" }
    "9.1.7" = @{ Title = "Ensure shareable links are restricted"; Level = "L1" }
    "9.1.8" = @{ Title = "Ensure enabling of external data sharing is restricted"; Level = "L1" }
    "9.1.9" = @{ Title = "Ensure 'Block ResourceKey Authentication' is 'Enabled'"; Level = "L1" }
    "9.1.10" = @{ Title = "Ensure access to APIs by Service Principals is restricted"; Level = "L1" }
    "9.1.11" = @{ Title = "Ensure Service Principals cannot create and use profiles"; Level = "L1" }
    "9.1.12" = @{ Title = "Ensure service principals ability to create workspaces, connections and deployment pipelines is restricted"; Level = "L1" }
}

function Add-RegistryResult {
    param(
        [Parameter(Mandatory)][string]$ControlNumber,
        [Parameter(Mandatory)][ValidateSet('Pass','Fail','Manual','Error')][string]$Result,
        [Parameter(Mandatory)][string]$Details,
        [string]$Remediation = ""
    )
    $entry = $Script:ControlRegistry[$ControlNumber]
    if (-not $entry) {
        Write-Log "WARNING: Control $ControlNumber not found in registry" -Level Warning
        return
    }
    Add-Result -ControlNumber $ControlNumber -ControlTitle $entry.Title -ProfileLevel $entry.Level -Result $Result -Details $Details -Remediation $Remediation
}

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

    if ($Script:LogFilePath) {
        try {
            "[$timestamp] [$Level] $Message" | Out-File -FilePath $Script:LogFilePath -Append -Encoding utf8
        }
        catch {
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

    if ($Script:RequestedProfileLevel -ne 'All') {
        if ($ProfileLevel -ne $Script:RequestedProfileLevel) {
            return
        }
    }

    $Script:TotalControls++

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

    $useDeviceAuth = $env:CIS_USE_DEVICE_CODE -eq "true"

    try {
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

        $tenantId = $mgContext.TenantId

        Write-Log "Using authenticated session for remaining services (TenantId: $tenantId)..." -Level Info

        Write-Log "Connecting to Exchange Online..." -Level Info
        Connect-ExchangeOnline -ShowBanner:$false -DisableWAM -ErrorAction Stop
        Write-Log "Connected to Exchange Online" -Level Success

        Write-Log "Connecting to SharePoint Online..." -Level Info
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            if (-not (Get-Module -Name "Microsoft.Online.SharePoint.PowerShell")) {
                Import-Module Microsoft.Online.SharePoint.PowerShell -UseWindowsPowerShell -WarningAction SilentlyContinue -DisableNameChecking -Force
            }
        }
        if ($useDeviceAuth) {
            Connect-SPOService -Url $SharePointAdminUrl -ModernAuth $true -UseSystemBrowser -ErrorAction Stop
        } else {
            Connect-SPOService -Url $SharePointAdminUrl -ModernAuth $true -ErrorAction Stop
        }
        Write-Log "Connected to SharePoint Online" -Level Success

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

    try {
        Write-Log "Checking 1.1.1 - Administrative accounts are cloud-only" -Level Info

        $readOnlyRoleTemplateIds = @(
            "88d8e3e3-8f55-4a1e-953a-9b9898b8876b"
            "f2ef992c-3afb-46b9-b7cf-a126ee74c451"
            "790c1fb9-7f7d-4f88-86a1-ef1f95c05c1b"
            "4a5d8f65-41da-4de4-8968-e035b65339cf"
            "5d6b6bb7-de71-4623-b4af-96380a352509"
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

    try {
        Write-Log "Checking 1.1.2 - Emergency access accounts" -Level Info

        $globalAdminRole = Get-MgDirectoryRole -Filter "DisplayName eq 'Global Administrator'" -ErrorAction Stop
        $globalAdminMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id -ErrorAction Stop

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

        $emergencyAccounts = @()
        foreach ($member in $globalAdminMembers) {
            if ($member.AdditionalProperties.'@odata.type' -ne '#microsoft.graph.user') { continue }
            $user = Get-MgUser -UserId $member.Id -Property Id,UserPrincipalName,DisplayName,OnPremisesSyncEnabled,AccountEnabled -ErrorAction Stop
            if ($user.OnPremisesSyncEnabled -eq $true) { continue }
            if (-not $user.AccountEnabled) { continue }

            $excludedCount = if ($caExcludedUsers.ContainsKey($user.Id)) { $caExcludedUsers[$user.Id] } else { 0 }
            $excludeRatio = if ($enabledPolicyCount -gt 0) { $excludedCount / $enabledPolicyCount } else { 0 }

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

    try {
        Write-Log "Checking 1.1.4 - Admin account license footprint" -Level Info

        $allowedSkus = @(
            "AAD_PREMIUM",
            "AAD_PREMIUM_P2",
            "INTUNE_A",
            "INTUNE_EDU",
            "EMSPREMIUM",
            "EMS",
            "RIGHTSMANAGEMENT",
            "THREAT_INTELLIGENCE",
            "ATP_ENTERPRISE",
            "ATA",
            "ADALLOM_STANDALONE",
            "IDENTITY_THREAT_PROTECTION"
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

    try {
        Write-Log "Checking 1.2.1 - Public groups approval" -Level Info
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

    try {
        Write-Log "Checking 1.3.1 - Password expiration policy" -Level Info
        $defaultDomain = Get-MgDomain -ErrorAction Stop | Where-Object { $_.IsDefault -eq $true } | Select-Object -First 1

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

    try {
        Write-Log "Checking 1.3.2 - Idle session timeout" -Level Info
        $timeoutPolicies = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/policies/activityBasedTimeoutPolicies" -ErrorAction Stop

        if (@($timeoutPolicies.value).Count -gt 0) {
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

    try {
        Write-Log "Checking 1.3.3 - External calendar sharing" -Level Info
        $sharingPolicies = Get-SharingPolicy -ErrorAction Stop
        $externalCalendarEnabled = $false

        foreach ($policy in $sharingPolicies) {
            if ($policy.Enabled -eq $true -and $policy.Domains) {
                foreach ($domain in $policy.Domains) {
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

    try {
        Write-Log "Checking 1.3.4 - User owned apps and services" -Level Info
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

    try {
        Write-Log "Checking 1.3.5 - Forms phishing protection" -Level Info
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

    try {
        Write-Log "Checking 1.3.7 - Third-party storage services" -Level Info
        $m365WebSP = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq 'c1f33bc0-bdb4-4248-ba9b-096807ddb43e'" -ErrorAction Stop

        if (@($m365WebSP.value).Count -eq 0 -or @($m365WebSP.value)[0].accountEnabled -eq $false) {
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

    Add-Result -ControlNumber "1.3.8" -ControlTitle "Ensure that Sways cannot be shared with people outside of your organization" `
               -ProfileLevel "L2" -Result "Manual" -Details "Check M365 Admin Center > Settings > Org Settings > Sway" `
               -Remediation "Disable external Sway sharing"

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

    $cachedMalwareFilterPolicy = $null
    $cachedHostedContentFilterPolicy = $null
    $cachedAcceptedDomains = $null
    $cachedConnectionFilterPolicy = $null
    try { $cachedMalwareFilterPolicy = Get-MalwareFilterPolicy } catch { Write-Log "Warning: Could not retrieve MalwareFilterPolicy. Related checks will report errors." -Level Warning }
    try { $cachedHostedContentFilterPolicy = Get-HostedContentFilterPolicy } catch { Write-Log "Warning: Could not retrieve HostedContentFilterPolicy. Related checks will report errors." -Level Warning }
    try { $cachedConnectionFilterPolicy = Get-HostedConnectionFilterPolicy -Identity Default } catch { Write-Log "Warning: Could not retrieve ConnectionFilterPolicy. Related checks will report errors." -Level Warning }
    try { $cachedAcceptedDomains = Get-AcceptedDomain } catch { Write-Log "Warning: Could not retrieve AcceptedDomain. Related checks will report errors." -Level Warning }

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

    try {
        Write-Log "Checking 2.1.4 - Safe Attachments policy" -Level Info
        $safeAttachmentPolicies = @(Get-SafeAttachmentPolicy)

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

    try {
        Write-Log "Checking 2.1.7 - Anti-phishing policy" -Level Info
        $antiPhishPolicies = @(Get-AntiPhishPolicy)

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

    try {
        Write-Log "Checking 2.1.8 - SPF records" -Level Info
        $acceptedDomains = $cachedAcceptedDomains
        $missingSpf = @()

        foreach ($domain in $acceptedDomains) {
            if ($domain.DomainType -eq "Authoritative") {
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

    try {
        Write-Log "Checking 2.1.9 - DKIM enabled" -Level Info
        $dkimConfigs = Get-DkimSigningConfig
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

    try {
        Write-Log "Checking 2.1.10 - DMARC records" -Level Info
        $acceptedDomains = $cachedAcceptedDomains
        $missingDmarc = @()
        $skippedSubdomains = @()

        $authDomains = @($acceptedDomains | Where-Object {
            $_.DomainType -eq "Authoritative" -and $_.DomainName -notlike "*.onmicrosoft.com"
        })

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
            }
        }

        foreach ($domain in $authDomains) {
            $domainName = $domain.DomainName
            Write-Log "Checking DMARC for $domainName" -Level Info

            $parts = $domainName.Split('.')
            $isSubdomainCovered = $false
            if ($parts.Count -gt 2) {
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

    try {
        Write-Log "Checking 2.1.11 - Comprehensive attachment filtering" -Level Info
        if ($null -eq $cachedMalwareFilterPolicy) { throw "MalwareFilterPolicy data unavailable" }
        $malwarePolicies = $cachedMalwareFilterPolicy

        $requiredBlockedTypes = @('ace','ani','app','docm','exe','jar','reg','scr','vbe','vbs','xlsm')

        $enabledPolicies = @($malwarePolicies | Where-Object { $_.EnableFileFilter -eq $true -and $_.FileTypes })

        if ($enabledPolicies.Count -gt 0) {
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

    Add-Result -ControlNumber "2.2.1" -ControlTitle "Ensure emergency access account activity is monitored" `
               -ProfileLevel "L1" -Result "Manual" -Details "Configure Cloud App Security alerts for emergency account usage" `
               -Remediation "Set up monitoring and alerts for emergency access accounts"

    try {
        Write-Log "Checking 2.4.1 - Priority account protection" -Level Info
        $priorityProtectionEnabled = (Get-EmailTenantSettings -ErrorAction Stop).EnablePriorityAccountProtection
        $priorityAccounts = @(Get-User -IsVIP -ErrorAction Stop)

        if ($priorityProtectionEnabled) {
            if ($priorityAccounts.Count -gt 0) {
                $vipList = ($priorityAccounts | Select-Object -First 5 -ExpandProperty UserPrincipalName) -join "; "
                $suffix = if ($priorityAccounts.Count -gt 5) { " (and $($priorityAccounts.Count - 5) more)" } else { "" }
                Add-Result -ControlNumber "2.4.1" -ControlTitle "Ensure Priority account protection is enabled and configured" `
                           -ProfileLevel "L1" -Result "Pass" -Details "Priority Account Protection is enabled and $($priorityAccounts.Count) priority accounts defined: $vipList$suffix"
            }
            else {
                Add-Result -ControlNumber "2.4.1" -ControlTitle "Ensure Priority account protection is enabled and configured" `
                           -ProfileLevel "L1" -Result "Fail" -Details "Priority Account Protection is enabled but no priority accounts have been defined" `
                           -Remediation "Define priority accounts in M365 Defender portal > Email & collaboration > Priority account protection"
            }
        }
        else {
            Add-Result -ControlNumber "2.4.1" -ControlTitle "Ensure Priority account protection is enabled and configured" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Priority Account Protection is not enabled (EnablePriorityAccountProtection = False)" `
                       -Remediation "Enable priority account protection in M365 Defender portal > Email & collaboration > Priority account protection"
        }
    }
    catch {
        Add-Result -ControlNumber "2.4.1" -ControlTitle "Ensure Priority account protection is enabled and configured" `
                   -ProfileLevel "L1" -Result "Manual" -Details "Unable to check priority account protection: $_" `
                   -Remediation "Verify in M365 Defender portal > Email & collaboration > Priority account protection"
    }

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

    Add-Result -ControlNumber "2.4.3" -ControlTitle "Ensure Microsoft Defender for Cloud Apps is enabled and configured" `
               -ProfileLevel "L2" -Result "Manual" -Details "Verify Defender for Cloud Apps configuration in M365 Defender portal" `
               -Remediation "Enable and configure Microsoft Defender for Cloud Apps"

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

    try {
        Write-Log "Checking 3.2.1 - DLP policies enabled" -Level Info
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
            Add-Result -ControlNumber "3.2.1" -ControlTitle "Ensure DLP policies are enabled" `
                       -ProfileLevel "L1" -Result "Manual" -Details "DLP cmdlets not available. Verify in Microsoft Purview > Data loss prevention" `
                       -Remediation "Connect to Security & Compliance PowerShell or verify DLP policies in Microsoft Purview portal"
        }
    }
    catch {
        Add-Result -ControlNumber "3.2.1" -ControlTitle "Ensure DLP policies are enabled" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

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
            Add-Result -ControlNumber "3.2.2" -ControlTitle "Ensure DLP policies are enabled for Microsoft Teams" `
                       -ProfileLevel "L1" -Result "Manual" -Details "DLP cmdlets not available. Verify in Microsoft Purview > Data loss prevention" `
                       -Remediation "Connect to Security & Compliance PowerShell or verify DLP policies in Microsoft Purview portal"
        }
    }
    catch {
        Add-Result -ControlNumber "3.2.2" -ControlTitle "Ensure DLP policies are enabled for Microsoft Teams" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

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

    try {
        Write-Log "Checking 4.1 - Non-compliant device marking" -Level Info
        $deviceManagementSettings = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/settings" -ErrorAction Stop

        $markAsNonCompliant = $false
        if ($deviceManagementSettings.deviceComplianceCheckinThresholdDays -or $deviceManagementSettings -is [hashtable]) {
            if ($deviceManagementSettings.secureByDefault -eq $true) {
                $markAsNonCompliant = $true
            }
        }

        if (-not $markAsNonCompliant) {
            try {
                $complianceDefaults = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies" -ErrorAction Stop
                $hasCompliancePolicies = @($complianceDefaults.value).Count -gt 0

                if ($hasCompliancePolicies) {
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

    try {
        Write-Log "Checking 4.2 - Personal device enrollment restrictions" -Level Info
        $enrollmentRestrictions = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations" -ErrorAction Stop

        $restrictionPolicies = @($enrollmentRestrictions.value | Where-Object {
            $_.'@odata.type' -eq '#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration'
        })

        if ($restrictionPolicies.Count -gt 0) {
            $personalBlocked = $true
            $platformDetails = @()

            foreach ($policy in $restrictionPolicies) {
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

    $cachedCAPolicies = $null
    $cachedAuthPolicy = $null
    try { $cachedCAPolicies = Get-MgIdentityConditionalAccessPolicy -All } catch { Write-Log "Warning: Could not retrieve Conditional Access policies. Related checks will report errors." -Level Warning }
    try { $cachedAuthPolicy = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop } catch { Write-Log "Warning: Could not retrieve Authorization Policy. Related checks will report errors." -Level Warning }
    $cachedDeviceRegPolicy = $null
    try { $cachedDeviceRegPolicy = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/policies/deviceRegistrationPolicy" -ErrorAction Stop } catch { Write-Log "Warning: Could not retrieve Device Registration Policy. Related checks will report errors." -Level Warning }
    $cachedBetaAuthPolicy = $null
    try { $cachedBetaAuthPolicy = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/policies/authorizationPolicy" -ErrorAction Stop } catch { Write-Log "Warning: Could not retrieve beta Authorization Policy." -Level Warning }

    try {
        Write-Log "Checking 5.1.2.1 - Per-user MFA disabled" -Level Info

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

    try {
        Write-Log "Checking 5.1.2.5 - Stay signed in option hidden" -Level Info

        $kmsiHidden = $false
        $detailMsg = ""

        try {
            $brandingResponse = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/organization/$($(Get-MgOrganization | Select-Object -First 1).Id)/branding" -ErrorAction Stop
            if ($brandingResponse -and $brandingResponse.signInPageText -and $brandingResponse.signInPageText.isKmsiHidden -eq $true) {
                $kmsiHidden = $true
                $detailMsg = "KMSI is hidden via organization branding (signInPageText.isKmsiHidden = true)"
            }
            elseif ($brandingResponse -and $null -ne $brandingResponse.signInPageText) {
                $detailMsg = "KMSI is NOT hidden in organization branding (signInPageText.isKmsiHidden = $($brandingResponse.signInPageText.isKmsiHidden))"
            }
        }
        catch {
            Write-Log "Could not check branding v1.0 endpoint: $_" -Level Warning
        }

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

    try {
        Write-Log "Checking 5.1.3.1 - Dynamic group for guest users" -Level Info
        $guestGroups = Get-MgGroup -Filter "groupTypes/any(c:c eq 'DynamicMembership')" -All -ErrorAction Stop
        $guestDynamicGroup = $null

        foreach ($group in $guestGroups) {
            $groupDetails = Get-MgGroup -GroupId $group.Id -ErrorAction Stop

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

    try {
        Write-Log "Checking 5.1.4.4 - Local admin assignment limited" -Level Info
        if ($null -eq $cachedDeviceRegPolicy) { throw "Device registration policy data unavailable" }
        $registeringUsers = $cachedDeviceRegPolicy.azureADJoin.localAdmins.registeringUsers
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

    try {
        Write-Log "Checking 5.1.4.6 - BitLocker key recovery restricted" -Level Info
        if ($null -eq $cachedBetaAuthPolicy) { throw "Beta authorization policy data unavailable" }
        $bitlockerRestriction = $cachedBetaAuthPolicy.value.defaultUserRolePermissions.allowedToReadBitlockerKeysForOwnedDevice
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

    try {
        Write-Log "Checking 5.1.5.1 - User consent disabled" -Level Info
        if ($null -eq $cachedAuthPolicy) { throw "Authorization policy data unavailable" }
        $authPolicy = $cachedAuthPolicy

        $consentPolicies = $authPolicy.DefaultUserRolePermissions.PermissionGrantPoliciesAssigned


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

    try {
        Write-Log "Checking 5.1.6.2 - Guest user access restricted" -Level Info
        if ($null -eq $cachedAuthPolicy) { throw "Authorization policy data unavailable" }
        $authPolicy = $cachedAuthPolicy

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

    try {
        Write-Log "Checking 5.1.6.3 - Guest inviter role restriction" -Level Info
        if ($null -eq $cachedAuthPolicy) { throw "Authorization policy data unavailable" }
        $authPolicy = $cachedAuthPolicy


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

    try {
        Write-Log "Checking 5.1.8.1 - Password hash sync for hybrid" -Level Info
        $org = Get-MgOrganization -ErrorAction Stop
        $isHybrid = $org.OnPremisesSyncEnabled

        if (-not $isHybrid) {
            Add-Result -ControlNumber "5.1.8.1" -ControlTitle "Ensure that password hash sync is enabled for hybrid deployments" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Cloud-only tenant (no hybrid deployment) - control not applicable"
        }
        else {
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

    Write-Log "Checking Conditional Access policies..." -Level Info

    try {
        Write-Log "Checking 5.2.2.1 - MFA for admin roles" -Level Info
        if ($null -eq $cachedCAPolicies) { throw "Conditional Access policy data unavailable" }
        $caPolicies = $cachedCAPolicies
        $adminMfaPolicy = $null

        $criticalAdminRoles = @(
            "62e90394-69f5-4237-9190-012177145e10",
            "194ae4cb-b126-40b2-bd5b-6091b380977d",
            "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
            "158c047a-c907-4556-b7ef-446551a6b5f7",
            "b0f54661-2d74-4c50-afa3-1ec803f12efe",
            "729827e3-9c14-49f7-bb1b-9608f156bbb8",
            "966707d0-3269-4727-9be2-8c3a10f19b9d",
            "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",
            "e8611ab8-c189-46e8-94e1-60213ab1f814"
        )

        foreach ($policy in $caPolicies) {
            if ($policy.State -eq "enabled" -and
                $policy.Conditions.Users.IncludeRoles -and
                $policy.GrantControls.BuiltInControls -contains "mfa") {

                if ($policy.Conditions.Users.IncludeRoles -contains "All") {
                    $adminMfaPolicy = $policy
                    break
                }

                $includedRoles = $policy.Conditions.Users.IncludeRoles
                $missingRoles = $criticalAdminRoles | Where-Object { $_ -notin $includedRoles }

                if ($missingRoles.Count -eq 0) {
                    $adminMfaPolicy = $policy
                    break
                }
            }
        }

        if ($adminMfaPolicy) {
            $coverageType = if ($adminMfaPolicy.Conditions.Users.IncludeRoles -contains "All") {
                "all directory roles"
            } else {
                "$($adminMfaPolicy.Conditions.Users.IncludeRoles.Count) administrative roles"
            }

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
            $excludedUserCount = if ($allUserMfaPolicy.Conditions.Users.ExcludeUsers) { $allUserMfaPolicy.Conditions.Users.ExcludeUsers.Count } else { 0 }
            $excludedGroupCount = if ($allUserMfaPolicy.Conditions.Users.ExcludeGroups) { $allUserMfaPolicy.Conditions.Users.ExcludeGroups.Count } else { 0 }
            $totalExclusions = $excludedUserCount + $excludedGroupCount

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

    try {
        Write-Log "Checking 5.2.2.3 - Block legacy authentication" -Level Info
        if ($null -eq $cachedCAPolicies) { throw "Conditional Access policy data unavailable" }
        $caPolicies = $cachedCAPolicies
        $legacyAuthBlockPolicy = $null

        $legacyAuthTypes = @("exchangeActiveSync", "other")

        foreach ($policy in $caPolicies) {
            if ($policy.State -eq "enabled" -and
                $policy.GrantControls.BuiltInControls -contains "block") {

                $hasExchangeActiveSync = $policy.Conditions.ClientAppTypes -contains "exchangeActiveSync"
                $hasOther = $policy.Conditions.ClientAppTypes -contains "other"

                if (($hasExchangeActiveSync -and $hasOther) -or
                    ($policy.Conditions.ClientAppTypes.Count -ge 4)) {
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

                $signInFreq = $policy.SessionControls.SignInFrequency
                $isCompliant = $false

                if ($signInFreq.IsEnabled -eq $true) {
                    if ($signInFreq.Type -eq "hours" -and $signInFreq.Value -le 4) {
                        $isCompliant = $true
                    }
                    elseif ($signInFreq.Type -eq "days" -and $signInFreq.Value -eq 1) {
                        $isCompliant = $true
                    }
                    elseif ($signInFreq.FrequencyInterval -eq "everyTime") {
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

    try {
        Write-Log "Checking 5.2.2.5 - Phishing-resistant MFA for admins" -Level Info
        if ($null -eq $cachedCAPolicies) { throw "Conditional Access policy data unavailable" }
        $phishResistantPolicy = $null
        $phishResistantStrengthId = "00000000-0000-0000-0000-000000000004"
        $adminRoleIds = @(
            "62e90394-69f5-4237-9190-012177145e10",
            "e8611ab8-c189-46e8-94e1-60213ab1f814",
            "194ae4cb-b126-40b2-bd5b-6091b380977d",
            "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",
            "29232cdf-9323-42fd-ade2-1d097af3e4de",
            "fe930be7-5e62-47db-91af-98c3a49a38b1",
            "b0f54661-2d74-4c50-afa3-1ec803f12efe"
        )

        foreach ($policy in $cachedCAPolicies) {
            if ($policy.State -ne "enabled") { continue }
            $includeRoles = @($policy.Conditions.Users.IncludeRoles)
            $targetsAdmins = $false
            foreach ($roleId in $adminRoleIds) {
                if ($includeRoles -contains $roleId) { $targetsAdmins = $true; break }
            }
            if (-not $targetsAdmins) { continue }
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

    try {
        Write-Log "Checking 5.2.2.10 - Managed device for MFA registration" -Level Info
        if ($null -eq $cachedCAPolicies) { throw "Conditional Access policy data unavailable" }
        $caPolicies = $cachedCAPolicies

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

    try {
        Write-Log "Checking 5.2.2.11 - Intune enrollment sign-in frequency" -Level Info
        if ($null -eq $cachedCAPolicies) { throw "Conditional Access policy data unavailable" }
        $caPolicies = $cachedCAPolicies

        $intuneEnrollmentPolicy = $caPolicies | Where-Object {
            ($_.Conditions.Applications.IncludeApplications -contains "d4ebce55-015a-49b5-a083-c84d1797ae8c" -or
             $_.Conditions.Applications.IncludeApplications -contains "0000000a-0000-0000-c000-000000000000") -and
            $_.State -eq "enabled" -and
            $_.SessionControls.SignInFrequency -ne $null
        }

        if ($intuneEnrollmentPolicy) {
            $signInFreq = $intuneEnrollmentPolicy.SessionControls.SignInFrequency

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

    try {
        Write-Log "Checking 5.2.2.12 - Device code flow blocked" -Level Info

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


    try {
        Write-Log "Checking 5.2.3.1 - Authenticator MFA fatigue protection" -Level Info
        $authMethodPolicy = Get-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId "MicrosoftAuthenticator" -ErrorAction Stop

        $featureSettings = $authMethodPolicy.AdditionalProperties['featureSettings']

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

        if (-not $numberMatching) {
            $numberMatching = "default (property absent - using Microsoft default)"
        }
        if (-not $additionalContext) { $additionalContext = "not configured" }
        if (-not $locationContext) { $locationContext = "not configured" }

        $numberMatchingCompliant = ($numberMatching -eq "enabled" -or $numberMatching -eq "default" -or $numberMatching -eq "default (property absent - using Microsoft default)")
        $additionalContextCompliant = ($additionalContext -eq "enabled" -or $additionalContext -eq "default")
        $locationContextCompliant = ($locationContext -eq "enabled" -or $locationContext -eq "default")

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

    try {
        Write-Log "Checking 5.2.3.2 - Custom banned passwords" -Level Info

        try {
            $passwordPolicy = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/settings" -ErrorAction SilentlyContinue

            $passwordSetting = $passwordPolicy.value | Where-Object {
                $_.displayName -eq "Password Rule Settings" -or
                $_.templateId -eq "5cf42378-d67d-4f36-ba46-e8b86229381d"
            }

            if ($passwordSetting) {
                $bannedPasswordsValue = $passwordSetting.values | Where-Object { $_.name -eq "BannedPasswordList" }

                if ($bannedPasswordsValue -and $bannedPasswordsValue.value -and $bannedPasswordsValue.value.Trim() -ne "") {
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
                Add-Result -ControlNumber "5.2.3.2" -ControlTitle "Ensure custom banned passwords lists are used" `
                           -ProfileLevel "L1" -Result "Manual" -Details "Unable to verify custom banned password list via API. Please verify manually in Entra ID portal." `
                           -Remediation "Check Entra ID > Security > Authentication methods > Password protection > Custom banned passwords"
            }
        }
        catch {
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

    try {
        Write-Log "Checking 5.2.3.3 - Password protection on-prem AD" -Level Info
        $org = Get-MgOrganization -ErrorAction Stop
        $isHybrid = $org.OnPremisesSyncEnabled

        if (-not $isHybrid) {
            Add-Result -ControlNumber "5.2.3.3" -ControlTitle "Ensure password protection is enabled for on-prem Active Directory" `
                       -ProfileLevel "L1" -Result "Pass" -Details "Cloud-only tenant (no hybrid deployment) - control not applicable"
        }
        else {
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

    try {
        Write-Log "Checking 5.2.3.6 - System-preferred MFA" -Level Info
        $authMethodsPolicy = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy" -ErrorAction Stop

        $systemCredPrefs = $authMethodsPolicy.systemCredentialPreferences

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


    Add-Result -ControlNumber "5.2.4.1" -ControlTitle "Ensure 'Self service password reset enabled' is set to 'All'" `
               -ProfileLevel "L1" -Result "Manual" -Details "Check Entra ID > Password reset > Properties > 'Self service password reset enabled' should be set to 'All'" `
               -Remediation "Navigate to Entra ID > Password reset > Properties and verify 'Self service password reset enabled' is set to 'All' (not 'Selected' or 'None')"


    try {
        Write-Log "Checking 5.3.1 - PIM configured" -Level Info
        $pimRoles = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules"

        if (@($pimRoles.value).Count -gt 0) {
            Add-Result -ControlNumber "5.3.1" -ControlTitle "Ensure 'Privileged Identity Management' is used to manage roles" `
                       -ProfileLevel "L2" -Result "Pass" -Details "PIM role assignments found: $(@($pimRoles.value).Count) eligible assignments"
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

    try {
        Write-Log "Checking 5.3.2 - Guest user access reviews" -Level Info
        $accessReviews = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/identityGovernance/accessReviews/definitions"

        $guestReviews = @($accessReviews.value | Where-Object {
            $_.scope.query -match "userType" -or $_.scope.query -match "guest"
        })

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

    try {
        Write-Log "Checking 5.3.3 - Privileged role access reviews" -Level Info
        $pimAccessReviews = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/identityGovernance/accessReviews/definitions" -ErrorAction SilentlyContinue

        $roleReviews = @($pimAccessReviews.value | Where-Object {
            $_.scope.'@odata.type' -match "principalResourceMembershipsScope" -or
            $_.scope.query -match "roleDefinition"
        })

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

    $cachedOrgConfig = $null
    try { $cachedOrgConfig = Get-OrganizationConfig } catch { Write-Log "Warning: Could not retrieve OrganizationConfig. Related checks will report errors." -Level Warning }

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

    try {
        Write-Log "Checking 6.1.2 - Mailbox audit actions" -Level Info
        if ($null -eq $cachedOrgConfig) { throw "OrganizationConfig data unavailable" }
        $orgConfig = $cachedOrgConfig

        $requiredOwnerActions = @("Create", "HardDelete", "MailboxLogin", "Move", "MoveToDeletedItems", "SoftDelete", "Update")
        $requiredDelegateActions = @("Create", "HardDelete", "Move", "MoveToDeletedItems", "SendAs", "SendOnBehalf", "SoftDelete", "Update")
        $requiredAdminActions = @("Copy", "Create", "HardDelete", "Move", "MoveToDeletedItems", "SendAs", "SendOnBehalf", "SoftDelete", "Update")

        $sampleSize = 50
        $mailboxes = Get-Mailbox -ResultSize $sampleSize | Select-Object UserPrincipalName, AuditEnabled, AuditOwner, AuditDelegate, AuditAdmin, DefaultAuditSet

        $compliantMailboxes = 0
        $nonCompliantDetails = @()

        foreach ($mbx in $mailboxes) {
            if ($mbx.AuditEnabled -eq $true) {
                $defaultSet = @($mbx.DefaultAuditSet)
                $usingOwnerDefaults = $defaultSet -contains "Owner"
                $usingDelegateDefaults = $defaultSet -contains "Delegate"
                $usingAdminDefaults = $defaultSet -contains "Admin"

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

    try {
        Write-Log "Checking 6.1.3 - Mailbox audit bypass" -Level Info
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
            Add-Result -ControlNumber "6.1.3" -ControlTitle "Ensure 'AuditBypassEnabled' is not enabled on mailboxes" `
                       -ProfileLevel "L1" -Result "Manual" -Details "Unable to check audit bypass status. Verify manually in Exchange Admin Center." `
                       -Remediation "Check Exchange Admin Center > Recipients > Mailboxes > Audit settings"
        }
    }
    catch {
        Add-Result -ControlNumber "6.1.3" -ControlTitle "Ensure 'AuditBypassEnabled' is not enabled on mailboxes" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

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

    try {
        Write-Log "Checking 6.5.3 - OWA storage providers restricted" -Level Info

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
    try {
        Write-Log "Checking 6.5.5 - Direct Send submissions rejected" -Level Info
        if ($null -eq $cachedOrgConfig) { throw "OrganizationConfig data unavailable" }
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

    $cachedSPOTenant = $null
    try { $cachedSPOTenant = Get-SPOTenant } catch { Write-Log "Warning: Could not retrieve SPO Tenant configuration. Related checks will report errors." -Level Warning }

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

    try {
        Write-Log "Checking 7.2.3 - External sharing restricted" -Level Info
        if ($null -eq $cachedSPOTenant) { throw "SPO Tenant data unavailable" }
        $spoTenant = $cachedSPOTenant

        $sharingValue = $spoTenant.SharingCapability.ToString().Trim()


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

    try {
        Write-Log "Checking 7.2.4 - OneDrive sharing restricted" -Level Info
        if ($null -eq $cachedSPOTenant) { throw "SPO Tenant data unavailable" }
        $spoTenant = $cachedSPOTenant

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

    try {
        Write-Log "Checking 7.2.7 - Link sharing restricted" -Level Info
        if ($null -eq $cachedSPOTenant) { throw "SPO Tenant data unavailable" }
        $spoTenant = $cachedSPOTenant

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

}

#endregion

#region Section 8: Microsoft Teams Admin Center

function Test-MicrosoftTeams {
    Write-Log "Checking Section 8: Microsoft Teams Admin Center..." -Level Info

    $cachedTeamsMeetingPolicy = $null
    $cachedTenantFedConfig = $null
    $cachedTeamsClientConfig = $null

    Import-Module MicrosoftTeams -Force -ErrorAction SilentlyContinue

    try { $cachedTeamsMeetingPolicy = Get-CsTeamsMeetingPolicy -Identity Global -ErrorAction Stop } catch { Write-Log "Warning: Could not retrieve Teams meeting policy: $_" -Level Warning }
    try { $cachedTenantFedConfig = Get-CsTenantFederationConfiguration -ErrorAction Stop } catch { Write-Log "Warning: Could not retrieve tenant federation configuration: $_" -Level Warning }
    try { $cachedTeamsClientConfig = Get-CsTeamsClientConfiguration -Identity Global -ErrorAction Stop } catch { Write-Log "Warning: Could not retrieve Teams client configuration: $_" -Level Warning }

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

    try {
        Write-Log "Checking 8.2.1 - External domains restricted" -Level Info
        $externalAccessPolicy = Get-CsExternalAccessPolicy -Identity Global -ErrorAction Stop
        if ($null -eq $cachedTenantFedConfig) { throw "Tenant federation configuration data unavailable" }
        $tenantFedConfig = $cachedTenantFedConfig

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
            $isRestricted = $true
            $details = "External access restricted to allowlist ($($tenantFedConfig.AllowedDomains.AllowedDomain.Count) domains)"
        }
        elseif ($tenantFedConfig.BlockedDomains -and
                $tenantFedConfig.BlockedDomains.Count -eq 0 -and
                $tenantFedConfig.AllowPublicUsers -eq $true) {
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

    try {
        Write-Log "Checking 8.2.4 - Skype communication disabled" -Level Info
        if ($null -eq $cachedTenantFedConfig) { throw "Tenant federation configuration data unavailable" }
        $tenantFedConfig = $cachedTenantFedConfig

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

    try {
        Write-Log "Checking 8.4.1 - Teams app permission policies" -Level Info
        $appPermissionPolicies = Get-CsTeamsAppPermissionPolicy -ErrorAction Stop

        $globalPolicy = $appPermissionPolicies | Where-Object { $_.Identity -eq "Global" }

        if ($globalPolicy) {
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
                       -Remediation "Set-CsTeamsMeetingPolicy -Identity Global -AutoAdmittedUsers EveryoneInCompanyExcludingGuests"
        }
    }
    catch {
        Add-Result -ControlNumber "8.5.3" -ControlTitle "Ensure only people in my org can bypass the lobby" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

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
                       -Remediation "Set-CsTeamsMeetingPolicy -Identity Global -MeetingChatEnabledType EnabledExceptAnonymous"
        }
    }
    catch {
        Add-Result -ControlNumber "8.5.5" -ControlTitle "Ensure meeting chat does not allow anonymous users" `
                   -ProfileLevel "L2" -Result "Error" -Details "Error: $_"
    }

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
                       -Remediation "Set-CsTeamsMeetingPolicy -Identity Global -DesignatedPresenterRoleMode OrganizerOnlyUserOverride"
        }
    }
    catch {
        Add-Result -ControlNumber "8.5.6" -ControlTitle "Ensure only organizers and co-organizers can present" `
                   -ProfileLevel "L2" -Result "Error" -Details "Error: $_"
    }

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
                       -Remediation "Set-CsTeamsMeetingPolicy -Identity Global -AllowExternalParticipantGiveRequestControl `$false"
        }
    }
    catch {
        Add-Result -ControlNumber "8.5.7" -ControlTitle "Ensure external participants can't give or request control" `
                   -ProfileLevel "L1" -Result "Error" -Details "Error: $_"
    }

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
                       -Remediation "Set-CsTeamsMeetingPolicy -Identity Global -AllowExternalNonTrustedMeetingChat `$false"
        }
    }
    catch {
        Add-Result -ControlNumber "8.5.8" -ControlTitle "Ensure external meeting chat is off" `
                   -ProfileLevel "L2" -Result "Error" -Details "Error: $_"
    }

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

    function Get-FabricSetting {
        param([string]$SettingName, [array]$Settings, [string]$Title)
        $result = $Settings | Where-Object { $_.settingName -eq $SettingName } | Select-Object -First 1
        if ($null -eq $result -and $Title) {
            $result = $Settings | Where-Object { $_.title -eq $Title } | Select-Object -First 1
        }
        return $result
    }

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

    $logoBase64 = "iVBORw0KGgoAAAANSUhEUgAAAfQAAAH0CAYAAADL1t+KAAAACXBIWXMAAA7DAAAOwwHHb6hkAAAAAXNSR0IArs4c6QAAIABJREFUeF7snQWAVdXa/p91YrpgyJmhG6RDEClFUUJQBBSQDrkYgCAgNYSCooAKoqAoUgIWjYKSgqSkdA0dk0yfWN+3JmTixN6n5pw97/n/v3svc1a87+9dZz97NQN9iAARIAJEgAgQAY8nwDzeA3KACBABIkAEiAARAAk6NQIiQASIABEgAgogQIKugCCSC0SACBABIkAESNCpDRABIkAEiAARUAABEnQFBJFcIAJEgAgQASJAgk5tgAgQASJABIiAAgiQoCsgiOQCESACRIAIEAESdGoDRIAIEAEiQAQUQIAEXQFBJBeIABEgAkSACJCgUxsgAkSACBABIqAAAiToCggiuUAEiAARIAJEgASd2gARIAJEgAgQAQUQIEFXQBDJBSJABIgAESACJOjUBogAESACRIAIKIAACboCgkguEAEiQASIABEgQac2QASIABEgAkRAAQRI0BUQRHKBCBABIkAEiAAJOrUBIkAEiAARIAIKIECCroAgkgtEgAgQASJABEjQqQ0QASJABIgAEVAAARJ0BQSRXCACRIAIEAEiQIJObYAIEAEiQASIgAIIkKArIIjkAhEgAkSACBABEnRqA0SACBABIkAEFECABF0BQSQXiAARIAJEgAiQoFMbIAJEgAgQASKgAAIk6AoIIrlABIgAESACRIAEndoAESACRIAIEAEFECBBV0AQyQUiQASIABEgAiTo1AaIABEgAkSACCiAAAm6AoJILhABIkAEiAARIEGnNkAEiAARIAJEQAEESNAVEERygQgQASJABIgACTq1ASJABIgAESACCiBAgq6AIJILRIAIEAEiQARI0KkNEAEiQASIABFQAAESdAUEkVwgAkSACBABIkCCTm2ACBABIkAEiIACCJCgKyCI5AIRIAJEgAgQARJ0agNEgAgQASJABBRAgARdAUEkF4gAESACRIAIkKBTGyACRIAIEAEioAACJOgKCCK5QASIABEgAkSABJ3aABEgAkSACBABBRAgQVdAEMkFIkAEiAARIAIk6NQGiAARIAJEgAgogAAJugKCSC4QASJABIgAESBBpzZABIgAESACREABBEjQFRBEcoEIEAEiQASIAAk6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"

    $reportPath = Join-Path $OutputPath "CIS-M365-Compliance-Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"

    $mgContext = Get-MgContext
    $currentTenantId = if ($mgContext.TenantId) { $mgContext.TenantId } else { "Unknown" }
    $currentUserAccount = if ($mgContext.Account) { $mgContext.Account } else { "Unknown User" }
    $reportDate = Get-Date -Format "MMMM dd, yyyy HH:mm:ss"

    $safeTenantDomain = Get-HtmlEncoded $TenantDomain
    $safeTenantId = Get-HtmlEncoded $currentTenantId
    $safeUserAccount = Get-HtmlEncoded $currentUserAccount
    $safeReportDate = Get-HtmlEncoded $reportDate

    $passRate = if ($Script:TotalControls -gt 0 -and ($Script:TotalControls - $Script:ManualControls) -gt 0) {
        [math]::Round(($Script:PassedControls / ($Script:TotalControls - $Script:ManualControls)) * 100, 2)
    } else { 0 }

    $l1PassRate = if ($Script:L1TotalControls -gt 0 -and ($Script:L1TotalControls - $Script:L1ManualControls) -gt 0) {
        [math]::Round(($Script:L1PassedControls / ($Script:L1TotalControls - $Script:L1ManualControls)) * 100, 2)
    } else { 0 }

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
           CSS VARIABLES - GLASSMORPHISM THEME
           ========================================================= */
        :root {
            --color-pass: #4ade80;
            --color-fail: #f87171;
            --color-warning: #fbbf24;
            --color-info: #93c5fd;
            --color-l2: #c4b5fd;
            --color-progress: #22c55e;
            --font-sans: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            --transition-speed: 0.3s;

            /* GR IT Services brand colors */
            --gr-red: #e53935;
            --gr-orange: #fb8c00;
            --gr-yellow: #fdd835;
            --gr-green: #43a047;
            --gr-blue: #1e88e5;
            --gr-purple: #8e24aa;
            --gr-gradient: linear-gradient(135deg, #e53935, #fb8c00, #fdd835, #43a047, #1e88e5, #8e24aa);
        }

        /* LIGHT THEME */
        [data-theme="light"] {
            --bg-primary: #e8eaf6;
            --bg-secondary: rgba(255, 255, 255, 0.55);
            --bg-tertiary: rgba(241, 245, 249, 0.6);
            --bg-header: linear-gradient(135deg, #0d1b2a 0%, #1b2838 40%, #162447 100%);
            --text-primary: #0f172a;
            --text-secondary: #475569;
            --text-muted: #64748b;
            --text-header: #ffffff;
            --accent: #1e88e5;
            --accent-light: #42a5f5;
            --border-color: rgba(255, 255, 255, 0.4);
            --border-subtle: rgba(255, 255, 255, 0.2);
            --shadow-sm: 0 1px 2px rgba(0,0,0,0.04);
            --shadow-md: 0 4px 16px rgba(0,0,0,0.08);
            --shadow-lg: 0 8px 32px rgba(0,0,0,0.1);
            --hover-bg: rgba(255, 255, 255, 0.7);
            --input-bg: rgba(255, 255, 255, 0.6);
            --input-border: rgba(0, 0, 0, 0.1);
            --detail-bg: rgba(255, 255, 255, 0.85);
            --detail-border: rgba(0, 0, 0, 0.08);
            --summary-box-bg: rgba(255, 255, 255, 0.5);
            --summary-box-border: rgba(0, 0, 0, 0.1);
            --tooltip-bg: rgba(15, 23, 42, 0.9);
            --tooltip-text: #f1f5f9;
            --tooltip-border: rgba(255,255,255,0.1);
            --glass-bg: rgba(255, 255, 255, 0.45);
            --glass-border: rgba(255, 255, 255, 0.5);
            --glass-shadow: 0 8px 32px rgba(0, 0, 0, 0.08);
            --glass-blur: 16px;
        }

        /* DARK THEME */
        [data-theme="dark"] {
            --bg-primary: #080b14;
            --bg-secondary: rgba(24, 28, 40, 0.6);
            --bg-tertiary: rgba(39, 42, 55, 0.5);
            --bg-header: rgba(12, 15, 25, 0.85);
            --text-primary: #e4e4e7;
            --text-secondary: #a1a1aa;
            --text-muted: #71717a;
            --text-header: #ffffff;
            --accent: #60a5fa;
            --accent-light: #93c5fd;
            --border-color: rgba(255, 255, 255, 0.08);
            --border-subtle: rgba(255, 255, 255, 0.04);
            --shadow-sm: 0 1px 2px rgba(0,0,0,0.3);
            --shadow-md: 0 4px 16px rgba(0,0,0,0.4);
            --shadow-lg: 0 8px 32px rgba(0,0,0,0.5);
            --hover-bg: rgba(255, 255, 255, 0.05);
            --input-bg: rgba(30, 34, 50, 0.7);
            --input-border: rgba(255, 255, 255, 0.08);
            --detail-bg: rgba(20, 24, 38, 0.9);
            --detail-border: rgba(255, 255, 255, 0.06);
            --summary-box-bg: rgba(15, 18, 30, 0.5);
            --summary-box-border: rgba(255, 255, 255, 0.08);
            --tooltip-bg: rgba(15, 18, 30, 0.95);
            --tooltip-text: #e4e4e7;
            --tooltip-border: rgba(255, 255, 255, 0.1);
            --glass-bg: rgba(15, 18, 30, 0.45);
            --glass-border: rgba(255, 255, 255, 0.08);
            --glass-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
            --glass-blur: 20px;
        }

        /* =========================================================
           BASE STYLES & ANIMATED BACKGROUND
           ========================================================= */
        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: var(--font-sans);
            background-color: var(--bg-primary);
            color: var(--text-primary);
            padding-top: 0;
            transition: background-color var(--transition-speed) ease, color var(--transition-speed) ease;
            min-height: 100vh;
            position: relative;
            overflow-x: hidden;
        }

        /* Animated gradient orbs background */
        body::before {
            content: '';
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            z-index: -1;
            background:
                radial-gradient(ellipse 600px 600px at 15% 20%, rgba(229, 57, 53, 0.12) 0%, transparent 70%),
                radial-gradient(ellipse 500px 500px at 85% 25%, rgba(30, 136, 229, 0.12) 0%, transparent 70%),
                radial-gradient(ellipse 550px 550px at 50% 80%, rgba(142, 36, 170, 0.10) 0%, transparent 70%),
                radial-gradient(ellipse 400px 400px at 20% 70%, rgba(67, 160, 71, 0.08) 0%, transparent 70%),
                radial-gradient(ellipse 450px 450px at 80% 75%, rgba(251, 140, 0, 0.08) 0%, transparent 70%);
            animation: orbFloat 20s ease-in-out infinite alternate;
        }

        [data-theme="dark"] body::before {
            background:
                radial-gradient(ellipse 600px 600px at 15% 20%, rgba(229, 57, 53, 0.07) 0%, transparent 70%),
                radial-gradient(ellipse 500px 500px at 85% 25%, rgba(30, 136, 229, 0.07) 0%, transparent 70%),
                radial-gradient(ellipse 550px 550px at 50% 80%, rgba(142, 36, 170, 0.06) 0%, transparent 70%),
                radial-gradient(ellipse 400px 400px at 20% 70%, rgba(67, 160, 71, 0.05) 0%, transparent 70%),
                radial-gradient(ellipse 450px 450px at 80% 75%, rgba(251, 140, 0, 0.05) 0%, transparent 70%);
        }

        @keyframes orbFloat {
            0% { transform: scale(1) translate(0, 0); }
            33% { transform: scale(1.05) translate(20px, -10px); }
            66% { transform: scale(0.98) translate(-15px, 15px); }
            100% { transform: scale(1.02) translate(10px, -5px); }
        }

        .container { max-width: 1400px; margin: 0 auto; }

        /* =========================================================
           GLASSMORPHISM HEADER
           ========================================================= */
        .header {
            background: var(--bg-header);
            backdrop-filter: blur(24px);
            -webkit-backdrop-filter: blur(24px);
            border-bottom: 1px solid rgba(255, 255, 255, 0.08);
            position: sticky;
            top: 0;
            z-index: 1000;
            box-shadow: 0 4px 30px rgba(0, 0, 0, 0.3);
            transition: background var(--transition-speed) ease, box-shadow var(--transition-speed) ease;
        }
        [data-theme="light"] .header {
            box-shadow: 0 4px 30px rgba(0, 0, 0, 0.15);
        }
        .header-container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 14px 40px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .header-left {
            display: flex;
            align-items: center;
            gap: 14px;
        }
        .header h1 {
            font-size: 1.45em;
            font-weight: 700;
            letter-spacing: -0.5px;
            margin: 0;
            color: var(--text-header);
            line-height: 1.2;
        }
        .header-branding {
            font-size: 0.85em;
            font-weight: 700;
            opacity: 0.9;
            letter-spacing: 2px;
            text-transform: uppercase;
            display: block;
            margin-top: 3px;
            background: var(--gr-gradient);
            background-size: 200% 100%;
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            animation: rainbowText 6s linear infinite;
        }
        @keyframes rainbowText {
            0% { background-position: 0% 50%; }
            100% { background-position: 200% 50%; }
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

        /* Rainbow accent line under header */
        .header::after {
            content: '';
            position: absolute;
            bottom: -3px;
            left: 0;
            right: 0;
            height: 3px;
            background: var(--gr-gradient);
            background-size: 200% 100%;
            animation: rainbowSlide 6s linear infinite;
        }
        @keyframes rainbowSlide {
            0% { background-position: 0% 50%; }
            100% { background-position: 200% 50%; }
        }

        .tenant-info {
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 6px 12px;
            border-radius: 10px;
            border: 1px solid rgba(255, 255, 255, 0.12);
            background: rgba(255, 255, 255, 0.06);
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
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
            width: 20px; height: 20px;
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
            backdrop-filter: blur(24px);
            -webkit-backdrop-filter: blur(24px);
            border: 1px solid var(--detail-border);
            border-radius: 16px;
            padding: 12px 16px;
            animation: slideDown 0.3s ease;
            box-shadow: var(--shadow-lg);
            z-index: 1001;
            transition: background var(--transition-speed) ease, border-color var(--transition-speed) ease;
        }
        .header-details-box.expanded { display: block; }
        @keyframes slideDown {
            from { opacity: 0; transform: translateY(-10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .detail-item {
            margin-bottom: 6px;
            padding-bottom: 6px;
            border-bottom: 1px solid var(--detail-border);
        }
        .detail-item:last-child { margin-bottom: 0; padding-bottom: 0; border-bottom: none; }
        .detail-label {
            font-size: 0.8em;
            font-weight: 600;
            margin-bottom: 2px;
        }
        [data-theme="dark"] .detail-label { color: #e4e4e7; }
        [data-theme="light"] .detail-label { color: #0f172a; }
        .detail-value { font-size: 0.75em; color: var(--text-secondary); }
        [data-theme="dark"] .detail-value { color: #9ca3af; }

        /* =========================================================
           THEME TOGGLE
           ========================================================= */
        .theme-toggle {
            position: relative;
            width: 56px; height: 30px;
            background: rgba(255,255,255,0.12);
            border: 1px solid rgba(255,255,255,0.18);
            border-radius: 15px;
            cursor: pointer;
            transition: all 0.3s ease;
            outline: none;
            padding: 0;
            flex-shrink: 0;
        }
        .theme-toggle:hover { background: rgba(255,255,255,0.18); }
        .theme-toggle .toggle-thumb {
            position: absolute;
            top: 3px; left: 3px;
            width: 22px; height: 22px;
            border-radius: 50%;
            background: #ffffff;
            transition: all 0.3s cubic-bezier(0.68, -0.55, 0.265, 1.55);
            display: flex; align-items: center; justify-content: center;
        }
        [data-theme="dark"] .theme-toggle .toggle-thumb { left: 29px; background: #334155; }
        .toggle-thumb::before {
            content: '';
            width: 12px; height: 12px;
            border-radius: 50%;
            background: #f59e0b;
            transition: all 0.3s ease;
        }
        [data-theme="dark"] .toggle-thumb::before {
            width: 10px; height: 10px;
            background: transparent;
            border-radius: 50%;
            box-shadow: inset -4px -2px 0 0 #fbbf24;
        }
        .toggle-thumb::after {
            content: '';
            position: absolute;
            width: 18px; height: 22px;
            border-radius: 50%;
            border: 2px dashed rgba(245,158,11,0.4);
            transition: all 0.3s ease;
        }
        [data-theme="dark"] .toggle-thumb::after { border-color: transparent; width: 0; height: 0; }

        /* =========================================================
           CONTENT & GLASSMORPHISM PANELS
           ========================================================= */
        .content {
            padding: 24px 40px 20px 40px;
            transition: background-color var(--transition-speed) ease;
        }
        h2 {
            color: var(--text-primary);
            margin-top: 30px;
            margin-bottom: 15px;
            transition: color var(--transition-speed) ease;
        }
        h2:first-child { margin-top: 0; margin-bottom: 10px; }

        /* Glass Summary Panel */
        .summary {
            background: var(--glass-bg);
            backdrop-filter: blur(var(--glass-blur));
            -webkit-backdrop-filter: blur(var(--glass-blur));
            padding: 28px 30px;
            border-radius: 20px;
            margin-bottom: 25px;
            border: 1px solid var(--glass-border);
            box-shadow: var(--glass-shadow);
            transition: all var(--transition-speed) ease;
        }

        /* Glass Summary Boxes */
        .summary-box {
            display: inline-block;
            margin: 8px 12px 8px 0;
            padding: 14px 24px;
            border-radius: 14px;
            cursor: pointer;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            background: var(--summary-box-bg);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border: 1px solid var(--glass-border);
            box-shadow: 0 2px 8px rgba(0,0,0,0.06);
        }
        .summary-box:hover {
            transform: translateY(-4px);
            box-shadow: 0 12px 28px rgba(0, 0, 0, 0.15);
            border-color: var(--accent);
        }
        .summary-box.active {
            box-shadow: 0 0 0 2px var(--accent), 0 8px 24px rgba(96, 165, 250, 0.25);
            border-color: var(--accent) !important;
            transform: translateY(-2px);
        }
        .pass { color: var(--color-pass); }
        .fail { color: var(--color-fail); }
        .manual { color: var(--color-warning); }
        .error { color: var(--color-fail); }
        .level-l1 { color: var(--color-info); }
        .level-l2 { color: var(--color-l2); }

        /* Glass Progress Bar */
        .progress-bar {
            width: 100%; height: 34px;
            background: var(--bg-tertiary);
            border-radius: 17px;
            overflow: hidden;
            margin: 15px 0;
            border: 1px solid var(--glass-border);
            transition: background-color var(--transition-speed) ease;
        }
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #22c55e, #4ade80, #86efac);
            background-size: 200% 100%;
            animation: progressShine 3s ease infinite;
            text-align: center;
            line-height: 34px;
            color: #064e3b;
            font-weight: 700;
            font-size: 0.95em;
            border-radius: 17px;
        }
        @keyframes progressShine {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }

        /* Glass Search Box */
        .search-container {
            position: relative;
            margin: 20px 0;
            max-width: 100%;
        }
        #searchBox {
            width: 100%;
            padding: 16px 50px 16px 22px;
            font-size: 16px;
            background: var(--glass-bg);
            backdrop-filter: blur(var(--glass-blur));
            -webkit-backdrop-filter: blur(var(--glass-blur));
            border: 1px solid var(--glass-border);
            border-radius: 14px;
            color: var(--text-primary);
            transition: all 0.3s ease;
            outline: none;
        }
        #searchBox:focus {
            border-color: var(--accent);
            box-shadow: 0 0 0 3px rgba(96, 165, 250, 0.15), 0 8px 24px rgba(0,0,0,0.1);
        }
        #searchBox::placeholder { color: var(--text-muted); }
        .search-icon {
            position: absolute;
            right: 20px; top: 50%;
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

        /* =========================================================
           GLASSMORPHISM TABLE
           ========================================================= */
        table {
            width: 100%;
            border-collapse: separate;
            border-spacing: 0;
            background: var(--glass-bg);
            backdrop-filter: blur(var(--glass-blur));
            -webkit-backdrop-filter: blur(var(--glass-blur));
            border: 1px solid var(--glass-border);
            border-radius: 18px;
            margin-top: 20px;
            overflow: hidden;
            box-shadow: var(--glass-shadow);
            transition: all var(--transition-speed) ease;
        }
        th {
            background: rgba(30, 136, 229, 0.08);
            color: var(--text-primary);
            padding: 14px 16px;
            text-align: left;
            font-weight: 700;
            font-size: 0.85em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border-bottom: 2px solid var(--accent);
            transition: all var(--transition-speed) ease;
        }
        [data-theme="dark"] th { background: rgba(96, 165, 250, 0.06); }
        td {
            padding: 14px 16px;
            border-bottom: 1px solid var(--border-color);
            transition: border-color var(--transition-speed) ease;
        }
        tr { transition: all 0.2s ease; }
        tr:hover { background: var(--hover-bg); }
        tr:last-child td { border-bottom: none; }
        .status-pass { color: var(--color-pass); font-weight: 700; }
        .status-fail { color: var(--color-fail); font-weight: 700; }
        .status-manual { color: var(--color-warning); font-weight: 700; }
        .status-error { color: var(--color-fail); font-weight: 700; }
        .details { font-size: 0.9em; color: var(--text-secondary); }
        .remediation { font-size: 0.85em; color: var(--accent); font-style: italic; margin-top: 5px; }

        /* =========================================================
           FLOATING ACTION BUTTONS - GLASS
           ========================================================= */
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
            width: 56px; height: 56px;
            border-radius: 50%;
            background: rgba(30, 136, 229, 0.2);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            border: 1px solid rgba(255, 255, 255, 0.12);
            display: flex; align-items: center; justify-content: center;
            text-decoration: none;
            font-size: 20px; font-weight: bold;
            color: white;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            box-shadow: 0 4px 16px rgba(0, 0, 0, 0.2);
            position: relative;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        }
        .action-btn:hover {
            transform: scale(1.15);
            box-shadow: 0 8px 32px rgba(96, 165, 250, 0.35);
            border-color: rgba(255, 255, 255, 0.3);
            background: rgba(30, 136, 229, 0.35);
        }
        .action-btn::before {
            content: attr(data-tooltip);
            position: absolute;
            right: 70px;
            background: var(--tooltip-bg);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            color: var(--tooltip-text);
            padding: 8px 14px;
            border-radius: 10px;
            font-size: 13px;
            white-space: nowrap;
            opacity: 0;
            pointer-events: none;
            transition: opacity 0.3s ease;
            border: 1px solid var(--tooltip-border);
            box-shadow: var(--shadow-lg);
        }
        .action-btn:hover::before { opacity: 1; }

        /* =========================================================
           FOOTER - GLASS WITH GR IT BRANDING
           ========================================================= */
        .footer {
            background: var(--glass-bg);
            backdrop-filter: blur(var(--glass-blur));
            -webkit-backdrop-filter: blur(var(--glass-blur));
            color: var(--text-secondary);
            padding: 24px 40px;
            text-align: center;
            border-top: 1px solid var(--glass-border);
            margin-top: 40px;
            font-size: 0.9em;
            transition: all var(--transition-speed) ease;
        }
        .footer p { margin: 0 0 6px 0; }
        .footer a { color: var(--accent); text-decoration: none; transition: color 0.2s; }
        .footer a:hover { text-decoration: underline; color: var(--accent-light); }
        .footer-brand {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            margin-top: 10px;
            padding: 8px 20px;
            border-radius: 12px;
            background: rgba(30, 136, 229, 0.06);
            border: 1px solid rgba(30, 136, 229, 0.12);
            font-weight: 600;
            font-size: 0.95em;
            color: var(--text-primary);
            text-decoration: none;
            transition: all 0.25s ease;
        }
        .footer-brand:hover {
            background: rgba(30, 136, 229, 0.12);
            border-color: rgba(30, 136, 229, 0.25);
            transform: translateY(-1px);
            text-decoration: none;
        }
        .footer-brand img { height: 44px; }

        /* Hidden class for filtering */
        .hidden { display: none !important; }

        /* Print styles */
        @media print {
            * { transition: none !important; animation: none !important; }
            html, body { background: #ffffff !important; color: #0f172a !important; }
            body::before { display: none !important; }
            [data-theme="dark"] {
                --bg-primary: #ffffff; --bg-secondary: #ffffff; --bg-tertiary: #f8fafc;
                --text-primary: #0f172a; --text-secondary: #475569; --text-muted: #64748b;
                --border-color: #e2e8f0; --detail-bg: #f8fafc; --detail-border: #e2e8f0;
                --input-bg: #ffffff; --hover-bg: #f1f5f9;
                --glass-bg: #ffffff; --glass-border: #e2e8f0;
            }
            .theme-toggle, .floating-actions { display: none !important; }
            .summary, table, #searchBox { backdrop-filter: none !important; -webkit-backdrop-filter: none !important; background: #fff !important; }
        }

        @media (max-width: 768px) {
            .header-container { padding: 12px 16px; flex-wrap: wrap; gap: 8px; }
            .header h1 { font-size: 1.1em; }
            .header-branding { font-size: 0.55em; }
            .content { padding: 12px 16px; }
            .summary { padding: 16px; border-radius: 14px; }
            .summary-box { margin: 4px 6px 4px 0; padding: 10px 14px; font-size: 0.9em; }
            .floating-actions { right: 10px; gap: 8px; }
            .action-btn { width: 44px; height: 44px; }
            table { font-size: 0.85em; }
        }

    </style>
</head>
<body>
    <!-- Header -->
    <div class="header">
        <div class="header-container">
            <div class="header-left" style="display:flex;align-items:center;">
                <a href="https://gritservices.ae" target="_blank" style="display:flex;align-items:center;"><img src="data:image/png;base64,$logoBase64" alt="GR IT Services" style="height:80px;margin-right:14px;border-radius:10px;"></a>
                <h1>CIS MICROSOFT 365 FOUNDATIONS BENCHMARK v6.0.0<span class="header-branding">A Product of GR IT Services</span></h1>
            </div>
            <div class="header-right">
                <button class="theme-toggle" id="themeToggle" title="Toggle dark/light mode" aria-label="Toggle theme">
                    <span class="toggle-thumb"></span>
                </button>
                <div class="tenant-info" id="tenantInfo" onclick="toggleHeaderDetails()">
                    <span class="subtitle">Details</span>
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
        <span class="search-icon">&
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
            <a href="https://gritservices.ae" target="_blank" class="action-btn" data-tooltip="GR IT Services">
                <img src="data:image/png;base64,$logoBase64" alt="GR IT Services" style="width:32px;height:32px;border-radius:50%;object-fit:cover;">
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
            <a href="https://gritservices.ae" target="_blank" class="footer-brand">
                <img src="data:image/png;base64,$logoBase64" alt="GR IT Services" style="border-radius:8px;">
                A Product of GR IT Services
            </a>
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

    if (-not (Connect-M365Services)) {
        Write-Log "Failed to connect to Microsoft 365 services. Exiting." -Level Error
        return
    }

    Write-Host "`n"
    Write-Log "Starting CIS compliance checks..." -Level Info
    Write-Host "`n"

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

    Write-Host "`n"
    Write-Log "Generating reports..." -Level Info
    $htmlReport = Export-HtmlReport -OutputPath $OutputPath
    $csvReport = Export-CsvReport -OutputPath $OutputPath

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

    Write-Log "Compliance check complete - Total: $($Script:TotalControls), Pass: $($Script:PassedControls), Fail: $($Script:FailedControls), Manual: $($Script:ManualControls), Error: $($Script:ErrorControls)" -Level Info

    Write-Host "`n"
    Write-Host "Reports saved to:" -ForegroundColor Cyan
    Write-Host "  HTML: $htmlReport" -ForegroundColor White
    Write-Host "  CSV:  $csvReport" -ForegroundColor White
    if ($Script:LogFilePath) {
        Write-Host "  Log:  $($Script:LogFilePath)" -ForegroundColor White
    }
    Write-Host "`n"

    Write-Log "Disconnecting from services..." -Level Info
    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
        Disconnect-SPOService -ErrorAction SilentlyContinue | Out-Null
        Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue | Out-Null
    }
    catch {
    }
    finally {
        if ($env:CIS_USE_DEVICE_CODE) { Remove-Item Env:\CIS_USE_DEVICE_CODE -ErrorAction SilentlyContinue }
        if ($env:AZURE_IDENTITY_DISABLE_MULTITENANTAUTH) { Remove-Item Env:\AZURE_IDENTITY_DISABLE_MULTITENANTAUTH -ErrorAction SilentlyContinue }
    }

    Write-Log "Done!" -Level Success
}

if ($MyInvocation.InvocationName -ne '.' -and $MyInvocation.InvocationName -notlike '*psm1') {
    Start-ComplianceCheck
}

#endregion
