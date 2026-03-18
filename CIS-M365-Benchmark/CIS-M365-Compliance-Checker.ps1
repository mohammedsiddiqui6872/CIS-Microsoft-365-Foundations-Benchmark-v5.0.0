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
        $enabledPolicyCount = @($caPolicies | Where-Object { $_.State -eq 'enabled' }).Count

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
        $globalAdminCount = @($globalAdmins).Count

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

        if (@($adminsWithHeavyLicenses).Count -eq 0) {
            Add-Result -ControlNumber "1.1.4" -ControlTitle "Ensure administrative accounts use licenses with a reduced application footprint" `
                       -ProfileLevel "L1" -Result "Pass" -Details "All $(@($adminUserIds).Count) admin accounts use only reduced-footprint licenses"
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

        if (@($publicGroups).Count -eq 0) {
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

        if (@($enabledSharedMB).Count -eq 0) {
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
        $disabledDkim = @($dkimConfigs | Where-Object { $_.Enabled -eq $false -and $_.Domain -notlike "*.onmicrosoft.com" })

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

        if (@($connectionFilter.IPAllowList).Count -eq 0) {
            Add-Result -ControlNumber "2.1.12" -ControlTitle "Ensure the connection filter IP allow list is not used" `
                       -ProfileLevel "L1" -Result "Pass" -Details "IP allow list is empty"
        }
        else {
            Add-Result -ControlNumber "2.1.12" -ControlTitle "Ensure the connection filter IP allow list is not used" `
                       -ProfileLevel "L1" -Result "Fail" -Details "IP allow list contains $(@($connectionFilter.IPAllowList).Count) entries" `
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

        if (@($policiesWithAllowedItems).Count -eq 0) {
            Add-Result -ControlNumber "2.1.14" -ControlTitle "Ensure inbound anti-spam policies do not contain allowed domains" `
                       -ProfileLevel "L1" -Result "Pass" -Details "No allowed domains/senders configured in anti-spam policies"
        }
        else {
            $failDetails = "Found $totalAllowedDomains allowed domain(s) and $totalAllowedSenders allowed sender(s) across $(@($policiesWithAllowedItems).Count) policy/policies. " +
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
        $errMsg = "$_"
        if ($errMsg -match "couldn't be found" -or $errMsg -match "not found" -or $errMsg -match "does not exist") {
            Add-Result -ControlNumber "2.4.2" -ControlTitle "Ensure Priority accounts have 'Strict protection' presets applied" `
                       -ProfileLevel "L1" -Result "Fail" -Details "Strict Preset Security Policy does not exist in this tenant" `
                       -Remediation "Enable Strict Preset Security Policy and apply to priority accounts in M365 Defender"
        }
        else {
            Add-Result -ControlNumber "2.4.2" -ControlTitle "Ensure Priority accounts have 'Strict protection' presets applied" `
                       -ProfileLevel "L1" -Result "Manual" -Details "Unable to check Strict Preset policy: $_" `
                       -Remediation "Verify strict protection preset is applied to priority accounts in M365 Defender"
        }
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
            $enabledDlpPolicies = @($dlpPolicies | Where-Object { $_.Enabled -eq $true })

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
            $labelPolicies = @(Get-LabelPolicy -ErrorAction Stop)
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
            if (@($perUserMfaUsers).Count -eq 0) {
                Add-Result -ControlNumber "5.1.2.1" -ControlTitle "Ensure 'Per-user MFA' is disabled" `
                           -ProfileLevel "L1" -Result "Pass" -Details "No per-user MFA enabled (use Conditional Access instead)"
            }
            else {
                $sample = ($perUserMfaUsers | Select-Object -First 5 | ForEach-Object { $_.userPrincipalName }) -join ", "
                Add-Result -ControlNumber "5.1.2.1" -ControlTitle "Ensure 'Per-user MFA' is disabled" `
                           -ProfileLevel "L1" -Result "Fail" -Details "$(@($perUserMfaUsers).Count) users have per-user MFA enabled (e.g. $sample)" `
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
        $restrictNonAdmin = $cachedBetaAuthPolicy.value.defaultUserRolePermissions.allowedToReadOtherUsers
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

        if ($consentPolicies -and @($consentPolicies).Count -gt 0) {
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
            $details = if (@($consentPolicies).Count -eq 0) { "User consent disabled (no policies assigned)" } else { "User consent disabled (no consent-enabling policies found)" }
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
                $missingRoles = @($criticalAdminRoles | Where-Object { $_ -notin $includedRoles })

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
                "$(@($adminMfaPolicy.Conditions.Users.IncludeRoles).Count) administrative roles"
            }

            $exclusionWarning = ""
            if ($adminMfaPolicy.Conditions.Users.ExcludeUsers -or $adminMfaPolicy.Conditions.Users.ExcludeRoles) {
                $excludedRoleCount = if ($adminMfaPolicy.Conditions.Users.ExcludeRoles) { @($adminMfaPolicy.Conditions.Users.ExcludeRoles).Count } else { 0 }
                $excludedUserCount = if ($adminMfaPolicy.Conditions.Users.ExcludeUsers) { @($adminMfaPolicy.Conditions.Users.ExcludeUsers).Count } else { 0 }
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
                    $coveredRoles = @($criticalAdminRoles | Where-Object { $_ -in $partialPolicy.Conditions.Users.IncludeRoles })
                    $missingRoles = @($criticalAdminRoles | Where-Object { $_ -notin $partialPolicy.Conditions.Users.IncludeRoles })

                    Add-Result -ControlNumber "5.2.2.1" -ControlTitle "Ensure multifactor authentication is enabled for all users in administrative roles" `
                               -ProfileLevel "L1" -Result "Fail" -Details "CA policy covers only $($coveredRoles.Count) of $(@($criticalAdminRoles).Count) critical admin roles. Missing: $($missingRoles.Count) roles" `
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
            $excludedUserCount = if ($allUserMfaPolicy.Conditions.Users.ExcludeUsers) { @($allUserMfaPolicy.Conditions.Users.ExcludeUsers).Count } else { 0 }
            $excludedGroupCount = if ($allUserMfaPolicy.Conditions.Users.ExcludeGroups) { @($allUserMfaPolicy.Conditions.Users.ExcludeGroups).Count } else { 0 }
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
                    (@($policy.Conditions.ClientAppTypes).Count -ge 4)) {
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
                    $passwordCount = @($passwords).Count
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
        $nonMfaUsers = @($authMethods | Where-Object { $_.IsMfaCapable -eq $false -and $_.UserType -eq "member" })

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
                           -ProfileLevel "L1" -Result "Fail" -Details "$(@($bypassMailboxes).Count) mailboxes have bypass enabled: $mbList" `
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

        if (@($policiesWithStorageProviders).Count -eq 0) {
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
                @($tenantFedConfig.AllowedDomains.AllowedDomain).Count -gt 0) {
            $isRestricted = $true
            $details = "External access restricted to allowlist ($(@($tenantFedConfig.AllowedDomains.AllowedDomain).Count) domains)"
        }
        elseif ($tenantFedConfig.BlockedDomains -and
                @($tenantFedConfig.BlockedDomains).Count -eq 0 -and
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
        elseif ($setting.enabled -eq $true -and $setting.enabledSecurityGroups -and @($setting.enabledSecurityGroups).Count -gt 0) {
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
        elseif ($setting.enabled -eq $true -and $setting.enabledSecurityGroups -and @($setting.enabledSecurityGroups).Count -gt 0) {
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
        elseif ($spSetting.enabled -eq $true -and $spSetting.enabledSecurityGroups -and @($spSetting.enabledSecurityGroups).Count -gt 0) {
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

    $logoBase64 = "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"

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

            /* PowerShellNerd brand colors */
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
                <a href="https://powershellnerd.com" target="_blank" style="display:flex;align-items:center;"><img src="data:image/png;base64,$logoBase64" alt="PowerShellNerd" style="height:80px;margin-right:14px;border-radius:10px;"></a>
                <h1>CIS MICROSOFT 365 FOUNDATIONS BENCHMARK v6.0.0</h1>
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
