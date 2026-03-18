#Requires -Version 5.1

$Script:ComplianceCheckerPath = Join-Path $PSScriptRoot "CIS-M365-Compliance-Checker.ps1"

$Script:PrerequisiteCheckRun = $false

function Script:Install-PrerequisitesAutomatically {
    $requiredModules = @(
        @{ Name = "Microsoft.Graph"; MinVersion = "2.0.0" }
        @{ Name = "ExchangeOnlineManagement"; MinVersion = $null }
        @{ Name = "Microsoft.Online.SharePoint.PowerShell"; MinVersion = $null }
        @{ Name = "MicrosoftTeams"; MinVersion = $null }
    )

    $optionalPBI = Get-Module -ListAvailable -Name MicrosoftPowerBIMgmt.Profile -ErrorAction SilentlyContinue
    if (-not $optionalPBI) {
        Write-Host "[Optional] Installing MicrosoftPowerBIMgmt.Profile for Power BI automation (Section 9)..." -ForegroundColor Cyan
        try {
            Install-Module -Name MicrosoftPowerBIMgmt.Profile -Scope CurrentUser -Force -SkipPublisherCheck -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
            Write-Host "  MicrosoftPowerBIMgmt.Profile installed successfully" -ForegroundColor Green
        }
        catch {
            Write-Host "  [Optional] Could not auto-install MicrosoftPowerBIMgmt.Profile: $_" -ForegroundColor DarkYellow
            Write-Host "  Section 9 (Power BI) controls will remain Manual" -ForegroundColor DarkYellow
        }
    }

    $missing = @()
    $needsUpdate = @()
    $needsImport = @()
    $psVersion = $PSVersionTable.PSVersion.Major

    foreach ($module in $requiredModules) {
        $moduleName = $module.Name
        $minVersion = $module.MinVersion
        $installed = Get-Module -ListAvailable -Name $moduleName | Sort-Object Version -Descending | Select-Object -First 1

        if (-not $installed) {
            $missing += $module
        }
        elseif ($minVersion -and $installed.Version -lt [Version]$minVersion) {
            $needsUpdate += $module
        }
        else {
            if ($moduleName -ne "Microsoft.Graph") {
                $loaded = Get-Module -Name $moduleName
                if (-not $loaded) {
                    $needsImport += $moduleName
                }
            }
        }
    }

    if ($needsUpdate.Count -gt 0) {
        Write-Host ""
        Write-Host "================================================================" -ForegroundColor Yellow
        Write-Host "  CIS M365 Benchmark - Updating Prerequisites" -ForegroundColor Yellow
        Write-Host "================================================================" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Updating $($needsUpdate.Count) outdated module(s)..." -ForegroundColor Yellow
        Write-Host ""

        foreach ($module in $needsUpdate) {
            Write-Host "  Updating $($module.Name)..." -NoNewline -ForegroundColor White

            if ($module.Name -eq "Microsoft.Graph") {
                try {
                    Write-Host ""
                    Write-Host "    Removing outdated Microsoft.Graph versions..." -ForegroundColor Gray
                    Get-InstalledModule -Name "Microsoft.Graph" -AllVersions -ErrorAction SilentlyContinue |
                        Where-Object { $_.Version -lt [Version]"2.0.0" } |
                        ForEach-Object {
                            Write-Host "    Uninstalling v$($_.Version)..." -NoNewline -ForegroundColor Gray
                            Uninstall-Module -Name "Microsoft.Graph" -RequiredVersion $_.Version -Force -ErrorAction SilentlyContinue
                            Write-Host " [OK]" -ForegroundColor Green
                        }

                    Write-Host "    Installing latest Microsoft.Graph..." -NoNewline -ForegroundColor Gray
                    Install-Module -Name "Microsoft.Graph" -Scope CurrentUser -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
                    Write-Host " [OK]" -ForegroundColor Green
                    Write-Host "  Microsoft.Graph update complete" -ForegroundColor Green
                    $needsImport += $module.Name
                }
                catch {
                    Write-Host " [FAILED]: $_" -ForegroundColor Red
                }
            }
            else {
                try {
                    Update-Module -Name $module.Name -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
                    Write-Host " [OK]" -ForegroundColor Green
                    $needsImport += $module.Name
                }
                catch {
                    try {
                        Install-Module -Name $module.Name -Scope CurrentUser -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
                        Write-Host " [REINSTALLED]" -ForegroundColor Green
                        $needsImport += $module.Name
                    }
                    catch {
                        Write-Host " [FAILED]" -ForegroundColor Yellow
                    }
                }
            }
        }
        Write-Host ""
    }

    if ($missing.Count -gt 0) {
        Write-Host ""
        Write-Host "================================================================" -ForegroundColor Cyan
        Write-Host "  CIS M365 Benchmark - Auto-Installing Prerequisites" -ForegroundColor Cyan
        Write-Host "================================================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Installing $($missing.Count) missing module(s)..." -ForegroundColor Yellow
        Write-Host "PowerShell Version: $psVersion" -ForegroundColor Gray
        Write-Host ""

        foreach ($module in $missing) {
            try {
                Write-Host "  Installing $($module.Name)..." -NoNewline -ForegroundColor White
                Install-Module -Name $module.Name -Scope CurrentUser -ErrorAction Stop -WarningAction SilentlyContinue -Repository PSGallery | Out-Null
                Write-Host " [OK]" -ForegroundColor Green
                $needsImport += $module.Name
            }
            catch {
                Write-Host " [FAILED]: $_" -ForegroundColor Red
            }
        }

        Write-Host ""
        Write-Host "================================================================" -ForegroundColor Cyan
        Write-Host "  Installation complete!" -ForegroundColor Cyan
        Write-Host "================================================================" -ForegroundColor Cyan
        Write-Host ""
    }

    if ($needsImport.Count -gt 0) {
        Write-Host "Loading prerequisite modules..." -ForegroundColor Cyan

        foreach ($moduleName in $needsImport) {
            try {
                Write-Host "  Loading $moduleName..." -NoNewline -ForegroundColor Gray
                if ($psVersion -ge 7) {
                    if ($moduleName -eq "Microsoft.Online.SharePoint.PowerShell") {
                        Import-Module -Name $moduleName -UseWindowsPowerShell -ErrorAction Stop -WarningAction SilentlyContinue -DisableNameChecking -Force | Out-Null
                    }
                    else {
                        Import-Module -Name $moduleName -ErrorAction Stop -WarningAction SilentlyContinue -DisableNameChecking -SkipEditionCheck -Force | Out-Null
                    }
                }
                else {
                    Import-Module -Name $moduleName -ErrorAction Stop -WarningAction SilentlyContinue -DisableNameChecking -Force | Out-Null
                }
                Write-Host " [OK]" -ForegroundColor Green
            }
            catch {
                Write-Host " [WARNING]" -ForegroundColor Yellow
            }
        }
        Write-Host ""
    }
}

function Script:Fix-MicrosoftGraphVersion {
    try {
        $graphModule = Get-Module -ListAvailable -Name Microsoft.Graph | Sort-Object Version -Descending | Select-Object -First 1

        if ($graphModule -and $graphModule.Version -lt [Version]"2.0.0") {
            Write-Host ""
            Write-Host "================================================================" -ForegroundColor Yellow
            Write-Host "  Updating Microsoft.Graph to fix authentication issues" -ForegroundColor Yellow
            Write-Host "================================================================" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "Current version: $($graphModule.Version)" -ForegroundColor Gray
            Write-Host "Required version: 2.0.0 or higher" -ForegroundColor Gray
            Write-Host ""
            Write-Host "Updating Microsoft.Graph module..." -ForegroundColor Yellow

            try {
                Get-InstalledModule -Name Microsoft.Graph -AllVersions -ErrorAction SilentlyContinue |
                    Where-Object { $_.Version -lt [Version]"2.0.0" } |
                    ForEach-Object {
                        Write-Host "  Removing old version $($_.Version)..." -NoNewline -ForegroundColor Gray
                        Uninstall-Module -Name Microsoft.Graph -RequiredVersion $_.Version -Force -ErrorAction SilentlyContinue
                        Write-Host " [OK]" -ForegroundColor Green
                    }

                Write-Host "  Installing latest Microsoft.Graph..." -NoNewline -ForegroundColor White
                Install-Module -Name Microsoft.Graph -Scope CurrentUser -ErrorAction Stop -WarningAction SilentlyContinue
                Write-Host " [OK]" -ForegroundColor Green

                Write-Host ""
                Write-Host "================================================================" -ForegroundColor Green
                Write-Host "  Microsoft.Graph updated successfully!" -ForegroundColor Green
                Write-Host "================================================================" -ForegroundColor Green
                Write-Host ""
                Write-Host "Please restart PowerShell and run Invoke-CISM365Benchmark again." -ForegroundColor Yellow
                Write-Host ""
                return $true
            }
            catch {
                Write-Host " [FAILED]" -ForegroundColor Red
                Write-Host ""
                Write-Host "Unable to auto-update Microsoft.Graph. Please update manually:" -ForegroundColor Yellow
                Write-Host "  Install-Module -Name Microsoft.Graph -Scope CurrentUser" -ForegroundColor White
                Write-Host ""
                return $false
            }
        }
    }
    catch {
        Write-Verbose "Error checking Microsoft Graph version: $_"
    }
    return $false
}


function Connect-CISM365Benchmark {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string[]]$Scopes = @(
            "Organization.Read.All",
            "Directory.Read.All",
            "Policy.Read.All",
            "UserAuthenticationMethod.Read.All",
            "RoleManagement.Read.All",
            "User.Read.All",
            "Group.Read.All",
            "Application.Read.All",
            "DeviceManagementConfiguration.Read.All",
            "DeviceManagementServiceConfig.Read.All",
            "OrgSettings-AppsAndServices.Read.All",
            "OrgSettings-Forms.Read.All"
        ),

        [switch]$UseDeviceCode
    )

    if (-not $Script:PrerequisiteCheckRun) {
        Script:Install-PrerequisitesAutomatically
        $Script:PrerequisiteCheckRun = $true
    }

    Write-Host "`nConnecting to Microsoft Graph" -ForegroundColor Yellow

    try {
        if (-not (Get-Module -Name Microsoft.Graph.Authentication)) {
            Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
        }

        $currentContext = $null
        try { $currentContext = Get-MgContext } catch { Write-Verbose "No existing Graph context found" }
        if ($currentContext -and $currentContext.TenantId) {
            Write-Host "Already connected to Microsoft Graph" -ForegroundColor Green
            Write-Host "  Tenant ID: $($currentContext.TenantId)" -ForegroundColor White
            Write-Host "  Account: $($currentContext.Account)" -ForegroundColor White

            $currentScopes = if ($null -ne $currentContext.Scopes) { $currentContext.Scopes } else { @() }
            $missingScopes = $Scopes | Where-Object { $_ -notin $currentScopes }
            if ($missingScopes) {
                Write-Host "`nMissing required scopes. Reconnecting..." -ForegroundColor Yellow
            } else {
                Write-Host "`nYou can now run: Invoke-CISM365Benchmark`n" -ForegroundColor Yellow
                return $currentContext
            }
        }

        $params = @{
            Scopes        = $Scopes
            NoWelcome     = $true
            ContextScope  = 'Process'
        }

        if ($PSVersionTable.PSVersion.Major -ge 7) {
            Write-Host "PowerShell 7+ detected" -ForegroundColor Cyan

            if ($UseDeviceCode) {
                $env:CIS_USE_DEVICE_CODE = "true"
            }

            Write-Host "Configuring authentication for PowerShell 7 compatibility..." -ForegroundColor Yellow

            $env:AZURE_IDENTITY_DISABLE_MULTITENANTAUTH = "true"

            if ($UseDeviceCode) {
                $authMethods = @(
                    @{
                        Name = "Device Code"
                        Params = @{
                            Scopes = $Scopes
                            NoWelcome = $true
                            UseDeviceCode = $true
                        }
                    }
                )
            } else {
                $authMethods = @(
                    @{
                        Name = "Interactive Browser"
                        Params = @{
                            Scopes = $Scopes
                            NoWelcome = $true
                        }
                    },
                    @{
                        Name = "Web Account Manager"
                        Params = @{
                            Scopes = $Scopes
                            NoWelcome = $true
                        }
                    },
                    @{
                        Name = "Minimal Parameters"
                        Params = @{
                            Scopes = $Scopes
                        }
                    }
                )
            }

            $connected = $false
            foreach ($method in $authMethods) {
                if ($connected) { break }

                try {
                    Write-Host "Trying $($method.Name) authentication..." -ForegroundColor Yellow
                    $methodParams = $method.Params
                    Connect-MgGraph @methodParams -ErrorAction Stop
                    $connected = $true
                }
                catch {
                    Write-Verbose "Failed with $($method.Name): $_"
                }
            }

            if (-not $connected) {
                Write-Host "`n⚠ PowerShell 7 Authentication Issue Detected" -ForegroundColor Yellow
                Write-Host "This is a known compatibility issue with Microsoft.Graph module in PowerShell 7." -ForegroundColor Yellow
                Write-Host "`nWorkarounds:" -ForegroundColor Cyan
                Write-Host "1. Use PowerShell 5.1 instead (recommended):" -ForegroundColor White
                Write-Host "   powershell.exe -Command `"Import-Module CIS-M365-Benchmark; Connect-CISM365Benchmark`"" -ForegroundColor Gray
                Write-Host "`n2. Or manually authenticate first:" -ForegroundColor White
                Write-Host "   Connect-MgGraph -Scopes 'Directory.Read.All','Policy.Read.All','User.Read.All'" -ForegroundColor Gray
                Write-Host "   Then run: Invoke-CISM365Benchmark" -ForegroundColor Gray

                throw "Unable to authenticate with Microsoft Graph in PowerShell 7. See workarounds above."
            }
        }
        else {
            if ($UseDeviceCode) {
                $params['UseDeviceCode'] = $true
                $env:CIS_USE_DEVICE_CODE = "true"
            }
            Connect-MgGraph @params
        }

        $context = Get-MgContext

        if ($context -and $context.TenantId) {
            Write-Host "`nSuccessfully connected to Microsoft Graph!" -ForegroundColor Green
            Write-Host "  Tenant ID: $($context.TenantId)" -ForegroundColor White
            Write-Host "  Account: $($context.Account)" -ForegroundColor White
            Write-Host "`nYou can now run: Invoke-CISM365Benchmark`n" -ForegroundColor Yellow
            return $context
        }
        else {
            throw "Connection established but unable to retrieve context"
        }
    }
    catch [Management.Automation.CommandNotFoundException] {
        Write-Host "`nThe Microsoft Graph PowerShell module is not installed." -ForegroundColor Red
        Write-Host "Please install it using: Install-Module Microsoft.Graph -Scope CurrentUser`n" -ForegroundColor Yellow
        throw
    }
    catch {
        Write-Host "`nFailed to connect to Microsoft Graph" -ForegroundColor Red
        Write-Host "Error: $_`n" -ForegroundColor Red
        throw
    }
}

function Invoke-CISM365Benchmark {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory=$false, Position=0, HelpMessage="Your M365 tenant domain (e.g., contoso.onmicrosoft.com). If not provided, will be auto-detected.")]
        [string]$TenantDomain,

        [Parameter(Mandatory=$false, Position=1, HelpMessage="SharePoint admin URL (e.g., https://contoso-admin.sharepoint.com). If not provided, will be auto-detected.")]
        [ValidatePattern('^https://.*-admin\.sharepoint\.(com|us|de|cn)/?$')]
        [string]$SharePointAdminUrl,

        [Parameter(Mandatory=$false)]
        [ValidateScript({Test-Path -Path $_ -PathType Container -IsValid})]
        [string]$OutputPath = ".",

        [Parameter(Mandatory=$false)]
        [ValidateSet('L1','L2','All')]
        [string]$ProfileLevel = 'All',

        [Parameter(Mandatory=$false, HelpMessage="Sections to exclude from the benchmark run. Valid values: AdminCenter, Defender, Purview, Intune, EntraID, Exchange, SharePoint, Teams, PowerBI")]
        [ValidateSet('AdminCenter','Defender','Purview','Intune','EntraID','Exchange','SharePoint','Teams','PowerBI')]
        [string[]]$ExcludeSections = @()
    )

    begin {
        Write-Verbose "Starting CIS Microsoft 365 Foundations Benchmark v6.0.0 Compliance Check"

        if ([string]::IsNullOrEmpty($TenantDomain) -or [string]::IsNullOrEmpty($SharePointAdminUrl)) {
            Write-Host ""
            Write-Host "================================================================" -ForegroundColor Cyan
            Write-Host "  Auto-Detecting Microsoft 365 Tenant Information" -ForegroundColor Cyan
            Write-Host "================================================================" -ForegroundColor Cyan
            Write-Host ""

            try {
                Write-Host "Checking Microsoft Graph connection..." -ForegroundColor Gray
                $graphContext = $null
                try { $graphContext = Get-MgContext } catch { Write-Verbose "No existing Graph context" }

                if (-not $graphContext) {
                    Write-Host ""
                    Write-Host "Not authenticated to Microsoft Graph." -ForegroundColor Yellow
                    Write-Host ""
                    Write-Host "Please run: Connect-CISM365Benchmark" -ForegroundColor Cyan
                    Write-Host ""
                    Write-Host "Attempting automatic authentication..." -ForegroundColor Yellow

                    try {
                        Connect-MgGraph -Scopes "Organization.Read.All","Directory.Read.All","Policy.Read.All","UserAuthenticationMethod.Read.All","RoleManagement.Read.All","User.Read.All","Group.Read.All","Application.Read.All","DeviceManagementConfiguration.Read.All","DeviceManagementServiceConfig.Read.All","OrgSettings-AppsAndServices.Read.All","OrgSettings-Forms.Read.All" -ErrorAction Stop | Out-Null
                        $graphContext = Get-MgContext
                        Write-Host "Authentication successful!" -ForegroundColor Green
                    }
                    catch {
                        Write-Host ""
                        Write-Host "================================================================" -ForegroundColor Red
                        Write-Host "  Authentication Failed" -ForegroundColor Red
                        Write-Host "================================================================" -ForegroundColor Red
                        Write-Host ""
                        Write-Host "Please authenticate first by running:" -ForegroundColor Yellow
                        Write-Host "  Connect-CISM365Benchmark" -ForegroundColor Cyan
                        Write-Host ""
                        Write-Host "Or provide tenant information manually:" -ForegroundColor Yellow
                        Write-Host "  Invoke-CISM365Benchmark -TenantDomain 'tenant.onmicrosoft.com' -SharePointAdminUrl 'https://tenant-admin.sharepoint.com'" -ForegroundColor Cyan
                        Write-Host ""
                        throw "Authentication required. Run Connect-CISM365Benchmark first or provide tenant parameters manually."
                    }
                }
                else {
                    Write-Host "Using existing Microsoft Graph connection" -ForegroundColor Green
                    Write-Host "  Account: $($graphContext.Account)" -ForegroundColor Gray
                }

                Write-Host "Retrieving tenant information..." -ForegroundColor Gray
                $orgDetails = Get-MgOrganization -ErrorAction Stop | Select-Object -First 1

                if ([string]::IsNullOrEmpty($TenantDomain)) {
                    $verifiedDomains = $orgDetails.VerifiedDomains | Where-Object { $_.Name -like "*.onmicrosoft.com" }
                    if ($verifiedDomains) {
                        $TenantDomain = @($verifiedDomains)[0].Name
                    } else {
                        $TenantDomain = @($orgDetails.VerifiedDomains)[0].Name
                    }
                    Write-Host "  Detected Tenant Domain: $TenantDomain" -ForegroundColor Green
                }

                if ([string]::IsNullOrEmpty($SharePointAdminUrl)) {
                    $tenantName = $TenantDomain.Split('.')[0]
                    $SharePointAdminUrl = "https://$tenantName-admin.sharepoint.com"
                    Write-Host "  Detected SharePoint Admin URL: $SharePointAdminUrl" -ForegroundColor Green
                }

                Write-Host ""
            }
            catch {
                Write-Host ""
                Write-Host "Failed to auto-detect tenant information: $_" -ForegroundColor Red
                Write-Host ""
                Write-Host "Please authenticate first:" -ForegroundColor Yellow
                Write-Host "  Connect-CISM365Benchmark" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "Or provide the tenant information manually:" -ForegroundColor Yellow
                Write-Host "  Invoke-CISM365Benchmark -TenantDomain 'tenant.onmicrosoft.com' -SharePointAdminUrl 'https://tenant-admin.sharepoint.com'" -ForegroundColor Cyan
                Write-Host ""
                throw "Auto-detection failed. Run Connect-CISM365Benchmark or provide tenant parameters manually."
            }
        }

        Write-Verbose "Tenant: $TenantDomain"
        Write-Verbose "SharePoint URL: $SharePointAdminUrl"
        Write-Verbose "Profile Level: $ProfileLevel"

        $graphFixed = Script:Fix-MicrosoftGraphVersion
        if ($graphFixed) {
            Write-Host "Microsoft.Graph has been updated. Please restart PowerShell and run this command again." -ForegroundColor Yellow
            return
        }

        if (-not (Test-Path -Path $OutputPath)) {
            Write-Verbose "Creating output directory: $OutputPath"
            New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
        }
    }

    process {
        try {
            $cleanSharePointUrl = $SharePointAdminUrl.TrimEnd('/')

            $scriptParams = @{
                TenantDomain = $TenantDomain
                SharePointAdminUrl = $cleanSharePointUrl
                OutputPath = $OutputPath
                ProfileLevel = $ProfileLevel
                ExcludeSections = $ExcludeSections
            }

            Write-Verbose "Executing CIS compliance checker script..."

            if (-not (Test-Path -Path $Script:ComplianceCheckerPath)) {
                throw "Compliance checker script not found at: $($Script:ComplianceCheckerPath). Please reinstall the module."
            }

            & $Script:ComplianceCheckerPath @scriptParams

            Write-Verbose "Generating summary report..."

            $htmlReport = Get-ChildItem -Path $OutputPath -Filter "CIS-M365-Compliance-Report_*.html" -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending |
                Select-Object -First 1

            $csvReport = Get-ChildItem -Path $OutputPath -Filter "CIS-M365-Compliance-Report_*.csv" -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending |
                Select-Object -First 1

            if ($csvReport) {
                $reportData = Import-Csv -Path $csvReport.FullName
                $passed = @($reportData | Where-Object { $_.Result -eq 'Pass' }).Count
                $failed = @($reportData | Where-Object { $_.Result -eq 'Fail' }).Count
                $manual = @($reportData | Where-Object { $_.Result -eq 'Manual' }).Count
                $errors = @($reportData | Where-Object { $_.Result -eq 'Error' }).Count
                $total = @($reportData).Count

                $complianceRate = if ($total -gt 0 -and ($total - $manual) -gt 0) {
                    [math]::Round(($passed / ($total - $manual)) * 100, 2)
                } else {
                    0
                }

                $summary = [PSCustomObject]@{
                    TenantDomain = $TenantDomain
                    ProfileLevel = $ProfileLevel
                    TotalControls = $total
                    Passed = $passed
                    Failed = $failed
                    Manual = $manual
                    Errors = $errors
                    ComplianceRate = $complianceRate
                    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    HtmlReport = if ($htmlReport) { $htmlReport.FullName } else { $null }
                    CsvReport = if ($csvReport) { $csvReport.FullName } else { $null }
                }

                return $summary
            }
            else {
                Write-Warning "No CSV report found. Check output path: $OutputPath"
            }

        }
        catch {
            Write-Error "Failed to execute CIS benchmark: $_"
            throw
        }
    }

    end {
        Write-Verbose "CIS benchmark check completed"
    }
}

function Get-CISM365BenchmarkControl {
    [CmdletBinding(DefaultParameterSetName='All')]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(ParameterSetName='ByControl', Position=0)]
        [string[]]$ControlNumber,

        [Parameter(ParameterSetName='BySection')]
        [ValidateSet('1','2','3','4','5','6','7','8','9')]
        [string]$Section,

        [Parameter()]
        [ValidateSet('L1','L2','All')]
        [string]$ProfileLevel = 'All'
    )

    $controls = @(
        [PSCustomObject]@{ControlNumber="1.1.1"; Title="Ensure Administrative accounts are cloud-only"; Section="1"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="1.1.2"; Title="Ensure two emergency access accounts have been defined"; Section="1"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="1.1.3"; Title="Ensure that between two and four global admins are designated"; Section="1"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="1.1.4"; Title="Ensure administrative accounts use licenses with a reduced application footprint"; Section="1"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="1.2.1"; Title="Ensure that only organizationally managed/approved public groups exist"; Section="1"; ProfileLevel="L2"; Automated=$true}
        [PSCustomObject]@{ControlNumber="1.2.2"; Title="Ensure sign-in to shared mailboxes is blocked"; Section="1"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="1.3.1"; Title="Ensure the 'Password expiration policy' is set to 'Set passwords to never expire'"; Section="1"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="1.3.2"; Title="Ensure 'Idle session timeout' is set to '3 hours (or less)' for unmanaged devices"; Section="1"; ProfileLevel="L2"; Automated=$true}
        [PSCustomObject]@{ControlNumber="1.3.3"; Title="Ensure 'External sharing' of calendars is not available"; Section="1"; ProfileLevel="L2"; Automated=$false}
        [PSCustomObject]@{ControlNumber="1.3.4"; Title="Ensure 'User owned apps and services' is restricted"; Section="1"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="1.3.5"; Title="Ensure internal phishing protection for Forms is enabled"; Section="1"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="1.3.6"; Title="Ensure the customer lockbox feature is enabled"; Section="1"; ProfileLevel="L2"; Automated=$false}
        [PSCustomObject]@{ControlNumber="1.3.7"; Title="Ensure 'third-party storage services' are restricted in 'Microsoft 365 on the web'"; Section="1"; ProfileLevel="L2"; Automated=$true}
        [PSCustomObject]@{ControlNumber="1.3.8"; Title="Ensure that Sways cannot be shared with people outside of your organization"; Section="1"; ProfileLevel="L2"; Automated=$false}
        [PSCustomObject]@{ControlNumber="1.3.9"; Title="Ensure shared bookings pages are restricted to select users"; Section="1"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="2.1.1"; Title="Ensure Safe Links for Office Applications is Enabled"; Section="2"; ProfileLevel="L2"; Automated=$true}
        [PSCustomObject]@{ControlNumber="2.1.2"; Title="Ensure the Common Attachment Types Filter is enabled"; Section="2"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="2.1.3"; Title="Ensure notifications for internal users sending malware is Enabled"; Section="2"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="2.1.4"; Title="Ensure Safe Attachments policy is enabled"; Section="2"; ProfileLevel="L2"; Automated=$true}
        [PSCustomObject]@{ControlNumber="2.1.5"; Title="Ensure Safe Attachments for SharePoint, OneDrive, and Microsoft Teams is Enabled"; Section="2"; ProfileLevel="L2"; Automated=$true}
        [PSCustomObject]@{ControlNumber="2.1.6"; Title="Ensure Exchange Online Spam Policies are set to notify administrators"; Section="2"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="2.1.7"; Title="Ensure that an anti-phishing policy has been created"; Section="2"; ProfileLevel="L2"; Automated=$true}
        [PSCustomObject]@{ControlNumber="2.1.8"; Title="Ensure that SPF records are published for all Exchange Domains"; Section="2"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="2.1.9"; Title="Ensure that DKIM is enabled for all Exchange Online Domains"; Section="2"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="2.1.10"; Title="Ensure DMARC Records for all Exchange Online domains are published"; Section="2"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="2.1.11"; Title="Ensure comprehensive attachment filtering is applied"; Section="2"; ProfileLevel="L2"; Automated=$true}
        [PSCustomObject]@{ControlNumber="2.1.12"; Title="Ensure the connection filter IP allow list is not used"; Section="2"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="2.1.13"; Title="Ensure the connection filter safe list is off"; Section="2"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="2.1.14"; Title="Ensure inbound anti-spam policies do not contain allowed domains"; Section="2"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="2.1.15"; Title="Ensure outbound anti-spam message limits are in place"; Section="2"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="2.2.1"; Title="Ensure emergency access account activity is monitored"; Section="2"; ProfileLevel="L1"; Automated=$false}
        [PSCustomObject]@{ControlNumber="2.4.1"; Title="Ensure Priority account protection is enabled and configured"; Section="2"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="2.4.2"; Title="Ensure Priority accounts have 'Strict protection' presets applied"; Section="2"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="2.4.3"; Title="Ensure Microsoft Defender for Cloud Apps is enabled and configured"; Section="2"; ProfileLevel="L2"; Automated=$false}
        [PSCustomObject]@{ControlNumber="2.4.4"; Title="Ensure Zero-hour auto purge for Microsoft Teams is on"; Section="2"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="3.1.1"; Title="Ensure Microsoft 365 audit log search is Enabled"; Section="3"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="3.2.1"; Title="Ensure DLP policies are enabled"; Section="3"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="3.2.2"; Title="Ensure DLP policies are enabled for Microsoft Teams"; Section="3"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="3.3.1"; Title="Ensure Information Protection sensitivity label policies are published"; Section="3"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="4.1"; Title="Ensure devices without a compliance policy are marked 'not compliant'"; Section="4"; ProfileLevel="L2"; Automated=$true}
        [PSCustomObject]@{ControlNumber="4.2"; Title="Ensure device enrollment for personally owned devices is blocked by default"; Section="4"; ProfileLevel="L2"; Automated=$true}
        [PSCustomObject]@{ControlNumber="5.1.2.1"; Title="Ensure 'Per-user MFA' is disabled"; Section="5"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="5.1.2.2"; Title="Ensure third party integrated applications are not allowed"; Section="5"; ProfileLevel="L2"; Automated=$true}
        [PSCustomObject]@{ControlNumber="5.1.2.3"; Title="Ensure 'Restrict non-admin users from creating tenants' is set to 'Yes'"; Section="5"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="5.1.2.4"; Title="Ensure access to the Entra admin center is restricted"; Section="5"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="5.1.2.5"; Title="Ensure the option to remain signed in is hidden"; Section="5"; ProfileLevel="L2"; Automated=$true}
        [PSCustomObject]@{ControlNumber="5.1.2.6"; Title="Ensure 'LinkedIn account connections' is disabled"; Section="5"; ProfileLevel="L2"; Automated=$true}
        [PSCustomObject]@{ControlNumber="5.1.3.1"; Title="Ensure a dynamic group for guest users is created"; Section="5"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="5.1.3.2"; Title="Ensure users cannot create security groups"; Section="5"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="5.1.4.1"; Title="Ensure the ability to join devices to Entra is restricted"; Section="5"; ProfileLevel="L2"; Automated=$true}
        [PSCustomObject]@{ControlNumber="5.1.4.2"; Title="Ensure the maximum number of devices per user is limited"; Section="5"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="5.1.4.3"; Title="Ensure the GA role is not added as a local administrator during Entra join"; Section="5"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="5.1.4.4"; Title="Ensure local administrator assignment is limited during Entra join"; Section="5"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="5.1.4.5"; Title="Ensure Local Administrator Password Solution is enabled"; Section="5"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="5.1.4.6"; Title="Ensure users are restricted from recovering BitLocker keys"; Section="5"; ProfileLevel="L2"; Automated=$true}
        [PSCustomObject]@{ControlNumber="5.1.5.1"; Title="Ensure user consent to apps accessing company data on their behalf is not allowed"; Section="5"; ProfileLevel="L2"; Automated=$true}
        [PSCustomObject]@{ControlNumber="5.1.5.2"; Title="Ensure the admin consent workflow is enabled"; Section="5"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="5.1.6.1"; Title="Ensure that collaboration invitations are sent to allowed domains only"; Section="5"; ProfileLevel="L2"; Automated=$true}
        [PSCustomObject]@{ControlNumber="5.1.6.2"; Title="Ensure that guest user access is restricted"; Section="5"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="5.1.6.3"; Title="Ensure guest user invitations are limited to the Guest Inviter role"; Section="5"; ProfileLevel="L2"; Automated=$true}
        [PSCustomObject]@{ControlNumber="5.1.8.1"; Title="Ensure that password hash sync is enabled for hybrid deployments"; Section="5"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="5.2.2.1"; Title="Ensure multifactor authentication is enabled for all users in administrative roles"; Section="5"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="5.2.2.2"; Title="Ensure multifactor authentication is enabled for all users"; Section="5"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="5.2.2.3"; Title="Enable Conditional Access policies to block legacy authentication"; Section="5"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="5.2.2.4"; Title="Ensure Sign-in frequency is enabled and browser sessions are not persistent for Administrative users"; Section="5"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="5.2.2.5"; Title="Ensure 'Phishing-resistant MFA strength' is required for Administrators"; Section="5"; ProfileLevel="L2"; Automated=$true}
        [PSCustomObject]@{ControlNumber="5.2.2.6"; Title="Enable Identity Protection user risk policies"; Section="5"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="5.2.2.7"; Title="Enable Identity Protection sign-in risk policies"; Section="5"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="5.2.2.8"; Title="Ensure 'sign-in risk' is blocked for medium and high risk"; Section="5"; ProfileLevel="L2"; Automated=$true}
        [PSCustomObject]@{ControlNumber="5.2.2.9"; Title="Ensure a managed device is required for authentication"; Section="5"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="5.2.2.10"; Title="Ensure a managed device is required to register security information"; Section="5"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="5.2.2.11"; Title="Ensure sign-in frequency for Intune Enrollment is set to 'Every time'"; Section="5"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="5.2.2.12"; Title="Ensure the device code sign-in flow is blocked"; Section="5"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="5.2.3.1"; Title="Ensure Microsoft Authenticator is configured to protect against MFA fatigue"; Section="5"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="5.2.3.2"; Title="Ensure custom banned passwords lists are used"; Section="5"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="5.2.3.3"; Title="Ensure password protection is enabled for on-prem Active Directory"; Section="5"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="5.2.3.4"; Title="Ensure all member users are 'MFA capable'"; Section="5"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="5.2.3.5"; Title="Ensure weak authentication methods are disabled"; Section="5"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="5.2.3.6"; Title="Ensure system-preferred multifactor authentication is enabled"; Section="5"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="5.2.3.7"; Title="Ensure the email OTP authentication method is disabled"; Section="5"; ProfileLevel="L2"; Automated=$true}
        [PSCustomObject]@{ControlNumber="5.2.4.1"; Title="Ensure 'Self service password reset enabled' is set to 'All'"; Section="5"; ProfileLevel="L1"; Automated=$false}
        [PSCustomObject]@{ControlNumber="5.3.1"; Title="Ensure 'Privileged Identity Management' is used to manage roles"; Section="5"; ProfileLevel="L2"; Automated=$true}
        [PSCustomObject]@{ControlNumber="5.3.2"; Title="Ensure 'Access reviews' for Guest Users are configured"; Section="5"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="5.3.3"; Title="Ensure 'Access reviews' for privileged roles are configured"; Section="5"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="5.3.4"; Title="Ensure approval is required for Global Administrator role activation"; Section="5"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="5.3.5"; Title="Ensure approval is required for Privileged Role Administrator activation"; Section="5"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="6.1.1"; Title="Ensure 'AuditDisabled' organizationally is set to 'False'"; Section="6"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="6.1.2"; Title="Ensure mailbox audit actions are configured"; Section="6"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="6.1.3"; Title="Ensure 'AuditBypassEnabled' is not enabled on mailboxes"; Section="6"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="6.2.1"; Title="Ensure all forms of mail forwarding are blocked and/or disabled"; Section="6"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="6.2.2"; Title="Ensure mail transport rules do not whitelist specific domains"; Section="6"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="6.2.3"; Title="Ensure email from external senders is identified"; Section="6"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="6.3.1"; Title="Ensure users installing Outlook add-ins is not allowed"; Section="6"; ProfileLevel="L2"; Automated=$true}
        [PSCustomObject]@{ControlNumber="6.5.1"; Title="Ensure modern authentication for Exchange Online is enabled"; Section="6"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="6.5.2"; Title="Ensure MailTips are enabled for end users"; Section="6"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="6.5.3"; Title="Ensure additional storage providers are restricted in Outlook on the web"; Section="6"; ProfileLevel="L2"; Automated=$true}
        [PSCustomObject]@{ControlNumber="6.5.4"; Title="Ensure SMTP AUTH is disabled"; Section="6"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="6.5.5"; Title="Ensure Direct Send submissions are rejected"; Section="6"; ProfileLevel="L2"; Automated=$true}
        [PSCustomObject]@{ControlNumber="7.2.1"; Title="Ensure modern authentication for SharePoint applications is required"; Section="7"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="7.2.2"; Title="Ensure SharePoint and OneDrive integration with Azure AD B2B is enabled"; Section="7"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="7.2.3"; Title="Ensure external content sharing is restricted"; Section="7"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="7.2.4"; Title="Ensure OneDrive content sharing is restricted"; Section="7"; ProfileLevel="L2"; Automated=$true}
        [PSCustomObject]@{ControlNumber="7.2.5"; Title="Ensure that SharePoint guest users cannot share items they don't own"; Section="7"; ProfileLevel="L2"; Automated=$true}
        [PSCustomObject]@{ControlNumber="7.2.6"; Title="Ensure SharePoint external sharing is managed through domain whitelist/blacklists"; Section="7"; ProfileLevel="L2"; Automated=$true}
        [PSCustomObject]@{ControlNumber="7.2.7"; Title="Ensure link sharing is restricted in SharePoint and OneDrive"; Section="7"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="7.2.8"; Title="Ensure external sharing is restricted by security group"; Section="7"; ProfileLevel="L2"; Automated=$false}
        [PSCustomObject]@{ControlNumber="7.2.9"; Title="Ensure guest access to a site or OneDrive will expire automatically"; Section="7"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="7.2.10"; Title="Ensure reauthentication with verification code is restricted"; Section="7"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="7.2.11"; Title="Ensure the SharePoint default sharing link permission is set"; Section="7"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="7.3.1"; Title="Ensure Office 365 SharePoint infected files are disallowed for download"; Section="7"; ProfileLevel="L2"; Automated=$true}
        [PSCustomObject]@{ControlNumber="7.3.2"; Title="Ensure OneDrive sync is restricted for unmanaged devices"; Section="7"; ProfileLevel="L2"; Automated=$true}
        [PSCustomObject]@{ControlNumber="8.1.1"; Title="Ensure external file sharing in Teams is enabled for only approved cloud storage services"; Section="8"; ProfileLevel="L2"; Automated=$true}
        [PSCustomObject]@{ControlNumber="8.1.2"; Title="Ensure users can't send emails to a channel email address"; Section="8"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="8.2.1"; Title="Ensure external domains are restricted in the Teams admin center"; Section="8"; ProfileLevel="L2"; Automated=$true}
        [PSCustomObject]@{ControlNumber="8.2.2"; Title="Ensure communication with unmanaged Teams users is disabled"; Section="8"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="8.2.3"; Title="Ensure external Teams users cannot initiate conversations"; Section="8"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="8.2.4"; Title="Ensure communication with Skype users is disabled"; Section="8"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="8.4.1"; Title="Ensure app permission policies are configured"; Section="8"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="8.5.1"; Title="Ensure anonymous users can't join a meeting"; Section="8"; ProfileLevel="L2"; Automated=$true}
        [PSCustomObject]@{ControlNumber="8.5.2"; Title="Ensure anonymous users and dial-in callers can't start a meeting"; Section="8"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="8.5.3"; Title="Ensure only people in my org can bypass the lobby"; Section="8"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="8.5.4"; Title="Ensure users dialing in can't bypass the lobby"; Section="8"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="8.5.5"; Title="Ensure meeting chat does not allow anonymous users"; Section="8"; ProfileLevel="L2"; Automated=$true}
        [PSCustomObject]@{ControlNumber="8.5.6"; Title="Ensure only organizers and co-organizers can present"; Section="8"; ProfileLevel="L2"; Automated=$true}
        [PSCustomObject]@{ControlNumber="8.5.7"; Title="Ensure external participants can't give or request control"; Section="8"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="8.5.8"; Title="Ensure external meeting chat is off"; Section="8"; ProfileLevel="L2"; Automated=$true}
        [PSCustomObject]@{ControlNumber="8.5.9"; Title="Ensure meeting recording is off by default"; Section="8"; ProfileLevel="L2"; Automated=$true}
        [PSCustomObject]@{ControlNumber="8.6.1"; Title="Ensure users can report security concerns in Teams"; Section="8"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="9.1.1"; Title="Ensure guest user access is restricted"; Section="9"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="9.1.2"; Title="Ensure external user invitations are restricted"; Section="9"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="9.1.3"; Title="Ensure guest access to content is restricted"; Section="9"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="9.1.4"; Title="Ensure 'Publish to web' is restricted"; Section="9"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="9.1.5"; Title="Ensure 'Interact with and share R and Python' visuals is 'Disabled'"; Section="9"; ProfileLevel="L2"; Automated=$true}
        [PSCustomObject]@{ControlNumber="9.1.6"; Title="Ensure 'Allow users to apply sensitivity labels for content' is 'Enabled'"; Section="9"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="9.1.7"; Title="Ensure shareable links are restricted"; Section="9"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="9.1.8"; Title="Ensure enabling of external data sharing is restricted"; Section="9"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="9.1.9"; Title="Ensure 'Block ResourceKey Authentication' is 'Enabled'"; Section="9"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="9.1.10"; Title="Ensure access to APIs by Service Principals is restricted"; Section="9"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="9.1.11"; Title="Ensure Service Principals cannot create and use profiles"; Section="9"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="9.1.12"; Title="Ensure service principals ability to create workspaces, connections and deployment pipelines is restricted"; Section="9"; ProfileLevel="L1"; Automated=$true}
    )

    $results = $controls

    if ($PSCmdlet.ParameterSetName -eq 'ByControl' -and $ControlNumber) {
        $results = $results | Where-Object { $_.ControlNumber -in $ControlNumber }
    }

    if ($PSCmdlet.ParameterSetName -eq 'BySection' -and $Section) {
        $results = $results | Where-Object { $_.Section -eq $Section }
    }

    if ($ProfileLevel -ne 'All') {
        $results = $results | Where-Object { $_.ProfileLevel -eq $ProfileLevel }
    }

    return $results
}

function Test-CISM365BenchmarkPrerequisites {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param()

    $requiredModules = @(
        @{Name="Microsoft.Graph"; Required=$true}
        @{Name="ExchangeOnlineManagement"; Required=$true}
        @{Name="Microsoft.Online.SharePoint.PowerShell"; Required=$true}
        @{Name="MicrosoftTeams"; Required=$true}
        @{Name="MicrosoftPowerBIMgmt.Profile"; Required=$false}
    )

    $results = @()

    foreach ($module in $requiredModules) {
        $installed = Get-Module -ListAvailable -Name $module.Name | Select-Object -First 1

        $results += [PSCustomObject]@{
            Module = $module.Name
            Installed = $null -ne $installed
            Version = if ($installed) { $installed.Version.ToString() } else { "Not Installed" }
            Required = $module.Required
            Status = if ($null -ne $installed) { "[OK] Installed" } elseif ($module.Required) { "[!] Required - Not Installed" } else { "[*] Optional - Not Installed" }
        }
    }

    return $results
}

function Get-CISM365BenchmarkInfo {
    [CmdletBinding()]
    param()

    $module = Get-Module -Name CIS-M365-Benchmark

    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "  CIS Microsoft 365 Foundations Benchmark v6.0.0" -ForegroundColor Cyan
    Write-Host "  PowerShell Module v$($module.Version)" -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Available Commands:" -ForegroundColor Yellow
    Write-Host "  - Connect-CISM365Benchmark           - Authenticate to Microsoft 365" -ForegroundColor White
    Write-Host "  - Invoke-CISM365Benchmark            - Run compliance checks" -ForegroundColor White
    Write-Host "  - Get-CISM365BenchmarkControl        - Get control information" -ForegroundColor White
    Write-Host "  - Test-CISM365BenchmarkPrerequisites - Check required modules" -ForegroundColor White
    Write-Host "  - Get-CISM365BenchmarkInfo           - Display this information" -ForegroundColor White
    Write-Host ""
    Write-Host "Quick Start:" -ForegroundColor Yellow
    Write-Host "  1. Authenticate:" -ForegroundColor Gray
    Write-Host "     Connect-CISM365Benchmark" -ForegroundColor Green
    Write-Host ""
    Write-Host "  2. Run compliance checks:" -ForegroundColor Gray
    Write-Host "     Invoke-CISM365Benchmark" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Or manually specify tenant:" -ForegroundColor Gray
    Write-Host "     Invoke-CISM365Benchmark -TenantDomain 'contoso.onmicrosoft.com' \" -ForegroundColor Green
    Write-Host "                         -SharePointAdminUrl 'https://contoso-admin.sharepoint.com'" -ForegroundColor Green
    Write-Host ""
    Write-Host "Help:" -ForegroundColor Yellow
    Write-Host "  Get-Help Invoke-CISM365Benchmark -Full" -ForegroundColor White
    Write-Host ""
    Write-Host "Links:" -ForegroundColor Yellow
    Write-Host "  - Documentation: https://github.com/mohammedsiddiqui6872/CIS-M365-Benchmark" -ForegroundColor White
    Write-Host "  - CIS Benchmark: https://www.cisecurity.org/benchmark/microsoft_365" -ForegroundColor White
    Write-Host "  - PowerShell Gallery: https://www.powershellgallery.com/packages/CIS-M365-Benchmark" -ForegroundColor White
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Disconnect-CISM365Benchmark {
    [CmdletBinding()]
    param()

    Write-Host "`nDisconnecting from Microsoft 365 services..." -ForegroundColor Yellow

    try {
        if (Get-MgContext -ErrorAction SilentlyContinue) {
            Disconnect-MgGraph -ErrorAction Stop | Out-Null
            Write-Host "  Disconnected from Microsoft Graph" -ForegroundColor Green
        }
    }
    catch { Write-Host "  Could not disconnect Microsoft Graph: $_" -ForegroundColor DarkYellow }

    try {
        Get-PSSession | Where-Object { $_.ConfigurationName -eq 'Microsoft.Exchange' -or $_.Name -like '*ExchangeOnline*' } | ForEach-Object {
            Remove-PSSession $_ -ErrorAction SilentlyContinue
        }
        if (Get-Command Disconnect-ExchangeOnline -ErrorAction SilentlyContinue) {
            Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
        }
        Write-Host "  Disconnected from Exchange Online" -ForegroundColor Green
    }
    catch { Write-Host "  Could not disconnect Exchange Online: $_" -ForegroundColor DarkYellow }

    try {
        if (Get-Command Disconnect-SPOService -ErrorAction SilentlyContinue) {
            Disconnect-SPOService -ErrorAction SilentlyContinue
            Write-Host "  Disconnected from SharePoint Online" -ForegroundColor Green
        }
    }
    catch { Write-Host "  Could not disconnect SharePoint Online: $_" -ForegroundColor DarkYellow }

    try {
        if (Get-Command Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue) {
            Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue
            Write-Host "  Disconnected from Microsoft Teams" -ForegroundColor Green
        }
    }
    catch { Write-Host "  Could not disconnect Microsoft Teams: $_" -ForegroundColor DarkYellow }

    try {
        Get-PSSession | Where-Object { $_.ConfigurationName -eq 'Microsoft.Exchange' -and $_.ComputerName -like '*compliance*' } | ForEach-Object {
            Remove-PSSession $_ -ErrorAction SilentlyContinue
        }
        Write-Host "  Disconnected from Security & Compliance" -ForegroundColor Green
    }
    catch { Write-Host "  Could not disconnect Security & Compliance: $_" -ForegroundColor DarkYellow }

    @('CIS_USE_DEVICE_CODE', 'AZURE_IDENTITY_DISABLE_MULTITENANTAUTH') | ForEach-Object {
        if (Test-Path "Env:\$_") { Remove-Item "Env:\$_" -ErrorAction SilentlyContinue }
    }

    $Script:PrerequisiteCheckRun = $false

    Write-Host "`nAll sessions disconnected.`n" -ForegroundColor Green
}

Export-ModuleMember -Function @(
    'Connect-CISM365Benchmark',
    'Invoke-CISM365Benchmark',
    'Disconnect-CISM365Benchmark',
    'Get-CISM365BenchmarkControl',
    'Test-CISM365BenchmarkPrerequisites',
    'Get-CISM365BenchmarkInfo'
)
