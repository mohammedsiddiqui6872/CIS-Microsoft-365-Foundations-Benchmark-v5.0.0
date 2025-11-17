#Requires -Version 5.1

$Script:ComplianceCheckerPath = Join-Path $PSScriptRoot "CIS-M365-Compliance-Checker.ps1"

$Script:PrerequisiteCheckRun = $false

function Script:Install-PrerequisitesAutomatically {
    $requiredModules = @(
        @{ Name = "Microsoft.Graph"; MinVersion = "2.0.0" }
        @{ Name = "ExchangeOnlineManagement"; MinVersion = $null }
        @{ Name = "Microsoft.Online.SharePoint.PowerShell"; MinVersion = $null }
        @{ Name = "MicrosoftTeams"; MinVersion = $null }
        @{ Name = "MSOnline"; MinVersion = $null }
    )

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
                    Install-Module -Name "Microsoft.Graph" -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
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
                    Update-Module -Name $module.Name -Force -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
                    Write-Host " [OK]" -ForegroundColor Green
                    $needsImport += $module.Name
                }
                catch {
                    try {
                        Install-Module -Name $module.Name -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
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
                Install-Module -Name $module.Name -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop -WarningAction SilentlyContinue -Repository PSGallery | Out-Null
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
                    Import-Module -Name $moduleName -ErrorAction Stop -WarningAction SilentlyContinue -DisableNameChecking -SkipEditionCheck -Force | Out-Null
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
                Install-Module -Name Microsoft.Graph -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop -WarningAction SilentlyContinue
                Write-Host " [OK]" -ForegroundColor Green

                Write-Host ""
                Write-Host "================================================================" -ForegroundColor Green
                Write-Host "  Microsoft.Graph updated successfully!" -ForegroundColor Green
                Write-Host "================================================================" -ForegroundColor Green
                Write-Host ""
                Write-Host "Please restart PowerShell and run Invoke-CISBenchmark again." -ForegroundColor Yellow
                Write-Host ""
                return $true
            }
            catch {
                Write-Host " [FAILED]" -ForegroundColor Red
                Write-Host ""
                Write-Host "Unable to auto-update Microsoft.Graph. Please update manually:" -ForegroundColor Yellow
                Write-Host "  Install-Module -Name Microsoft.Graph -Force -AllowClobber" -ForegroundColor White
                Write-Host ""
                return $false
            }
        }
    }
    catch {
    }
    return $false
}

if (-not $Script:PrerequisiteCheckRun) {
    Script:Install-PrerequisitesAutomatically
    $Script:PrerequisiteCheckRun = $true
}

function Connect-CISBenchmark {
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
            "Application.Read.All"
        ),

        [switch]$UseDeviceCode
    )

    Write-Host "`nConnecting to Microsoft Graph" -ForegroundColor Yellow

    try {
        if (-not (Get-Module -Name Microsoft.Graph.Authentication)) {
            Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
        }

        $params = @{
            Scopes        = $Scopes
            NoWelcome     = $true
            ContextScope  = 'Process'
        }

        if ($UseDeviceCode) {
            $params['UseDeviceCode'] = $true
        }
        elseif ($PSVersionTable.PSVersion.Major -ge 7) {
            Write-Host "PowerShell 7+ detected - Using Device Code authentication for compatibility" -ForegroundColor Cyan
            $params['UseDeviceCode'] = $true
        }

        Connect-MgGraph @params

        $context = Get-MgContext

        if ($context -and $context.TenantId) {
            Write-Host "`nSuccessfully connected to Microsoft Graph!" -ForegroundColor Green
            Write-Host "  Tenant ID: $($context.TenantId)" -ForegroundColor White
            Write-Host "  Account: $($context.Account)" -ForegroundColor White
            Write-Host "`nYou can now run: Invoke-CISBenchmark`n" -ForegroundColor Yellow
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

function Invoke-CISBenchmark {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory=$false, Position=0, HelpMessage="Your M365 tenant domain (e.g., contoso.onmicrosoft.com). If not provided, will be auto-detected.")]
        [string]$TenantDomain,

        [Parameter(Mandatory=$false, Position=1, HelpMessage="SharePoint admin URL (e.g., https://contoso-admin.sharepoint.com). If not provided, will be auto-detected.")]
        [ValidatePattern('^https://.*-admin\.sharepoint\.com/?$')]
        [string]$SharePointAdminUrl,

        [Parameter(Mandatory=$false)]
        [ValidateScript({Test-Path -Path $_ -PathType Container -IsValid})]
        [string]$OutputPath = ".",

        [Parameter(Mandatory=$false)]
        [ValidateSet('L1','L2','All')]
        [string]$ProfileLevel = 'All',

        [Parameter(Mandatory=$false)]
        [ValidateSet('Both','HTML','CSV')]
        [string]$Format = 'Both',

        [Parameter(Mandatory=$false)]
        [string[]]$Sections
    )

    begin {
        Write-Verbose "Starting CIS Microsoft 365 Foundations Benchmark v5.0.0 Compliance Check"

        if ([string]::IsNullOrEmpty($TenantDomain) -or [string]::IsNullOrEmpty($SharePointAdminUrl)) {
            Write-Host ""
            Write-Host "================================================================" -ForegroundColor Cyan
            Write-Host "  Auto-Detecting Microsoft 365 Tenant Information" -ForegroundColor Cyan
            Write-Host "================================================================" -ForegroundColor Cyan
            Write-Host ""

            try {
                Write-Host "Checking Microsoft Graph connection..." -ForegroundColor Gray
                $graphContext = Get-MgContext -ErrorAction SilentlyContinue

                if (-not $graphContext) {
                    Write-Host ""
                    Write-Host "Not authenticated to Microsoft Graph." -ForegroundColor Yellow
                    Write-Host ""
                    Write-Host "Please run: Connect-CISBenchmark" -ForegroundColor Cyan
                    Write-Host ""
                    Write-Host "Attempting automatic authentication..." -ForegroundColor Yellow

                    try {
                        Connect-MgGraph -Scopes "Organization.Read.All","Directory.Read.All" -ErrorAction Stop | Out-Null
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
                        Write-Host "  Connect-CISBenchmark" -ForegroundColor Cyan
                        Write-Host ""
                        Write-Host "Or provide tenant information manually:" -ForegroundColor Yellow
                        Write-Host "  Invoke-CISBenchmark -TenantDomain 'tenant.onmicrosoft.com' -SharePointAdminUrl 'https://tenant-admin.sharepoint.com'" -ForegroundColor Cyan
                        Write-Host ""
                        throw "Authentication required. Run Connect-CISBenchmark first or provide tenant parameters manually."
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
                Write-Host "  Connect-CISBenchmark" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "Or provide the tenant information manually:" -ForegroundColor Yellow
                Write-Host "  Invoke-CISBenchmark -TenantDomain 'tenant.onmicrosoft.com' -SharePointAdminUrl 'https://tenant-admin.sharepoint.com'" -ForegroundColor Cyan
                Write-Host ""
                throw "Auto-detection failed. Run Connect-CISBenchmark or provide tenant parameters manually."
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
            }

            Write-Verbose "Executing CIS compliance checker script..."

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
                $passed = ($reportData | Where-Object { $_.Result -eq 'Pass' }).Count
                $failed = ($reportData | Where-Object { $_.Result -eq 'Fail' }).Count
                $manual = ($reportData | Where-Object { $_.Result -eq 'Manual' }).Count
                $errors = ($reportData | Where-Object { $_.Result -eq 'Error' }).Count
                $total = $reportData.Count

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

function Get-CISBenchmarkControl {
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
        [PSCustomObject]@{ControlNumber="1.1.2"; Title="Ensure two emergency access accounts have been defined"; Section="1"; ProfileLevel="L1"; Automated=$false}
        [PSCustomObject]@{ControlNumber="1.1.3"; Title="Ensure that between two and four global admins are designated"; Section="1"; ProfileLevel="L1"; Automated=$true}
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

function Test-CISBenchmarkPrerequisites {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param()

    $requiredModules = @(
        @{Name="Microsoft.Graph"; Required=$true}
        @{Name="ExchangeOnlineManagement"; Required=$true}
        @{Name="Microsoft.Online.SharePoint.PowerShell"; Required=$true}
        @{Name="MicrosoftTeams"; Required=$true}
        @{Name="MSOnline"; Required=$false}
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

function Get-CISBenchmarkInfo {
    [CmdletBinding()]
    param()

    $module = Get-Module -Name CIS-M365-Benchmark

    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "  CIS Microsoft 365 Foundations Benchmark v5.0.0" -ForegroundColor Cyan
    Write-Host "  PowerShell Module v$($module.Version)" -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Available Commands:" -ForegroundColor Yellow
    Write-Host "  - Connect-CISBenchmark           - Authenticate to Microsoft 365" -ForegroundColor White
    Write-Host "  - Invoke-CISBenchmark            - Run compliance checks" -ForegroundColor White
    Write-Host "  - Get-CISBenchmarkControl        - Get control information" -ForegroundColor White
    Write-Host "  - Test-CISBenchmarkPrerequisites - Check required modules" -ForegroundColor White
    Write-Host "  - Get-CISBenchmarkInfo           - Display this information" -ForegroundColor White
    Write-Host ""
    Write-Host "Quick Start:" -ForegroundColor Yellow
    Write-Host "  1. Authenticate:" -ForegroundColor Gray
    Write-Host "     Connect-CISBenchmark" -ForegroundColor Green
    Write-Host ""
    Write-Host "  2. Run compliance checks:" -ForegroundColor Gray
    Write-Host "     Invoke-CISBenchmark" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Or manually specify tenant:" -ForegroundColor Gray
    Write-Host "     Invoke-CISBenchmark -TenantDomain 'contoso.onmicrosoft.com' \" -ForegroundColor Green
    Write-Host "                         -SharePointAdminUrl 'https://contoso-admin.sharepoint.com'" -ForegroundColor Green
    Write-Host ""
    Write-Host "Help:" -ForegroundColor Yellow
    Write-Host "  Get-Help Invoke-CISBenchmark -Full" -ForegroundColor White
    Write-Host ""
    Write-Host "Links:" -ForegroundColor Yellow
    Write-Host "  - Documentation: https://github.com/mohammedsiddiqui6872/CIS-M365-Benchmark" -ForegroundColor White
    Write-Host "  - CIS Benchmark: https://www.cisecurity.org/benchmark/microsoft_365" -ForegroundColor White
    Write-Host "  - PowerShell Gallery: https://www.powershellgallery.com/packages/CIS-M365-Benchmark" -ForegroundColor White
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host ""
}

Export-ModuleMember -Function @(
    'Connect-CISBenchmark',
    'Invoke-CISBenchmark',
    'Get-CISBenchmarkControl',
    'Test-CISBenchmarkPrerequisites',
    'Get-CISBenchmarkInfo'
)
