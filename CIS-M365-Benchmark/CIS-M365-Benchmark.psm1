#Requires -Version 5.1

<#
.SYNOPSIS
    CIS Microsoft 365 Foundations Benchmark v5.0.0 Module

.DESCRIPTION
    PowerShell module for auditing Microsoft 365 environments against CIS Benchmark v5.0.0.
    Provides cmdlets for running compliance checks and generating reports with zero false positives.

.NOTES
    Version: 2.4.2
    Author: Mohammed Siddiqui
    Copyright: (c) 2025 Mohammed Siddiqui. MIT License.
#>

# Store the path to the main script for execution
$Script:ComplianceCheckerPath = Join-Path $PSScriptRoot "CIS-M365-Compliance-Checker.ps1"

# Automatic prerequisite installation on module import
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
            # Don't auto-import Microsoft.Graph - let Connect-MgGraph handle it
            if ($moduleName -ne "Microsoft.Graph") {
                $loaded = Get-Module -Name $moduleName
                if (-not $loaded) {
                    $needsImport += $moduleName
                }
            }
        }
    }

    # Update outdated modules - CRITICAL for Microsoft.Graph
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

            # Special handling for Microsoft.Graph - MUST uninstall old versions first
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
                # For other modules, use standard update
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

    # Install missing modules
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

    # Import modules that aren't loaded
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
                # Don't block module loading if a prerequisite fails to import
                # It will be caught later when the user runs Invoke-CISBenchmark
                Write-Host " [WARNING]" -ForegroundColor Yellow
            }
        }
        Write-Host ""
    }
}

# Function to fix Microsoft.Graph version issues
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
                # Uninstall old versions first
                Get-InstalledModule -Name Microsoft.Graph -AllVersions -ErrorAction SilentlyContinue |
                    Where-Object { $_.Version -lt [Version]"2.0.0" } |
                    ForEach-Object {
                        Write-Host "  Removing old version $($_.Version)..." -NoNewline -ForegroundColor Gray
                        Uninstall-Module -Name Microsoft.Graph -RequiredVersion $_.Version -Force -ErrorAction SilentlyContinue
                        Write-Host " [OK]" -ForegroundColor Green
                    }

                # Install latest version
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
        # Silently continue if version check fails
    }
    return $false
}

# Automatically install missing prerequisites when module is first imported
if (-not $Script:PrerequisiteCheckRun) {
    Script:Install-PrerequisitesAutomatically
    $Script:PrerequisiteCheckRun = $true
}

<#
.SYNOPSIS
    Connects to Microsoft 365 services for CIS Benchmark compliance checks.

.DESCRIPTION
    Authenticates to Microsoft Graph with the necessary permissions for running
    CIS Microsoft 365 Foundations Benchmark compliance checks. Attempts browser-based
    authentication first, then falls back to device code authentication if needed.

.PARAMETER Scopes
    Optional custom Microsoft Graph permission scopes. If not specified, uses
    the default scopes required for CIS benchmark checks.

.EXAMPLE
    Connect-CISBenchmark

    Authenticates to Microsoft 365. Opens a browser window or displays a device code for authentication.

.EXAMPLE
    Connect-CISBenchmark -Scopes "Organization.Read.All", "User.Read.All"

    Connects with custom permission scopes.

.OUTPUTS
    PSCustomObject
    Returns the Microsoft Graph context if successful.

.NOTES
    This function must be run before Invoke-CISBenchmark to establish authentication.
    Uses interactive browser-based authentication compatible with the latest Microsoft.Graph SDK.

.LINK
    https://github.com/mohammedsiddiqui6872/CIS-Microsoft-365-Foundations-Benchmark-v5.0.0
#>
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

        # Use device code flow for authentication
        [switch]$UseDeviceCode
    )

    Write-Host "`nConnecting to Microsoft Graph" -ForegroundColor Yellow

    try {
        # Ensure Microsoft.Graph.Authentication is loaded before calling Connect-MgGraph
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

<#
.SYNOPSIS
    Invokes CIS Microsoft 365 Foundations Benchmark compliance checks.

.DESCRIPTION
    Runs automated compliance checks against your Microsoft 365 tenant based on
    CIS Microsoft 365 Foundations Benchmark v5.0.0. Generates HTML and CSV reports
    showing pass/fail status for all 130 controls across 9 sections.

.PARAMETER TenantDomain
    Your Microsoft 365 tenant domain (e.g., contoso.onmicrosoft.com)

.PARAMETER SharePointAdminUrl
    Your SharePoint admin URL (e.g., https://contoso-admin.sharepoint.com)

.PARAMETER OutputPath
    Directory path where reports will be saved. Default: Current directory

.PARAMETER ProfileLevel
    CIS profile level to check: 'L1', 'L2', or 'All'. Default: 'All'
    - L1: Level 1 controls (baseline security)
    - L2: Level 2 controls (enhanced security)
    - All: Both L1 and L2 controls

.PARAMETER Format
    Output format: 'Both', 'HTML', or 'CSV'. Default: 'Both'

.PARAMETER Sections
    Specific benchmark sections to check (e.g., @('1','2','3') or @('1.1','2.1'))
    If not specified, all sections are checked.

.EXAMPLE
    Connect-CISBenchmark
    Invoke-CISBenchmark

    First authenticate, then run all compliance checks with auto-detected tenant information.

.EXAMPLE
    Connect-CISBenchmark
    Invoke-CISBenchmark -ProfileLevel "L1"

    Runs only Level 1 (baseline) compliance checks with auto-detected tenant information.

.EXAMPLE
    Connect-CISBenchmark
    Invoke-CISBenchmark -TenantDomain "contoso.onmicrosoft.com" -SharePointAdminUrl "https://contoso-admin.sharepoint.com"

    Runs all compliance checks with manually specified tenant information.

.EXAMPLE
    Invoke-CISBenchmark -Format "HTML" -OutputPath "C:\CIS-Reports"

    Generates only HTML report and saves it to specified directory. Tenant info auto-detected.

.EXAMPLE
    Invoke-CISBenchmark -Sections @('1','2','5')

    Runs only Section 1 (M365 Admin), Section 2 (Defender), and Section 5 (Entra ID) checks.

.EXAMPLE
    Invoke-CISBenchmark -Verbose

    Runs all checks with verbose output showing detailed progress.

.OUTPUTS
    System.Management.Automation.PSCustomObject
    Returns a summary object containing:
    - TotalControls: Total number of controls checked
    - Passed: Number of passing controls
    - Failed: Number of failing controls
    - Manual: Number of controls requiring manual review
    - Errors: Number of controls with errors
    - ComplianceRate: Percentage of automated controls that passed
    - ReportPaths: Array of generated report file paths

.NOTES
    Required Modules:
    - Microsoft.Graph
    - ExchangeOnlineManagement
    - Microsoft.Online.SharePoint.PowerShell
    - MicrosoftTeams
    - MSOnline (optional)

    Required Permissions:
    - Global Reader (recommended) or equivalent read permissions
    - See PERMISSIONS.md for detailed permission requirements

    Authentication:
    - Run Connect-CISBenchmark first to authenticate
    - Or the function will attempt auto-authentication if not already connected

.LINK
    https://github.com/mohammedsiddiqui6872/CIS-Microsoft-365-Foundations-Benchmark-v5.0.0

.LINK
    https://www.cisecurity.org/benchmark/microsoft_365
#>
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

        # Auto-detect tenant domain and SharePoint URL if not provided
        if ([string]::IsNullOrEmpty($TenantDomain) -or [string]::IsNullOrEmpty($SharePointAdminUrl)) {
            Write-Host ""
            Write-Host "================================================================" -ForegroundColor Cyan
            Write-Host "  Auto-Detecting Microsoft 365 Tenant Information" -ForegroundColor Cyan
            Write-Host "================================================================" -ForegroundColor Cyan
            Write-Host ""

            try {
                # Check for existing Microsoft Graph connection
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

                # Get organization details
                Write-Host "Retrieving tenant information..." -ForegroundColor Gray
                $orgDetails = Get-MgOrganization -ErrorAction Stop | Select-Object -First 1

                if ([string]::IsNullOrEmpty($TenantDomain)) {
                    # Get the primary verified domain or onmicrosoft.com domain
                    $verifiedDomains = $orgDetails.VerifiedDomains | Where-Object { $_.Name -like "*.onmicrosoft.com" }
                    if ($verifiedDomains) {
                        $TenantDomain = @($verifiedDomains)[0].Name
                    } else {
                        $TenantDomain = @($orgDetails.VerifiedDomains)[0].Name
                    }
                    Write-Host "  Detected Tenant Domain: $TenantDomain" -ForegroundColor Green
                }

                if ([string]::IsNullOrEmpty($SharePointAdminUrl)) {
                    # Construct SharePoint admin URL from tenant name
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

        # Check and fix Microsoft.Graph version if needed
        $graphFixed = Script:Fix-MicrosoftGraphVersion
        if ($graphFixed) {
            Write-Host "Microsoft.Graph has been updated. Please restart PowerShell and run this command again." -ForegroundColor Yellow
            return
        }

        # Ensure output directory exists
        if (-not (Test-Path -Path $OutputPath)) {
            Write-Verbose "Creating output directory: $OutputPath"
            New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
        }
    }

    process {
        try {
            # Clean SharePoint URL - remove trailing slash if present
            $cleanSharePointUrl = $SharePointAdminUrl.TrimEnd('/')

            # Build parameters for the script
            $scriptParams = @{
                TenantDomain = $TenantDomain
                SharePointAdminUrl = $cleanSharePointUrl
                OutputPath = $OutputPath
                ProfileLevel = $ProfileLevel
            }

            Write-Verbose "Executing CIS compliance checker script..."

            # Execute the compliance checker script
            & $Script:ComplianceCheckerPath @scriptParams

            Write-Verbose "Generating summary report..."

            # Get the most recent report files
            $htmlReport = Get-ChildItem -Path $OutputPath -Filter "CIS-M365-Compliance-Report_*.html" -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending |
                Select-Object -First 1

            $csvReport = Get-ChildItem -Path $OutputPath -Filter "CIS-M365-Compliance-Report_*.csv" -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending |
                Select-Object -First 1

            # Parse CSV to get summary statistics
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

                # Return summary object
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

<#
.SYNOPSIS
    Gets information about CIS benchmark controls.

.DESCRIPTION
    Retrieves details about specific CIS Microsoft 365 Foundations Benchmark controls,
    including control number, title, profile level, and description.

.PARAMETER ControlNumber
    Specific control number(s) to retrieve (e.g., "1.1.1", "2.1.3")
    If not specified, returns all controls.

.PARAMETER Section
    Return all controls in a specific section (e.g., "1", "2", "5")

.PARAMETER ProfileLevel
    Filter by profile level: 'L1', 'L2', or 'All'

.EXAMPLE
    Get-CISBenchmarkControl -ControlNumber "1.1.1"

    Gets details for control 1.1.1

.EXAMPLE
    Get-CISBenchmarkControl -Section "5"

    Gets all controls in Section 5 (Entra ID)

.EXAMPLE
    Get-CISBenchmarkControl -ProfileLevel "L1"

    Gets all Level 1 controls

.OUTPUTS
    System.Management.Automation.PSCustomObject
    Control information including number, title, section, profile level, and automation status
#>
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

    # Define control metadata (this would ideally be loaded from a data file)
    $controls = @(
        [PSCustomObject]@{ControlNumber="1.1.1"; Title="Ensure Administrative accounts are cloud-only"; Section="1"; ProfileLevel="L1"; Automated=$true}
        [PSCustomObject]@{ControlNumber="1.1.2"; Title="Ensure two emergency access accounts have been defined"; Section="1"; ProfileLevel="L1"; Automated=$false}
        [PSCustomObject]@{ControlNumber="1.1.3"; Title="Ensure that between two and four global admins are designated"; Section="1"; ProfileLevel="L1"; Automated=$true}
        # ... (Additional controls would be defined here or loaded from JSON/XML)
    )

    # Filter based on parameters
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

<#
.SYNOPSIS
    Tests if required PowerShell modules are installed.

.DESCRIPTION
    Checks if all required Microsoft 365 PowerShell modules are installed
    and reports their versions and installation status.

.EXAMPLE
    Test-CISBenchmarkPrerequisites

    Checks all required modules and displays their status.

.OUTPUTS
    System.Management.Automation.PSCustomObject
    Module name, version, installation status, and required status
#>
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

<#
.SYNOPSIS
    Displays information about the CIS M365 Benchmark module.

.DESCRIPTION
    Shows module version, available commands, and useful links.

.EXAMPLE
    Get-CISBenchmarkInfo

    Displays module information.
#>
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

# Export module members
Export-ModuleMember -Function @(
    'Connect-CISBenchmark',
    'Invoke-CISBenchmark',
    'Get-CISBenchmarkControl',
    'Test-CISBenchmarkPrerequisites',
    'Get-CISBenchmarkInfo'
)
